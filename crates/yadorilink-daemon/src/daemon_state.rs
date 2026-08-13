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

use sha2::Digest;
use tokio::sync::{broadcast, mpsc};
use yadorilink_filesystem_sync::block_liveness::{
    BlockLivenessGate, BlockPhysicalDeletionGuard, BlockReferenceWriteGuard,
};
use yadorilink_local_storage::BlockStore;
use yadorilink_replica_domain::change::{ChangeAuth, PolicyUnavailable};
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::custody::{CustodyStamp, FullReplicaCustody};

use crate::daemon_runtime::{DaemonBuild, RuntimeComponents};
#[cfg(test)]
use crate::durability_service::CustodyConfirmer;
use crate::durability_service::GroupDurabilityStatus;
use yadorilink_peer_session::peer_session::{
    BlockWriteActivityProvider, HandoffLeaseResponder, HandoffTicketResponder,
    PeerHandoffLeaseGrant, PeerHandoffTicketGrant, PeerSyncSession,
};
use yadorilink_peer_session::rate_limiter::RateLimiters;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::{
    DurabilityRoot, DurabilityRoots, MembershipCommitMode, MembershipDurabilityScope,
    MembershipOperationAction, MembershipOperationState, RoleLossAction, RoleLossOperationParams,
    RoleLossOperationState,
};
use yadorilink_replica_engine::repair_election::{AuthorizedWriter, RepairElectionContext};
use yadorilink_sync_sqlite::handoff_lease::HandoffLeaseState;

use crate::change_policy::GroupPolicyState;
use crate::governance_config::GovernanceConfigStore;
use crate::reporting::ReportingStorage;
use crate::supervise;

/// How often the retention-expiry sweep
/// runs — see its spawn site in `DaemonState::new` for why this is a much
/// longer interval than the other periodic sweeps in this file.
pub(crate) const RETENTION_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
const MATERIALIZATION_REPAIR_SWEEP_INTERVAL: Duration = Duration::from_secs(90);

/// Test-only hook overriding the value every subsequently-constructed
/// `DaemonState`'s materialization-repair scheduler starts with, closing a
/// race `set_materialization_repair_sweep_interval` alone cannot: that
/// setter only takes effect on the scheduler's *next* sleep, so a caller
/// racing against `DaemonState::new` (which has already spawned the
/// scheduler by the time it returns) cannot guarantee its override lands
/// before that task's first read — especially on a multi-threaded runtime,
/// where the newly-spawned task can start executing on a different worker
/// thread immediately, with no `.await` needed to hand it control. A test
/// that needs to prove convergence with NO help from this periodic sweep
/// (see `fix/conflict-copy-convergence-obligation-20260723`'s acceptance
/// criteria) needs the FIRST sleep, not just subsequent ones, to already
/// reflect the override. Set this before constructing any `DaemonState`
/// whose scheduler should start with it.
static MATERIALIZATION_REPAIR_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS: std::sync::OnceLock<
    Mutex<Option<Duration>>,
> = std::sync::OnceLock::new();

pub fn set_default_materialization_repair_sweep_interval_for_tests(interval: Duration) {
    *MATERIALIZATION_REPAIR_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(interval);
}

fn default_materialization_repair_sweep_interval() -> Duration {
    MATERIALIZATION_REPAIR_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS
        .get()
        .and_then(|m| *m.lock().unwrap_or_else(|p| p.into_inner()))
        .unwrap_or(MATERIALIZATION_REPAIR_SWEEP_INTERVAL)
}
/// How often the role-loss-operation reconciliation sweep
/// (`run_role_loss_reconciliation_sweep`) retries any journal row left
/// mid-flight by a crash or a compensation attempt that couldn't reach the
/// coordination plane. Matches `MATERIALIZATION_REPAIR_SWEEP_INTERVAL`'s
/// cadence rather than the much longer retention-expiry one: a role-loss
/// split state is a user-visible correctness gap the same way a broken
/// materialization is, not a slow-moving housekeeping concern.
pub(crate) const ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL: Duration = Duration::from_secs(90);
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

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
/// One scheduling owner for every membership-related recovery journal this
/// daemon currently sweeps: this device's own role loss (demote/unlink),
/// unknown-scope device removals, and ambiguous ticket-bound revoke/remove
/// commits. `pub` for the same reason `run_role_loss_reconciliation_sweep`
/// is — so a test can invoke exactly this deterministically instead of
/// racing `DaemonState::new`'s real-time periodic spawn.
pub async fn run_membership_recovery_sweep(state: &Arc<DaemonState>) {
    run_role_loss_reconciliation_sweep(state).await;
    let application = crate::adapters::build_application_services(state.clone());
    application.membership.reconcile_unknown_scope().await;
    application.membership.reconcile_ambiguous().await;
}

pub async fn run_role_loss_reconciliation_sweep(state: &Arc<DaemonState>) {
    let rows = match state
        .replica_coordinator
        .role_loss_operation_repository()
        .list_role_loss_operations_in_states(&[
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
                if let Err(e) = state
                    .replica_coordinator
                    .role_loss_operation_repository()
                    .delete_role_loss_operation(&op.operation_id)
                {
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

/// M3 Pass 5: see `DaemonState::active_relay_sessions`'s own doc comment.
#[derive(Debug, Clone)]
struct RelaySessionRecord {
    source_device_id: String,
    group_id: String,
    destination_device_id: String,
}

/// M3 Pass 6: see `DaemonState::requester_relay_sessions`'s own doc
/// comment. `relay_device_id` is what `RelayCarrier::send_via_relay`
/// looks up the live `PeerSyncSession` by (`self.peers.session(&relay_
/// device_id)`) to send subsequent `RelayData` frames over.
///
/// `opened_via` (independent-review finding H4): the EXACT session
/// object this relay session was opened over, captured at open time.
/// `self.peers.session(&relay_device_id)` alone answers "is THIS DEVICE
/// currently connected to the relay", not "is it the SAME connection
/// this specific relay session_id was negotiated on" -- a disconnect and
/// reconnect between the open and a later reuse attempt produces a
/// DIFFERENT `PeerSyncSession` object (fresh handshake, fresh state) that
/// merely happens to share the same device_id, and B's own forwarder
/// still has its `RelayReplySink` pointed at the OLD (now-dead) session,
/// with no way to learn otherwise. `Weak`, not `Arc`, so a requester
/// session's bookkeeping never keeps a dead `PeerSyncSession` alive by
/// itself; `Weak::upgrade` failing is exactly equivalent to a generation
/// mismatch, both mean "treat as no existing session."
#[derive(Clone)]
struct RequesterRelaySession {
    relay_device_id: String,
    destination_peer_public: [u8; 32],
    /// Mirrors the admitting grant's own expiry -- see `record_requester_
    /// relay_session`'s own doc comment for why this device tracks it
    /// independently rather than trusting B's `RelayClose` to always
    /// arrive.
    expires_at_unix: i64,
    opened_via: std::sync::Weak<yadorilink_peer_session::peer_session::PeerSyncSession>,
}

#[derive(Default)]
struct PeerNetmapMetadata {
    signing_keys: HashMap<String, [u8; 32]>,
    writers: HashSet<(String, String)>,
    full_replicas: HashSet<(String, String)>,
    /// M3 Pass 4: device ids that have declared `RelayCapability::Capable`
    /// on the coordination-plane netmap. Deliberately device-keyed, not
    /// group-scoped like `full_replicas` -- relay capability is not a
    /// per-group storage role, and (per `crate::route`'s own doc comment)
    /// is never derived from or gated by group authorization/full-replica
    /// status the way `full_replicas` is gated by `authorized_groups` in
    /// `replace_peer_netmap_metadata`.
    relay_capable: HashSet<String>,
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
    /// Phase 7D-10.9: this is now the ONLY replica/DAG/materialization
    /// composition-root handle `DaemonState` holds -- `sync_state: Arc<
    /// yadorilink_sync_core::index::SyncState>` (additive since 7D-10.2)
    /// has been removed. Every production call site that used to read
    /// `sync_state` was already repointed to this field by earlier passes,
    /// or (the two provider-setter calls, `app::run`'s own `SyncState::open`)
    /// removed/repointed in the same pass that deleted the field -- see
    /// `docs/design/phase7d10-exit-report.md`'s 7D-10.9 addendum.
    pub replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    pub block_store: Arc<dyn BlockStore + Send + Sync>,
    /// M2-5: coalesces concurrent `FETCH_DATA`-driven `hydration::hydrate`
    /// calls for the same path onto one real attempt -- see
    /// `hydration_single_flight`'s own module doc for why this is
    /// layered outside, not a replacement for, `hydrate_inner`'s
    /// per-path lock. Per daemon-instance state, matching
    /// `ReplicaCoordinator::path_lock_registry`'s own reasoning (never a
    /// process-wide `static`, which the deterministic simulator's many
    /// in-process daemon instances would wrongly share).
    pub hydrate_single_flight: crate::hydration_single_flight::HydrateSingleFlight,
    /// Shared, device-wide block-serve credit/coalescing engine (stage 2)
    /// -- one instance for the whole daemon, handed to every
    /// `PeerSyncSession` this device constructs via
    /// `PeerSyncSession::set_block_serve_engine` (`peer_orchestrator.rs`),
    /// exactly like `block_store` above. See
    /// `yadorilink_peer_session::block_serve`'s own doc comment for why the
    /// engine type itself lives in that crate rather than this one.
    pub block_serve_engine: Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
    /// Live peer sessions and per-peer connectivity, updated as
    /// `PeerChannel`s connect/upgrade -- see
    /// `crate::peer_registry::PeerRegistry`'s own doc comment. Reached only
    /// through its own methods; the maps themselves are private.
    pub peers: Arc<crate::peer_registry::PeerRegistry>,
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
    /// M3 Pass 2: this device's WireGuard static PRIVATE key -- see
    /// `set_device_static_secret`'s own doc comment. Absent only if
    /// identity was never available (the same case `device_static_public`
    /// already handles); `ensure_shared_socket` degrades gracefully to
    /// the pre-M3-Pass-2 broadcast fallback when unset, same as an absent
    /// `device_static_public` already degrades the MAC1 gate.
    pub device_static_secret: std::sync::OnceLock<boringtun::x25519::StaticSecret>,
    /// M3 Pass 5: the coordination plane's currently-pinned service
    /// signing key -- the SAME trust anchor `change_policy::
    /// verify_group_policy_log` uses for group policy logs, mirrored here
    /// (from the identical pin decision `record_group_policy_states`
    /// already makes on every netmap update) so relay-grant verification
    /// can reach it at any later point, independent of any specific
    /// netmap-subscription attempt. `None` until the first netmap update
    /// with policy distribution enabled has been processed.
    pinned_coordination_service_key: Mutex<Option<[u8; 32]>>,
    /// M3 Pass 5: this device's own relay-session forwarding actor
    /// registry (its role as "B") -- see
    /// `crate::relay_forwarder::RelayForwarder`'s own doc comment.
    pub relay_forwarder: Arc<crate::relay_forwarder::RelayForwarder>,
    /// M3 Pass 5: replay guard for grant ids this device has admitted as a
    /// relay -- see `crate::relay_session::RelayReplayGuard`'s own doc
    /// comment. Device-wide (not per-session), since the same grant_id
    /// must never be usable twice regardless of which channel presents it.
    pub(crate) relay_replay_guard: crate::relay_session::RelayReplayGuard,
    /// M3 Pass 5: mirrors `peer_orchestrator::NetmapDiffState::channels`
    /// (device_id -> live direct `Arc<PeerChannel>`) onto `DaemonState`,
    /// at the identical insert/remove points -- `diff_state` itself is
    /// local to `run`'s own call stack, unreachable from a
    /// `RelaySessionHandler` implementation on `DaemonState`, which needs
    /// this device's OWN confirmed direct channel to the relay
    /// destination (to open its dedicated forwarding socket against the
    /// right address, and to confirm a direct route exists at all --
    /// see `relay_session::RelayAdmissionContext::has_direct_route_to_
    /// destination`'s own doc comment for why that check specifically
    /// forbids relay chaining).
    direct_channels: Mutex<HashMap<String, Arc<yadorilink_transport::PeerChannel>>>,
    /// M3 Pass 5: session id -> the full authorization tuple it was
    /// admitted under -- see `record_relay_session`'s own doc comment for
    /// why (per-datagram revalidation, closing H2/M3 in the independent
    /// review). Also what `remove_direct_channel` searches to find
    /// sessions affected by a specific destination's route disappearing.
    /// Known limitation, not yet worth further plumbing to close: an
    /// entry for a session that closes NORMALLY (idle timeout, grant
    /// expiry, explicit close, or a `revalidate_relay_session` failure --
    /// all of which go through `RelayForwarder::close_session`, not
    /// straight through this map) is only pruned by `forget_relay_
    /// session`, called from `handle_relay_data`'s own dispatch once a
    /// close is detected there -- a session that goes idle and times out
    /// with NO further datagrams ever arriving has no such trigger and
    /// stays in this map until this device restarts. Bounded in practice
    /// (each entry is a few small strings, and idle sessions are rare
    /// relative to active ones), not fixed here.
    active_relay_sessions: Mutex<HashMap<u64, RelaySessionRecord>>,
    /// M3 Pass 6: session id -> the destination peer's WireGuard static
    /// public key, for a session THIS device opened as the relay
    /// REQUESTER ("A"), not provider ("B") -- distinct from
    /// `active_relay_sessions` above, which only ever tracks sessions this
    /// device is providing forwarding for. Consulted first by
    /// `handle_relay_data`'s dispatch, before falling through to the
    /// provider-side path, so a reply this device's own `RelayCarrier` is
    /// waiting on is routed into the right `PeerChannel` via `deliver_
    /// relay_datagram` instead of being mistaken for a forward request
    /// this device never opened. Keyed by `(relay_device_id, session_id)`,
    /// not `session_id` alone -- see `requester_relay_session`'s own doc
    /// comment for the cross-relay session-id collision this closes.
    requester_relay_sessions: Mutex<HashMap<(String, u64), RequesterRelaySession>>,
    /// M3 Pass 6: `grant_id -> ` the oneshot this device's own
    /// `RelayCarrier::send_via_relay` is waiting on for the matching
    /// `RelayOpenedFrame` reply, plus the device_id the matching `RelayOpen`
    /// was actually sent to -- `resolve_pending_relay_open` checks a
    /// `RelayOpened`'s own authenticated sender against this before
    /// resolving, so a different peer this device happens to also have a
    /// session with cannot complete (or poison) an open it was never asked
    /// to answer, even if it somehow guesses/replays a live `grant_id`.
    /// Removed on first delivery -- a sender with nobody left waiting (the
    /// caller already gave up) is simply dropped when its receiver goes
    /// away, not a leak; bounded by how many opens are ever in flight at
    /// once.
    pending_relay_opens: Mutex<
        HashMap<
            String,
            (String, tokio::sync::oneshot::Sender<yadorilink_sync_wire::RelayOpenedFrame>),
        >,
    >,
    /// M3 Pass 6: how this device (as relay REQUESTER) obtains a signed
    /// `RelayGrant` before opening a session -- see `crate::relay_carrier::
    /// RelayGrantSource`'s own doc comment for why this is `None` in
    /// production today (no coordination-plane endpoint exists yet to
    /// fill it) and only ever `Some` in tests, via `FakeCoordination`.
    relay_grant_source: Mutex<Option<Arc<dyn crate::relay_carrier::RelayGrantSource>>>,
    /// M3 Pass 5: this device's own local configuration of whether it is
    /// willing to relay for other peers -- see `crate::route::
    /// RelayCapability`'s own doc comment. Defaults to `false` (the
    /// fail-safe default: a device must explicitly opt in). Distinct from
    /// `peer_relay_capability`, which reads OTHER peers' netmap-advertised
    /// capability -- this is what THIS device would itself advertise, and
    /// what its own relay-admission check consults for "am I actually
    /// willing to do this" (defense in depth beyond trusting the
    /// coordination plane's own issuance decision, per `relay_session`'s
    /// own doc comment). Not yet wired into netmap registration/
    /// advertisement (`register_with_fake`'s production counterpart) --
    /// a device that sets this locally is not yet visible to the
    /// coordination plane as a relay candidate; that wiring is a
    /// remaining follow-up, tracked separately from the relay mechanism
    /// itself.
    local_relay_capable: std::sync::atomic::AtomicBool,
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
    /// `pub(crate)`: read by `maintenance::materialization_repair::
    /// MaterializationRepairJob`'s own `run_once`, a relocation of what
    /// used to be this file's own `spawn_materialization_repair_scheduler`
    /// loop body.
    pub(crate) materialization_repair_cursors: Mutex<HashMap<String, usize>>,
    /// group_id -> next candidate offset for the Convergence Engine's own
    /// per-group peer selection (`convergence::engine`) — a separate cursor
    /// from `materialization_repair_cursors` above since the two run on
    /// independent schedules (event-driven/~1s vs the 90s backstop) and
    /// rotating them together would couple cadences that have no reason to
    /// be coupled.
    pub(crate) convergence_engine_cursors: Mutex<HashMap<String, usize>>,
    /// group_id -> next path-budget offset for the Convergence Engine's own
    /// per-tick path cap (`MAX_PATHS_PER_RECONCILE_ATTEMPT` in
    /// `convergence::engine`) — a confirmed, reproduced regression (see
    /// `fix/conflict-copy-convergence-obligation-20260723`): a single
    /// candidate attempt handed the ENTIRE claimed batch for a group
    /// (up to `MAX_JOBS_PER_TICK_PER_GROUP`, 128) processes every path's
    /// blocks fully serially, and a large backlog of not-yet-referenced/
    /// genuinely-missing blocks was measured accumulating into a 40+
    /// second single call with no visible progress. Rotating which bounded
    /// subset of `remaining` gets attempted each tick (this cursor) is what
    /// lets every path eventually get its turn without needing an
    /// unboundedly large single attempt.
    pub(crate) convergence_engine_path_budget_cursors: Mutex<HashMap<String, usize>>,
    /// group_id -> cached `PeerSyncSession` bound to a `LoopbackPeerMessageChannel`
    /// rather than a live peer connection -- see `local_retirement_session`'s
    /// own doc comment for why retirement needs a session object at all,
    /// and why one not requiring a connected peer. Built lazily on first
    /// use per group and reused after that, matching a real peer session's
    /// own long-lived-per-connection shape (rate limiters, block-serve
    /// engine, and friends are shared `Arc`s either way, so nothing here
    /// depends on reconstructing fresh per call).
    local_retirement_sessions:
        Mutex<HashMap<String, Arc<yadorilink_peer_session::peer_session::PeerSyncSession>>>,
    /// Overridable copy of `MATERIALIZATION_REPAIR_SWEEP_INTERVAL` — same
    /// mutable-after-construction shape as `PeerSyncSession::
    /// full_index_resync_interval` (`StdMutex`, opt-in override via
    /// `set_materialization_repair_sweep_interval`), for the identical
    /// reason: every existing call site keeps compiling and behaving
    /// identically at the 90s default, and a test that needs the backstop
    /// to fire faster than production's cadence can opt in without a
    /// constructor parameter.
    materialization_repair_sweep_interval: Mutex<Duration>,
    /// local_path -> that link's single runtime record: its
    /// folder-watcher tasks (the debounce accumulator and the executor
    /// that consumes its flushes, plus the periodic repair and
    /// dirty-journal tasks), its targeted-flush handle, and its sync-root
    /// single-instance OS lock. All three used to be three independently-
    /// updated maps (`link_tasks`, `link_flush_handles`, `link_root_locks`)
    /// keyed the same way but published and torn down at different points
    /// in `start_link_watch_inner`/`stop_link_watch` — which is exactly
    /// what let a peer session's targeted flush
    /// (`LinkFlushHandle::flush_pending_local_change` and friends) and the
    /// disk-reconcile backstop sweep (`run_disk_reconcile_backstop_sweep`),
    /// both of which take their own `Arc<LinkFlushHandle>` clone
    /// independent of any map, keep committing index/DAG writes after
    /// `stop_link_watch` had already removed the entry and dropped the
    /// root lock. `LinkRuntime` closes that gap with `LinkFlushHandle`'s
    /// own operation fence (`LinkOpFence`): `stop_link_watch` aborts and
    /// awaits every task exactly as before, then additionally waits for
    /// that fence to drain (every in-flight targeted flush or backstop
    /// call to actually finish, and every new one to be refused) before
    /// dropping `root_lock`. See `LinkRuntime`'s own doc.
    ///
    /// A `LinkSlot::Starting` placeholder is reserved via `links` as the
    /// very first step of `start_link_watch_inner` (via
    /// `LinkSlotStartingGuard` -- see its own doc for the start-vs-stop
    /// zombie-runtime race this closes), replaced by `LinkSlot::Ready` once
    /// every fallible step has succeeded, and removed as a single entry by
    /// `stop_link_watch`. See `crate::link_registry::LinkRegistry`'s own
    /// doc comment for its exact coordination; fields are private, reached
    /// only through its own methods.
    pub links: Arc<crate::link_registry::LinkRegistry>,
    /// Test-only override consulted by `root_lease_for` before its normal
    /// `link_runtimes` lookup -- lets a unit test that only calls
    /// `sync_state.add_link(...)` (never a real `start_link_watch`, which
    /// spins up a watcher, debounce/executor/repair tasks, and an OS-level
    /// root lock the test has no interest in) still exercise a production
    /// mutation path that requires a live `RootCommitPermit`
    /// (`hydration::hydrate_inner`, `hydration::evict`, ...). Not reachable
    /// outside test builds -- see this field's own `cfg` -- so it is not a
    /// production bypass, the same seam `root_commit::RootLease::
    /// for_tests()` is for tests that hold a `SyncState` handle directly
    /// rather than a `DaemonState`.
    #[cfg(any(test, feature = "test-support"))]
    pub test_root_commit_authorities:
        Mutex<HashMap<String, Arc<yadorilink_root_authority::root_commit::RootLease>>>,
    /// Test-only override consulted by `adapters::build_application_services`
    /// in place of the real `on_demand_pipeline_is_connected()` probe --
    /// `None` (the default) leaves the real, unconditionally-`false`
    /// production adapter wired in. A `Mutex<Option<bool>>` rather than the
    /// free function's own thread-local `OverrideForTest`, because a
    /// multi-threaded Tokio integration test's async task (this daemon's
    /// actual caller) is not guaranteed to run on the same OS thread the
    /// test itself set an override from -- see `application::ports::
    /// PlaceholderPipelineCapabilityPort`'s own doc comment. Not reachable
    /// outside test builds -- see this field's own `cfg`.
    #[cfg(any(test, feature = "test-support"))]
    pub test_placeholder_pipeline_connected: Mutex<Option<bool>>,
    /// Test-only override consulted FIRST by `impl RelaySessionHandler for
    /// DaemonState` (`relay_session_handler.rs`) -- `None` (the default)
    /// leaves the real admission/forwarding pipeline wired in. Lets a test
    /// give one specific device's own `PeerSyncSession`s a recording/
    /// observing handler (e.g. the relay REQUESTER side, "A", which has
    /// no production consumer of its own relayed replies yet -- that
    /// wiring is Pass 6's job, not this mechanism's) without touching any
    /// other device's real behavior. Not reachable outside test builds --
    /// see this field's own `cfg`, mirroring `test_placeholder_pipeline_
    /// connected`'s own reasoning exactly.
    #[cfg(any(test, feature = "test-support"))]
    pub test_relay_session_handler:
        Mutex<Option<Arc<dyn yadorilink_peer_session::peer_session::RelaySessionHandler>>>,
    /// Absolute paths a shell-extension client has asked to pause
    /// individually via `ContextAction::PauseItem` — finer-grained than
    /// the whole-link pause in `SyncState`, and deliberately in-memory
    /// only: it's a transient UI action, not durable state.
    pub paused_paths: Mutex<HashSet<String>>,
    /// This device's observability-facing runtime state -- see
    /// `crate::runtime_telemetry::RuntimeTelemetry`'s own doc comment.
    pub telemetry: Arc<crate::runtime_telemetry::RuntimeTelemetry>,
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
    pub reporting: Arc<ReportingStorage>,
    /// On-disk persistence for the
    /// global rate limits / headroom override (`governance_config`'s doc
    /// comment). Opening this never writes anything to disk by itself,
    /// mirroring `reporting`'s "safe for every existing call site" property.
    pub governance_config: Arc<GovernanceConfigStore>,
    /// The single, shared upload/
    /// download token-bucket pair every `PeerSyncSession` this daemon
    /// constructs is wired to (`peer_orchestrator::spawn_peer_session`,
    /// via `PeerSyncSession::set_rate_limiters`) — this is what makes
    /// "concurrent per-peer fetches share one global ceiling"
    /// true: they all draw from these exact two `Arc<TokenBucket>`
    /// instances, not independent per-session copies. Initialized from
    /// `governance_config` at construction; `GovernanceCommandService::
    /// set_limits` (`adapters::runtime::governance`) re-reads config and
    /// updates these same buckets' rates in place (live reload) rather
    /// than replacing the `Arc`, so every already-connected session picks
    /// up a change on its very next token consumption.
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
    /// This device's durability confirmation/latch state -- see
    /// `crate::durability_service::DurabilityService`'s own doc comment.
    /// `durability.group_durability_latch`: group_id -> latched
    /// `DurabilityUnknown` override, set by
    /// [`Self::latch_group_durability_unknown`] whenever a force override
    /// bypasses this daemon's own durability handoff gate for that group.
    /// A group with NO entry here is not thereby "Healthy" — its status is
    /// still derived live (see [`Self::group_durability_status`]); presence
    /// here only ever pins a group to `DurabilityUnknown` until a later
    /// whole-group handoff re-check clears it. The set is loaded from and
    /// written through `SyncState` so force history survives restart.
    durability: Arc<crate::durability_service::DurabilityService>,
    durability_latch_load_failed: AtomicBool,
    /// Set while at least one `membership_operations` journal row is in
    /// `UnknownScope` state (a `--force` device removal proceeded without a
    /// verified list of groups at risk). Since the AT-RISK GROUPS are
    /// themselves unknown, this cannot be expressed as a per-group latch —
    /// it forces every group's `group_durability_status` to
    /// `DurabilityUnknown` until a reconciliation pass narrows the scope
    /// down to real per-group latches and clears this flag. Loaded from
    /// `SyncState` at startup so it survives a restart, matching
    /// `durability_latch_load_failed`'s own persistence.
    unknown_scope_membership_marker: AtomicBool,
    /// operation_id -> consecutive `TransientFailure` count from
    /// `EnrollmentRecoveryService::reconcile_once`'s activate retries, so a
    /// coordination-plane outage (or any other unconfirmable activate) that
    /// outlasts `enrollment_recovery_service::TRANSIENT_ESCALATION_THRESHOLD` sweeps
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
    /// Check/download/verify/install
    /// orchestration, persisted update policy, and the pinned trust root
    /// for manifest signature verification.
    pub update_manager: Arc<crate::update::manager::UpdateManager>,
    /// Incremented for the duration of
    /// every sync-critical write this daemon performs — the initial
    /// folder scan and every debounced flush's chunk/index/broadcast pass
    /// (the daemon's own `LinkRuntimeController::start`), and on-demand-sync's
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
    /// last-run bookkeeping — see `gc_state::GcState`'s doc comment.
    pub gc: Arc<crate::gc_state::GcState>,
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
    /// Test-only escape hatch from the unconditional, real-time periodic
    /// `daemon-state-membership-recovery-sweep` spawned by [`Self::new`] --
    /// see [`Self::disable_membership_recovery_sweep_for_test`]'s own doc
    /// comment for why a recovery-diagnosis crash-qualification test needs
    /// this. Always `false` (sweep enabled, unchanged from today) unless a
    /// test explicitly opts out; compiled out of non-test builds entirely.
    #[cfg(test)]
    pub(crate) membership_recovery_sweep_disabled_for_test: std::sync::atomic::AtomicBool,
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

/// Backs [`DaemonState::link_runtime_dependencies`]'s narrow bundle: the
/// three operations the per-link runtime module tree (`link_runtime.rs`
/// and `link_runtime/operations/*.rs`) needs but cannot perform itself
/// without reaching into daemon-wide coordination state that dependency
/// bundle deliberately does not carry -- see
/// `link_runtime::dependencies::LinkRuntimeHostPort`'s own doc for why
/// each of these three specifically can't just be a plain field there.
impl crate::link_runtime::dependencies::LinkRuntimeHostPort for DaemonState {
    fn broadcast_change<'a>(
        &'a self,
        group_id: &'a str,
        records: Vec<FileRecord>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        // Resolves to the inherent method below (Rust prefers an inherent
        // method over a trait method of the same name on the same
        // receiver type), not a recursive call into this trait method --
        // the same resolution `HandoffLeaseResponder for DaemonState`
        // already relies on just above.
        Box::pin(self.broadcast_change(group_id, records))
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(self.begin_write_activity())
    }

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.device_signing_key()
    }
}

impl DaemonState {
    /// Narrows this daemon-wide state down to exactly what the per-link
    /// runtime module tree needs -- see
    /// `link_runtime::dependencies::LinkRuntimeDependencies`'s own doc.
    /// Called at the top of every `LinkRuntimeController` entry point that
    /// touches that module tree (`start_inner`, the disk-
    /// reconcile backstop sweep, ...), each of which threads the returned
    /// bundle down instead of `self` from that point on.
    pub(crate) fn link_runtime_dependencies(
        self: &Arc<Self>,
    ) -> Arc<crate::link_runtime::dependencies::LinkRuntimeDependencies> {
        Arc::new(crate::link_runtime::dependencies::LinkRuntimeDependencies {
            replica_coordinator: self.replica_coordinator.clone(),
            block_store: self.block_store.clone(),
            telemetry: self.telemetry.clone(),
            device_id: self.device_id.clone(),
            host: self.clone() as Arc<dyn crate::link_runtime::dependencies::LinkRuntimeHostPort>,
        })
    }

    /// Shared by both `PendingLocalChangeFlush` methods below: resolves
    /// `group_id` to its live `LinkRuntime`, if this device is actively
    /// linked (and watching) that group at all.
    fn link_runtime_for(&self, group_id: &str) -> Option<Arc<crate::link_runtime::LinkRuntime>> {
        let local_path = match self.replica_coordinator.link_repository().list_links() {
            Ok(links) => links.into_iter().find(|l| l.group_id == group_id).map(|l| l.local_path),
            Err(e) => {
                tracing::warn!(error = %e, group_id, "failed to look up this group's local link");
                None
            }
        };
        let local_path = local_path?;
        // `Starting` or absent: nothing to flush against yet either way.
        self.links.runtime(&local_path)
    }
}

impl yadorilink_peer_session::peer_session::PendingLocalChangeFlush for DaemonState {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = yadorilink_peer_session::peer_session::PendingLocalFlushOutcome>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match self.link_runtime_for(group_id) {
                // `Starting` or absent: nothing to flush against yet either way.
                Some(runtime) => runtime.flush_pending_local_change(group_id, rel_path).await,
                None => yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::Settled,
            }
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = yadorilink_peer_session::peer_session::PendingLocalFlushOutcome>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match self.link_runtime_for(group_id) {
                Some(runtime) => runtime.flush_case_fold_sibling(group_id, rel_path).await,
                None => yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::Settled,
            }
        })
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
pub(crate) fn run_blocking_sweep_offloaded(sweep: impl FnOnce()) {
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
    /// Whether this device's on-demand (placeholder) materialization pipeline
    /// is connected end-to-end -- the single place every call site in this
    /// crate (`ReplicaRoleService::set_storage_mode` via
    /// `PlaceholderPipelineCapabilityPort`, `hydration::evict`) should read
    /// this from, so `set_test_placeholder_pipeline_connected`'s override
    /// reaches all of them uniformly instead of each site needing its own
    /// test seam. Falls through to `yadorilink_filesystem_sync::placeholder_backend::
    /// on_demand_pipeline_is_connected` (unconditionally `false` in every
    /// real build) when no test override is set.
    pub(crate) fn on_demand_pipeline_is_connected(&self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(connected) = *self
            .test_placeholder_pipeline_connected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            return connected;
        }
        yadorilink_filesystem_sync::placeholder_backend::on_demand_pipeline_is_connected()
    }

    /// Repairs index rows omitted from the DAG by a policy-withheld initial
    /// import. Called both immediately after a verified policy snapshot lands
    /// and by the periodic materialization audit as a long-horizon retry.
    pub(crate) async fn backfill_missing_change_history(&self, group_id: &str) {
        let Some(signing_key) = self.device_signing_key() else { return };
        let emitter = yadorilink_sync_sqlite::dag_store::ChangeEmitter::new(
            self.device_id.clone(),
            signing_key,
        );
        match crate::dag_import::backfill_missing_history(
            self.replica_coordinator.as_ref(),
            group_id,
            &emitter,
        )
        .await
        {
            Ok(crate::dag_import::BackfillOutcome::Backfilled { paths }) => {
                tracing::info!(
                    group_id,
                    paths,
                    "repaired indexed paths missing from change history"
                );
                match self.replica_coordinator.file_index_repository().list_files(group_id) {
                    Ok(records) => self.broadcast_change(group_id, records).await,
                    Err(e) => tracing::warn!(
                        group_id,
                        error = %e,
                        "history repair committed but immediate heads announce could not be prepared"
                    ),
                }
            }
            Ok(crate::dag_import::BackfillOutcome::NothingMissing) => {}
            Err(e) => tracing::warn!(
                group_id,
                error = %e,
                "change-history coverage audit failed; will retry"
            ),
        }
    }

    /// Convenience wrapper around [`Self::build`] for every caller that
    /// wants the old all-in-one behavior: construct `self`, then start
    /// `MaintenanceCoordinator` on it immediately. Production
    /// (`app::run`) uses `build` directly instead, so it controls exactly
    /// when maintenance starts relative to the rest of composition-root
    /// wiring; this wrapper exists so the very large number of existing
    /// test call sites (which only ever wanted a fully-functional
    /// `DaemonState`, never cared about controlling that ordering
    /// themselves) don't all need to change.
    pub fn new(
        device_id: String,
        replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Arc<Self> {
        let build = Self::build(device_id, replica_coordinator, block_store);
        crate::maintenance_coordinator::start(&build.state, build.forward_rx);
        build.state
    }

    /// Construction only -- builds `self` and wires its internal
    /// closures (local-change-auth/repair-election providers), but starts
    /// no background task and performs no other side effect beyond that
    /// wiring and `update_manager.recover_on_startup()`'s own startup
    /// recovery I/O. The caller owns starting `MaintenanceCoordinator` on
    /// the returned state (see [`Self::new`] for the common case, or
    /// `app::run` for production's own explicit sequencing).
    pub(crate) fn build(
        device_id: String,
        replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> DaemonBuild {
        let (status_push_tx, _) = broadcast::channel(256);
        let (forward_tx, forward_rx) = mpsc::unbounded_channel::<(String, FileRecord)>();
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let governance_config = GovernanceConfigStore::new(crate::device_config::config_dir());
        // Apply whatever's on disk
        // (or the safe unlimited/no-override default if nothing's ever
        // been written) right away, so a freshly-started daemon's very
        // first session/block write already reflects a previous `limits
        // set`/headroom override rather than starting unlimited/unenforced
        // for a beat.
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
        let (persisted_durability_latches, durability_latch_load_failed) = match replica_coordinator
            .role_loss_operation_repository()
            .list_durability_unknown_latches()
        {
            Ok(groups) => (groups, false),
            Err(error) => {
                tracing::error!(%error, "failed to load durability-unknown latches; failing status closed");
                (Vec::new(), true)
            }
        };
        let unknown_scope_membership_marker = replica_coordinator
            .membership_operation_repository()
            .has_open_unknown_durability_scope_operation()
            .unwrap_or(true);
        let (nat_sink, nat_candidates) = yadorilink_transport::CandidateSink::new();
        let state = Arc::new(Self {
            device_id,
            replica_coordinator,
            block_store,
            hydrate_single_flight: crate::hydration_single_flight::HydrateSingleFlight::new(),
            // 512 MiB global / 128 MiB per-peer / 256 MiB per-group,
            // sized against `MAX_BLOCK_SIZE` (16 MiB, `chunker.rs`) --
            // each of a request's credit is reserved pessimistically at
            // that pre-read worst case (see `handle_block_request_with_
            // credit`'s doc comment), so these bound roughly how many
            // full-size blocks this device serves concurrently overall/to
            // one peer/for one group, not raw request count. 16 is
            // `BlockServeEngine::new`'s own tuned value -- it is now BOTH
            // what this device advertises AND the real concurrent-dispatch
            // cap (previously two independently-set, silently-diverging
            // numbers: this passed 64 while the dispatch queue itself was
            // separately hardcoded to 16, so a peer favoring this device
            // based on its advertised worker-slot count was reading a
            // number this device could never actually back up). See that
            // constructor's own doc comment for the throughput/fairness
            // measurements 16 was tuned against before changing it.
            block_serve_engine: yadorilink_peer_session::block_serve::BlockServeEngine::new(
                512 * 1024 * 1024,
                128 * 1024 * 1024,
                256 * 1024 * 1024,
                16,
            ),
            peers: Arc::new(crate::peer_registry::PeerRegistry::new()),
            nat_sink,
            nat_candidates,
            nat_observations: yadorilink_transport::ObservationLog::new(),
            shared_socket: tokio::sync::OnceCell::new(),
            device_static_public: std::sync::OnceLock::new(),
            device_static_secret: std::sync::OnceLock::new(),
            pinned_coordination_service_key: Mutex::new(None),
            relay_forwarder: Arc::new(crate::relay_forwarder::RelayForwarder::new()),
            relay_replay_guard: crate::relay_session::RelayReplayGuard::new(),
            direct_channels: Mutex::new(HashMap::new()),
            active_relay_sessions: Mutex::new(HashMap::new()),
            requester_relay_sessions: Mutex::new(HashMap::new()),
            pending_relay_opens: Mutex::new(HashMap::new()),
            relay_grant_source: Mutex::new(None),
            local_relay_capable: std::sync::atomic::AtomicBool::new(false),
            device_signing_key: Mutex::new(None),
            peer_netmap_metadata: Mutex::new(PeerNetmapMetadata::default()),
            membership_generation: std::sync::atomic::AtomicU64::new(0),
            group_policy_states: Mutex::new(HashMap::new()),
            stale_policy_groups: Mutex::new(HashMap::new()),
            materialization_repair_cursors: Mutex::new(HashMap::new()),
            convergence_engine_cursors: Mutex::new(HashMap::new()),
            convergence_engine_path_budget_cursors: Mutex::new(HashMap::new()),
            local_retirement_sessions: Mutex::new(HashMap::new()),
            materialization_repair_sweep_interval: Mutex::new(
                default_materialization_repair_sweep_interval(),
            ),
            links: Arc::new(crate::link_registry::LinkRegistry::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_root_commit_authorities: Mutex::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_placeholder_pipeline_connected: Mutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            test_relay_session_handler: Mutex::new(None),
            paused_paths: Mutex::new(HashSet::new()),
            telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
            forward_tx,
            in_flight_broadcasts: AtomicI64::new(0),
            shutdown_tx,
            reporting: Arc::new(ReportingStorage::open_default()),
            governance_config: Arc::new(governance_config),
            rate_limiters,
            disk_headroom_enforcement_enabled: std::sync::atomic::AtomicBool::new(false),
            durability: Arc::new(crate::durability_service::DurabilityService::new(
                persisted_durability_latches
                    .into_iter()
                    .map(|group_id| (group_id, GroupDurabilityStatus::DurabilityUnknown))
                    .collect(),
            )),
            durability_latch_load_failed: AtomicBool::new(durability_latch_load_failed),
            unknown_scope_membership_marker: AtomicBool::new(unknown_scope_membership_marker),
            pending_enrollment_transient_attempts: Mutex::new(HashMap::new()),
            update_manager: Arc::new(crate::update::manager::UpdateManager::new(
                crate::device_config::config_dir(),
                current_crate_version(),
            )),
            active_write_ops: AtomicI64::new(0),
            block_liveness_gate: BlockLivenessGate::default(),
            started_at: std::time::Instant::now(),
            last_activity_unix: AtomicI64::new(now_unix()),
            gc: Arc::new(crate::gc_state::GcState::new()),
            coordination_client_config: std::sync::OnceLock::new(),
            #[cfg(test)]
            membership_recovery_sweep_disabled_for_test: std::sync::atomic::AtomicBool::new(false),
        });
        // Recover from any update artifact
        // left unverified, or an install left mid-handoff, by a previous
        // run that crashed/was killed/lost power — before the periodic
        // scheduler (spawned below) or any control-socket update request
        // can observe (and potentially act on) stale state.
        state.update_manager.recover_on_startup();
        {
            let weak_state = Arc::downgrade(&state);
            let local_change_auth_provider: Arc<
                crate::replica_coordinator::LocalChangeAuthProvider,
            > = Arc::new(move |group_id| {
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
            });
            // Since 7D-10.7 repointed `build_change_processor` to construct
            // `LocalChangeProcessor` from `replica_coordinator` (it now
            // implements `LocalMutationStore`), real local edits resolve
            // their authorization stamp through
            // `ReplicaCoordinator::local_emission_auth` exclusively -- the
            // `SyncState`-side copy this provider used to also be wired onto
            // (removed in 7D-10.9 along with the `sync_state` field itself)
            // had no remaining production reader. See
            // phase7d10-exit-report.md's 7D-10.8/7D-10.9 addenda.
            state.replica_coordinator.set_local_change_auth_provider(local_change_auth_provider);
        }
        {
            let weak_state = Arc::downgrade(&state);
            let repair_election_provider: Arc<crate::replica_coordinator::RepairElectionProvider> =
                Arc::new(move |group_id, obligation| {
                    let Some(state) = weak_state.upgrade() else {
                        return Err(PolicyUnavailable);
                    };
                    let Some(signing_key) = state.device_signing_key() else {
                        return Err(PolicyUnavailable);
                    };
                    let local_fingerprint: [u8; 32] =
                        sha2::Sha256::digest(signing_key.verifying_key().as_bytes()).into();
                    let netmap_writers = |state: &DaemonState| {
                        let metadata =
                            state.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
                        let mut writers: Vec<AuthorizedWriter> = metadata
                            .writers
                            .iter()
                            .filter(|(_, writer_group)| writer_group == group_id)
                            .filter_map(|(device_id, _)| {
                                metadata.signing_keys.get(device_id).map(|key| AuthorizedWriter {
                                    device_id: device_id.clone(),
                                    signing_key_fingerprint: sha2::Sha256::digest(key).into(),
                                })
                            })
                            .collect();
                        writers.retain(|writer| writer.device_id != state.device_id);
                        writers.push(AuthorizedWriter {
                            device_id: state.device_id.clone(),
                            signing_key_fingerprint: local_fingerprint,
                        });
                        writers.sort();
                        writers
                    };
                    let (auth, writers) = match state.resolve_group_policy(group_id) {
                        GroupPolicyResolution::Verified(policy) => {
                            let writers = policy.current_writers();
                            if writers.is_empty() {
                                // A verified policy whose Grant chain names NO
                                // writers is the bootstrap regime with a signed
                                // (empty) log: the same regime in which ordinary
                                // emission is still authorized. Taking it
                                // literally here would rank NOBODY — every
                                // replica computes `local_rank = None`, the
                                // deterministic failover never unlocks for any
                                // device, and the liveness guarantee this
                                // election exists to provide (issue #24) silently
                                // dies group-wide (measured: row14's six devices
                                // each logging AwaitingFailover forever while a
                                // six-head frontier never merges). Fall back to
                                // the same netmap-derived writer set the
                                // no-policy bootstrap arm uses; the strict
                                // grant/fingerprint binding still applies
                                // whenever the chain names any writer at all.
                                (policy.change_auth(), netmap_writers(&state))
                            } else {
                                (policy.change_auth(), writers)
                            }
                        }
                        GroupPolicyResolution::Bootstrap => {
                            (ChangeAuth::PLACEHOLDER, netmap_writers(&state))
                        }
                        GroupPolicyResolution::Withhold => return Err(PolicyUnavailable),
                    };
                    RepairElectionContext::new(
                        auth,
                        obligation,
                        writers,
                        state.device_id.clone(),
                        local_fingerprint,
                    )
                    .map_err(|_| PolicyUnavailable)
                });
            // Same reasoning as `local_change_auth_provider` above: real
            // local edits (and the repair-election path that resolves
            // through it) run through `replica_coordinator` exclusively.
            state.replica_coordinator.set_repair_election_provider(repair_election_provider);
        }
        DaemonBuild { state, forward_rx }
    }

    /// This state's runtime-owner components, as `Arc` clones -- for a
    /// caller (the composition root, an adapter) that needs to hold them
    /// directly rather than reach through `DaemonState`.
    #[allow(dead_code)]
    pub(crate) fn runtime_components(&self) -> RuntimeComponents {
        RuntimeComponents {
            peers: self.peers.clone(),
            links: self.links.clone(),
            telemetry: self.telemetry.clone(),
            durability: self.durability.clone(),
        }
    }

    /// Seeds this device's WireGuard static public key for the transport hub's
    /// MAC1 initiation gate. Must be called before the hub is first bound (see
    /// [`ensure_shared_socket`](DaemonState::ensure_shared_socket)); a later
    /// call is a no-op.
    pub fn set_device_static_public(&self, public_bytes: [u8; 32]) {
        let _ = self.device_static_public.set(public_bytes);
    }

    /// M3 Pass 2: seeds this device's WireGuard static PRIVATE key so
    /// `ensure_shared_socket` can call `TransportHub::set_device_identity`,
    /// closing the O(N^2) handshake-fan-in cost the `handshake_fan_in.rs`
    /// reproducer measured (M3 Pass 1) -- see that method's own doc
    /// comment for the full mechanism. Held here the same way
    /// `TransportHub`'s own `DemuxRegistry` now holds an identical copy
    /// (set via that same call), and the same way every registered peer
    /// channel's own `Tunn` ALREADY holds an identical copy for its
    /// lifetime -- not a new class of exposure, one more copy of
    /// already-in-process key material with the same lifetime
    /// characteristics. Must be called before the hub is first bound; a
    /// later call is a no-op (matching `set_device_static_public`'s own
    /// contract exactly).
    pub fn set_device_static_secret(&self, secret: boringtun::x25519::StaticSecret) {
        let _ = self.device_static_secret.set(secret);
    }

    /// M3 Pass 5: records the coordination plane's CURRENTLY pinned
    /// service signing key, mirrored from `record_group_policy_states`'s
    /// own pin decision on every netmap update -- see the field's own
    /// doc comment. A `Mutex`, not a `OnceLock` like `device_static_
    /// secret` above: unlike a device's own identity, the pinned service
    /// key can legitimately be updated (the pin-decision logic itself
    /// governs whether a NEW presented key is accepted as a rotation or
    /// rejected as a mismatch; this setter just mirrors whatever that
    /// logic already decided, it makes no decision of its own).
    pub fn set_pinned_coordination_service_key(&self, key: [u8; 32]) {
        *self.pinned_coordination_service_key.lock().unwrap_or_else(|p| p.into_inner()) = Some(key);
    }

    /// The coordination plane's currently pinned service signing key, if
    /// this device has processed at least one policy-bearing netmap
    /// update. `None` is the fail-safe default relay-grant verification
    /// must treat as "cannot verify anything" -- never a wildcard accept.
    pub fn pinned_coordination_service_key(&self) -> Option<[u8; 32]> {
        *self.pinned_coordination_service_key.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// M3 Pass 5: records `device_id`'s live direct channel -- see
    /// `direct_channels`'s own doc comment for why this mirror exists.
    pub(crate) fn set_direct_channel(
        &self,
        device_id: String,
        channel: Arc<yadorilink_transport::PeerChannel>,
    ) {
        self.direct_channels.lock().unwrap_or_else(|p| p.into_inner()).insert(device_id, channel);
    }

    pub(crate) fn remove_direct_channel(&self, device_id: &str) {
        self.direct_channels.lock().unwrap_or_else(|p| p.into_inner()).remove(device_id);
        // M3 Pass 5: cleanup on route loss -- any relay session THIS
        // device (as relay) currently has open toward `device_id` no
        // longer has a real direct path to forward through (`device_id`
        // disconnected, was revoked, or its channel lost the ABA race on
        // a reconnect -- any of `remove_direct_channel`'s own callers).
        // Closed immediately here rather than left to the forwarder's own
        // idle timeout, which would otherwise keep a now-meaningless
        // session (and its slot) alive for up to a minute after the route
        // it depends on is already gone. See `active_relay_sessions`'s own
        // doc comment for the independent-review finding (M3) this half
        // addresses -- the OTHER half, a route that's still nominally
        // "connected" but no longer `RouteKind::Direct` specifically
        // (e.g. re-racing candidates without the channel object itself
        // being removed), is covered by `revalidate_relay_session`'s own
        // per-datagram check, not here.
        let mut sessions = self.active_relay_sessions.lock().unwrap_or_else(|p| p.into_inner());
        let affected: Vec<u64> = sessions
            .iter()
            .filter(|(_, record)| record.destination_device_id == device_id)
            .map(|(id, _)| *id)
            .collect();
        for session_id in &affected {
            sessions.remove(session_id);
        }
        drop(sessions);
        for session_id in affected {
            self.relay_forwarder.close_session(session_id, "destination_route_lost");
        }
    }

    /// M3 Pass 5 (independent-review findings H2/M3): the full
    /// authorization tuple a relay session was admitted under, keyed by
    /// its forwarder-assigned session id. `RelayForwarder` itself tracks
    /// sessions only by id and raw destination address -- it has no
    /// concept of groups, peers, or authorization at all (deliberately;
    /// see its own module doc comment) -- so THIS is what lets `handle_
    /// relay_data` re-run the exact same group-membership/relay-
    /// capability/direct-route checks `admit_relay_open` ran at OPEN
    /// time, on every single subsequent datagram, closing the session
    /// the moment any of them stops holding. Without this, an already-
    /// open session kept forwarding on stale authorization for the rest
    /// of its grant's lifetime after a group-edge revoke that left
    /// another shared group intact (the exact gap the review's own
    /// framing asked about).
    pub(crate) fn record_relay_session(
        &self,
        session_id: u64,
        source_device_id: String,
        group_id: String,
        destination_device_id: String,
    ) {
        self.active_relay_sessions.lock().unwrap_or_else(|p| p.into_inner()).insert(
            session_id,
            RelaySessionRecord { source_device_id, group_id, destination_device_id },
        );
    }

    pub(crate) fn forget_relay_session(&self, session_id: u64) {
        self.active_relay_sessions.lock().unwrap_or_else(|p| p.into_inner()).remove(&session_id);
    }

    /// M3 Pass 6 (independent-review finding H2): whether `session_id` is
    /// CURRENTLY an active session this device is providing relay for
    /// (role "B"), and if so, its `source_device_id`. Provider-assigned
    /// session ids (this device's own `RelayForwarder` counter) and
    /// requester-tracked session ids (assigned by whichever OTHER device
    /// this device asked to relay for it) are two independent numbering
    /// spaces that happen to share one `u64` wire representation -- a
    /// device that is simultaneously providing relay for peer X AND has
    /// its own requester session open THROUGH peer X can have the SAME
    /// session_id mean two different things depending on role, both
    /// legitimately reachable from an authenticated frame from X. Used by
    /// `relay_session_handler::handle_relay_data`/`handle_relay_close` to
    /// detect that ambiguity and fail closed rather than guess.
    pub(crate) fn active_relay_session_source(&self, session_id: u64) -> Option<String> {
        self.active_relay_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&session_id)
            .map(|record| record.source_device_id.clone())
    }

    /// Re-runs the exact same authorization checks `admit_relay_open` ran
    /// when this session was first admitted, against THIS device's
    /// CURRENT live state -- see `record_relay_session`'s own doc comment
    /// for why this exists and what gap it closes. Returns `Ok(())` if
    /// the session is still fully authorized, `Err(reason)` (a short,
    /// stable slug matching `RelayClose`'s own convention) otherwise --
    /// the caller (`handle_relay_data`) is responsible for actually
    /// closing the session on `Err`; this method only decides, it does
    /// not act. Treats an untracked session id as already-invalid
    /// (`"unknown_session"`) rather than panicking or defaulting
    /// permissive.
    pub(crate) fn revalidate_relay_session(&self, session_id: u64) -> Result<(), &'static str> {
        let record = self
            .active_relay_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&session_id)
            .cloned();
        let Some(record) = record else {
            return Err("unknown_session");
        };
        if !self.peer_is_writer(&record.source_device_id, &record.group_id) {
            return Err("source_no_longer_a_group_member");
        }
        if !self.is_local_group_member(&record.group_id) {
            return Err("relay_no_longer_a_group_member");
        }
        if !self.peer_is_writer(&record.destination_device_id, &record.group_id) {
            return Err("destination_no_longer_a_group_member");
        }
        if !self.is_local_relay_capable() {
            return Err("relay_capability_disabled");
        }
        let still_direct = matches!(
            self.peers.reachability(&record.destination_device_id),
            Some(crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct))
        );
        if !still_direct {
            return Err("destination_route_no_longer_direct");
        }
        Ok(())
    }

    /// `device_id`'s live direct channel, if this device currently has
    /// one -- used by the relay-admission path to confirm a direct route
    /// exists and to read its confirmed address (see `PeerChannel::
    /// confirmed_direct_addr`).
    pub(crate) fn direct_channel(&self, device_id: &str) -> Option<Arc<yadorilink_transport::PeerChannel>> {
        self.direct_channels.lock().unwrap_or_else(|p| p.into_inner()).get(device_id).cloned()
    }

    /// M3 Pass 8 (final-gate review finding, High -- 2nd round): whether
    /// this device's OWN path to `device_id` is CURRENTLY a confirmed
    /// direct `PeerChannel`, read from the live channel object itself
    /// (`direct_channel` above) rather than `self.peers.reachability()`
    /// -- see `relay_candidates`'s own doc comment for why that
    /// distinction matters here specifically: the registry is only an
    /// asynchronously-updated mirror of this exact same channel's own
    /// watch channel, so it can briefly still report a route that has
    /// already changed. Used by both relay-candidate SELECTION and
    /// immediately before actually sending, in `relay_carrier.rs`, to
    /// keep the window between the two as narrow as this call's own cost.
    pub(crate) fn is_directly_reachable(&self, device_id: &str) -> bool {
        self.direct_channel(device_id).is_some_and(|channel| {
            matches!(
                channel.reachability(),
                yadorilink_transport::PeerReachability::Connected { .. }
            )
        })
    }

    /// The device_id that owns the channel whose WireGuard static public
    /// key is `peer_public` -- the reverse of `direct_channel` above. A
    /// linear scan over `direct_channels` rather than a second
    /// synchronized side table: this map is small (bounded by this
    /// device's own connected-peer count) and only ever consulted from
    /// `RelayCarrier::send_via_relay`, never a hot path.
    pub(crate) fn device_id_for_peer_public(&self, peer_public: &[u8; 32]) -> Option<String> {
        self.direct_channels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, channel)| &channel.peer_public() == peer_public)
            .map(|(device_id, _)| device_id.clone())
    }

    /// M3 Pass 6: installs a `RelayGrantSource` -- see that trait's own
    /// doc comment for why nothing calls this in production yet (`pub`
    /// under this cfg, not `pub(crate)`, specifically so an integration
    /// test in `tests/` -- a separate compilation unit from this crate's
    /// own `src/` -- can install `FakeCoordination` as one, matching
    /// `test_relay_session_handler`'s own visibility for the identical
    /// reason).
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_relay_grant_source(&self, source: Arc<dyn crate::relay_carrier::RelayGrantSource>) {
        *self.relay_grant_source.lock().unwrap_or_else(|p| p.into_inner()) = Some(source);
    }

    /// M3 Pass 7 (chaos tests): the requester-tracked session id this
    /// device is currently using to reach `destination_peer_public` via
    /// relay, if any -- `pub` under this same cfg and for the identical
    /// reason as `set_relay_grant_source`, so an integration test can
    /// distinguish multiple concurrent relay sessions (e.g. multi-peer
    /// fan-in through one relay) by id rather than only by aggregate
    /// count.
    #[cfg(any(test, feature = "test-support"))]
    pub fn requester_relay_session_id_for_destination_test(
        &self,
        destination_peer_public: &[u8; 32],
    ) -> Option<u64> {
        self.requester_relay_session_for_destination(destination_peer_public, now_unix())
            .map(|(id, _)| id)
    }

    pub(crate) fn relay_grant_source(
        &self,
    ) -> Option<Arc<dyn crate::relay_carrier::RelayGrantSource>> {
        self.relay_grant_source.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// M3 Pass 6: candidate relay devices for reaching `destination_
    /// device_id` -- every device that (a) has declared `RelayCapability::
    /// Capable`, (b) shares at least one group with BOTH this device and
    /// the destination (the same group, not merely one group each -- a
    /// relay grant is scoped to one `group_id` shared by all three, see
    /// `relay_grant::RelayGrant`'s own fields), and (c) this device
    /// already has a live `PeerSyncSession` with (never dials a NEW
    /// connection purely to use someone as a relay -- a real, deliberate
    /// scope limit of this increment, not an oversight: opening fresh
    /// connections on the relay-selection path would make an already
    /// best-effort fallback path responsible for its own connection
    /// supervision too). Returns `(relay_device_id, group_id)` pairs,
    /// most-recently-registered-writer order is not meaningful here (plain
    /// `HashSet` iteration) -- the caller tries them in whatever order
    /// this returns and stops at the first that actually grants.
    pub(crate) fn relay_candidates(&self, destination_device_id: &str) -> Vec<(String, String)> {
        let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let groups_of = |device_id: &str| -> HashSet<String> {
            metadata
                .writers
                .iter()
                .filter(|(d, _)| d == device_id)
                .map(|(_, g)| g.clone())
                .collect()
        };
        let dest_groups = groups_of(destination_device_id);
        let mut candidates = Vec::new();
        for relay_device_id in &metadata.relay_capable {
            if relay_device_id == &self.device_id || relay_device_id == destination_device_id {
                continue;
            }
            // M3 Pass 8 (final-gate review finding, High -- 2nd round):
            // requires the underlying `PeerChannel` to `relay_device_id`
            // to be itself direct, not merely "connected" -- without this,
            // if this device's OWN path to `relay_device_id` is itself
            // `ConnectedRelay` (through some other device D), a session
            // opened "through" it would actually chain A->D->B->C: every
            // local admission check on B still passes (B sees an
            // authenticated peer and a direct B->C route), with no
            // provenance that A's frames were already relayed before
            // reaching B. This is the identical requirement `relay_
            // session::RelayAdmissionContext::has_direct_route_to_
            // destination`'s own doc comment already enforces on B's side
            // for the B->C leg.
            //
            // Reads the LIVE `PeerChannel` (`is_directly_reachable`), not
            // `self.peers.reachability()` -- the first review round's own
            // fix used that daemon-level registry, which is only an
            // ASYNCHRONOUSLY updated mirror of the channel's own watch
            // channel (`poll_reachability`'s own background task is what
            // copies one into the other), so a route that had just
            // flipped away from Direct could still read as Direct here
            // for one mirror-propagation cycle. `direct_channel` is the
            // same `Arc<PeerChannel>` `send_via_relay` itself sends over
            // moments later, so this reads the exact object whose state
            // actually matters, not a lagging copy of it.
            if !self.is_directly_reachable(relay_device_id) {
                continue;
            }
            let relay_groups = groups_of(relay_device_id);
            // This device's own membership is NOT read from `metadata.
            // writers` -- that set is populated per-PEER from the netmap
            // (`replace_peer_netmap_metadata`), and self is not its own
            // netmap peer entry. `is_local_group_member` is the same
            // check `RelayAdmissionContext::relay_is_group_member` uses
            // on the provider side, for the identical reason.
            if let Some(group_id) = relay_groups
                .intersection(&dest_groups)
                .find(|group_id| self.is_local_group_member(group_id))
            {
                candidates.push((relay_device_id.clone(), group_id.clone()));
            }
        }
        candidates
    }

    /// M3 Pass 6: records that session `session_id`, opened by THIS device
    /// as relay REQUESTER via `relay_device_id`, carries traffic for
    /// `destination_peer_public` -- see `requester_relay_sessions`'s own
    /// doc comment. `expires_at_unix` mirrors the admitting grant's own
    /// expiry (independent-review, final-gate finding): B's forwarder
    /// enforces its own expiry independently and closes on its own, but
    /// its one-shot `RelayClose` frame can be lost (a dropped/full
    /// `try_send`, or the A<->B session itself briefly backed up) with no
    /// retry -- without also tracking the expiry HERE, a lost close would
    /// let this device reuse (and report success for) a session B has
    /// already forgotten, forever.
    pub(crate) fn record_requester_relay_session(
        &self,
        session_id: u64,
        relay_device_id: String,
        destination_peer_public: [u8; 32],
        expires_at_unix: i64,
        opened_via: &Arc<yadorilink_peer_session::peer_session::PeerSyncSession>,
    ) {
        self.requester_relay_sessions.lock().unwrap_or_else(|p| p.into_inner()).insert(
            (relay_device_id.clone(), session_id),
            RequesterRelaySession {
                relay_device_id,
                destination_peer_public,
                expires_at_unix,
                opened_via: Arc::downgrade(opened_via),
            },
        );
    }

    /// An existing requester-opened session already carrying traffic for
    /// `destination_peer_public`, if this device has one AND the
    /// `PeerSyncSession` it was opened over is still the live one (see
    /// `RequesterRelaySession::opened_via`'s own doc comment) AND it
    /// hasn't outlived its own recorded grant expiry -- `send_via_relay`
    /// reuses it rather than opening a new one per datagram. A stale
    /// entry (the relay connection was replaced since this session
    /// opened, or the grant has expired) is removed here rather than left
    /// for a later caller to rediscover the same staleness.
    pub(crate) fn requester_relay_session_for_destination(
        &self,
        destination_peer_public: &[u8; 32],
        now_unix: i64,
    ) -> Option<(u64, String)> {
        let mut sessions = self.requester_relay_sessions.lock().unwrap_or_else(|p| p.into_inner());
        let (key, record) = sessions
            .iter()
            .find(|(_, s)| &s.destination_peer_public == destination_peer_public)
            .map(|(key, s)| (key.clone(), s.clone()))?;
        let still_live = now_unix < record.expires_at_unix
            && record.opened_via.upgrade().is_some_and(|session| {
                self.peers
                    .session(&record.relay_device_id)
                    .is_some_and(|current| Arc::ptr_eq(&session, &current))
            });
        if still_live {
            Some((key.1, record.relay_device_id))
        } else {
            sessions.remove(&key);
            None
        }
    }

    /// The relay device a requester-opened `session_id` was opened
    /// through, and its destination -- used to route an inbound
    /// `RelayData`/close for this session id (this device receiving its
    /// own relay's reply) rather than mistaking it for a forward request.
    /// Keyed by `(relay_device_id, session_id)`, NOT `session_id` alone
    /// (independent-review, final-gate finding): each relay assigns
    /// session ids from its OWN independent counter starting at 1, so two
    /// DIFFERENT relays this device is simultaneously using as requester
    /// routinely hand back the identical number -- a bare `u64` key would
    /// let the second `record_requester_relay_session` silently overwrite
    /// the first device's entry. `relay_device_id` -- already known by the
    /// caller as `authenticated_peer_device_id`, the identity of whichever
    /// session this frame physically arrived on -- makes the lookup exact
    /// rather than an ownership check performed after the fact.
    pub(crate) fn requester_relay_session(
        &self,
        relay_device_id: &str,
        session_id: u64,
    ) -> Option<[u8; 32]> {
        self.requester_relay_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(relay_device_id.to_string(), session_id))
            .map(|s| s.destination_peer_public)
    }

    pub(crate) fn forget_requester_relay_session(&self, relay_device_id: &str, session_id: u64) {
        self.requester_relay_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(relay_device_id.to_string(), session_id));
    }

    /// M3 Pass 6: registers a oneshot to be resolved by the matching
    /// `RelayOpenedFrame` reply, scoped to `expected_relay_device_id` (the
    /// device this device is actually sending the `RelayOpen` to) -- see
    /// `pending_relay_opens`'s own doc comment.
    pub(crate) fn register_pending_relay_open(
        &self,
        grant_id: String,
        expected_relay_device_id: String,
        sender: tokio::sync::oneshot::Sender<yadorilink_sync_wire::RelayOpenedFrame>,
    ) {
        self.pending_relay_opens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(grant_id, (expected_relay_device_id, sender));
    }

    /// Resolves and removes the pending open matching `opened.grant_id`,
    /// if this device has one outstanding AND `authenticated_peer_device_id`
    /// matches the device that open was actually sent to -- called from
    /// `handle_relay_opened`. A miss (already timed out, an `opened` for a
    /// grant_id this device never requested, or a sender mismatch) is
    /// silently a no-op, matching `RelaySessionHandler::handle_relay_
    /// opened`'s own doc comment; a mismatch specifically is put back so
    /// the device that was actually asked can still resolve it later.
    pub(crate) fn resolve_pending_relay_open(
        &self,
        opened: yadorilink_sync_wire::RelayOpenedFrame,
        authenticated_peer_device_id: &str,
    ) {
        let mut pending = self.pending_relay_opens.lock().unwrap_or_else(|p| p.into_inner());
        let Some((expected_relay_device_id, _)) = pending.get(&opened.grant_id) else {
            return;
        };
        if expected_relay_device_id != authenticated_peer_device_id {
            tracing::debug!(
                grant_id = %opened.grant_id,
                peer = authenticated_peer_device_id,
                "relay opened reply from a device that was never sent this open; ignoring"
            );
            return;
        }
        if let Some((_, sender)) = pending.remove(&opened.grant_id) {
            drop(pending);
            let _ = sender.send(opened);
        }
    }

    /// M3 Pass 6 (independent-review finding): removes a pending open
    /// this device's own `RelayCarrier::send_via_relay` is giving up on
    /// (the `RelayOpen` send itself failed, or its reply timed out) --
    /// without this, `pending_relay_opens` accumulates one entry per
    /// failed/timed-out attempt forever, since `resolve_pending_relay_
    /// open` only ever removes an entry that actually gets a matching
    /// reply.
    pub(crate) fn forget_pending_relay_open(&self, grant_id: &str) {
        self.pending_relay_opens.lock().unwrap_or_else(|p| p.into_inner()).remove(grant_id);
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
        let hub = self
            .shared_socket
            .get_or_try_init(|| async {
                let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
                yadorilink_transport::TransportHub::bind(addr, device_public).await
            })
            .await
            .cloned()?;
        // M3 Pass 2: idempotent (`TransportHub::set_device_identity`'s own
        // `OnceLock`-backed no-op-on-second-call contract), so calling it
        // on every `ensure_shared_socket` invocation (not just the one
        // that actually bound the hub) is deliberate and cheap -- avoids
        // needing this closure itself to reach into `device_static_secret`
        // (that would move the read outside `get_or_try_init`'s own
        // closure, which is fine, but doing it here keeps the ordering
        // dependency explicit: identity is set on whatever hub instance
        // this call ends up returning, whether freshly bound or already
        // cached).
        if let Some(secret) = self.device_static_secret.get() {
            hub.set_device_identity(secret.clone());
        }
        Ok(hub)
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
        self.links.mark_degraded(local_path, reason, now_unix(), |backoff_attempt| {
            supervise::BackoffConfig::DEGRADED_LINK_RECHECK.next(backoff_attempt).as_secs() as i64
        });
    }

    /// Clears `local_path`'s Degraded state, if any — a no-op if it wasn't
    /// degraded.
    pub fn clear_link_degraded(&self, local_path: &str) {
        self.links.clear_degraded(local_path);
    }

    pub fn is_link_degraded(&self, local_path: &str) -> bool {
        self.links.is_degraded(local_path)
    }

    pub fn degraded_link_info(
        &self,
        local_path: &str,
    ) -> Option<crate::link_registry::DegradedLinkInfo> {
        self.links.degraded_info(local_path)
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
    ) -> Result<(), crate::sync_error::SyncError> {
        self.replica_coordinator
            .role_loss_operation_repository()
            .latch_group_durability_unknown(group_id)?;
        self.durability.latch_unknown(group_id);
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
    ) -> Result<(), crate::sync_error::SyncError> {
        self.replica_coordinator
            .role_loss_operation_repository()
            .clear_group_durability_unknown(group_id)?;
        self.durability.clear_unknown(group_id);
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
        // The three account-wide/group-scoped "cannot currently confirm"
        // facts (latch-table load failure, an unresolved unknown-scope
        // removal, a recovery-blocked membership operation) are gathered
        // here since they live on `DaemonState`'s own atomics/`SyncState`,
        // not inside `DurabilityService` -- see
        // `crate::durability_service::classify`'s own doc for why this
        // exact precedence (each one short-circuits before the optimistic
        // materialization check ever runs) is the actual fail-safe
        // property, not an implementation detail. `latched_unknown` is
        // left `false` here -- `DurabilityService::classify` fills it in
        // from its own latch table, which this method never touches
        // directly.
        let facts = crate::durability_service::DurabilityFacts {
            latch_load_failed: self.durability_latch_load_failed.load(Ordering::SeqCst),
            scope_unknown: self.unknown_scope_membership_marker.load(Ordering::SeqCst),
            recovery_blocked: self
                .replica_coordinator
                .membership_operation_repository()
                .has_recovery_blocked_membership_operation()
                .unwrap_or(true),
            latched_unknown: false,
            materialization: match self
                .replica_coordinator
                .materialization_state_repository()
                .materialization_counts(group_id)
            {
                Ok(counts) if counts.placeholder == 0 && counts.hydrating == 0 => {
                    Ok(crate::durability_service::MaterializationHealth::FullyLocal)
                }
                Ok(_) => Ok(crate::durability_service::MaterializationHealth::Partial),
                Err(_) => Err(()),
            },
        };
        self.durability.classify(group_id, facts)
    }

    /// re-checks free space for every Degraded link whose backoff
    /// window has elapsed, clearing it ("cleared once a
    /// subsequent headroom check for that link's volume succeeds") once
    /// the volume is no longer `Critical`, or rescheduling it (bumped
    /// backoff) if it's still under pressure. A link whose local folder no
    /// longer exists (unlinked while degraded) or whose free space can't
    /// currently be determined is left degraded rather than guessed clear.
    pub(crate) fn recheck_degraded_links(&self) {
        let now = now_unix();
        let due = self.links.degraded_due_snapshot(now);
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
    /// registered. A registered (non-empty `device_id`) `DaemonState` built
    /// without one is a fail-closed condition, not a legitimate no-emitter
    /// path — see `ensure_initial_change_history`'s own doc
    /// comment for why: local edits would be indexed but never recorded as
    /// DAG changes, which is silent data loss from the group's perspective.
    /// Only a genuinely unregistered device (empty `device_id`) tolerates
    /// this being unset.
    pub fn set_device_signing_key(&self, signing_key: ed25519_dalek::SigningKey) {
        *self.device_signing_key.lock().unwrap_or_else(|p| p.into_inner()) = Some(signing_key);
    }

    /// This device's change-history signing key, if one has been wired.
    /// Consulted by the daemon's own `LinkRuntimeController`-owned module tree when deciding whether to emit signed
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
        relay_capable: bool,
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
        if relay_capable {
            metadata.relay_capable.insert(device_id.to_string());
        } else {
            metadata.relay_capable.remove(device_id);
        }
        // M3 Pass 4 (independent-review finding): `relay_capable` changes
        // deliberately do NOT bump `membership_generation` -- that counter
        // is netmap AUTHORIZATION state (see its own doc comment), read by
        // durability confirmations and full-replica handoffs to fail
        // closed on ANY membership churn during their wait. Relay
        // willingness is neither authorization nor durability -- coupling
        // it in would make toggling a peer's relay declaration able to
        // spuriously fail an unrelated in-flight durability confirmation,
        // exactly the connectivity/durability coupling `crate::route`'s
        // own doc comment says this model must never introduce.
        let changed = key_changed
            || before_writers != *authorized_groups
            || before_replicas != next_replicas;
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
    }

    pub fn clear_peer_netmap_metadata(&self, device_id: &str) {
        self.replace_peer_netmap_metadata(device_id, None, &HashSet::new(), &HashSet::new(), false);
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

    /// Whether THIS device syncs `group_id` as a full replica (its link's
    /// storage mode is eager/"store everything"). A missing link or any lookup
    /// error is treated as "not a full replica" — the guard/custody callers
    /// only ever need the positive, and an absent link cannot be a replica.
    pub fn is_local_full_replica(&self, group_id: &str) -> bool {
        matches!(
            self.replica_coordinator.link_repository().materialization_policy_for_group(group_id),
            Ok(Some(yadorilink_replica_domain::session_state::MaterializationPolicy::Eager))
        )
    }

    /// Whether THIS device is currently a member of `group_id` at all
    /// (any storage mode, not just full-replica) -- used by relay
    /// admission to re-verify its own membership in a grant's `group_id`
    /// independent of what the grant itself claims.
    pub fn is_local_group_member(&self, group_id: &str) -> bool {
        self.replica_coordinator
            .link_repository()
            .materialization_policy_for_group(group_id)
            .is_ok_and(|policy| policy.is_some())
    }

    /// M3 Pass 5: sets this device's own local relay-capability
    /// configuration -- see `local_relay_capable`'s own doc comment.
    pub fn set_local_relay_capable(&self, capable: bool) {
        self.local_relay_capable.store(capable, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_local_relay_capable(&self) -> bool {
        self.local_relay_capable.load(std::sync::atomic::Ordering::Relaxed)
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

    /// `device_id`'s current, netmap-derived relay capability -- see
    /// `crate::route::RelayCapability`'s own doc comment for the
    /// `Durability != Connectivity` invariant this deliberately does NOT
    /// derive from `peer_group_is_full_replica` or anything else: it is
    /// purely that peer's own self-declaration, recorded independently.
    pub fn peer_relay_capability(&self, device_id: &str) -> crate::route::RelayCapability {
        if self
            .peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .relay_capable
            .contains(device_id)
        {
            crate::route::RelayCapability::Capable
        } else {
            crate::route::RelayCapability::Disabled
        }
    }

    /// Installs the custody confirmer used by the on-demand reclamation gate.
    /// Production wires a peer-to-peer confirmer (below); tests inject a
    /// deterministic one so custody behavior can be exercised without a live
    /// peer.
    #[cfg(test)]
    pub fn set_custody_confirmer(&self, confirmer: Arc<dyn CustodyConfirmer>) {
        self.durability.install_custody_confirmer(confirmer);
    }

    /// Wires the peer-to-peer custody confirmer. Physical cache reclamation is
    /// still disabled until confirmations carry crash-durable responder-side
    /// GC leases; this wiring preserves exact-version diagnostics and the
    /// generation-stamped implementation that the future lease flow will use.
    pub fn install_p2p_custody_confirmer(self: &Arc<Self>) {
        self.durability.install_custody_confirmer(Arc::new(
            crate::adapters::runtime::custody::P2pCustodyConfirmer::new(self),
        ));
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
        self.durability.confirm_version(group_id, path, version_hash, blocks)
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
        self.durability.confirmation_still_valid(group_id, stamp)
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

    pub(crate) async fn confirm_version_present_witness_via_peer(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let candidates: Vec<(String, Arc<PeerSyncSession>)> = self
            .peers
            .all_sessions()
            .into_iter()
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

    /// Overrides how often the daemon-level materialization-repair sweep
    /// (`spawn_materialization_repair_scheduler`) re-drives any change still
    /// unapplied — see `materialization_repair_sweep_interval`'s doc
    /// comment. A test whose scenario can leave a change legitimately
    /// stalled for multiple production-cadence (90s) intervals with no
    /// other retry trigger in flight (no new local writes, no incoming
    /// traffic) can opt into a much shorter one instead of either widening
    /// its own timeout budget to absorb 90s gaps or accepting a wall-clock
    /// tax production doesn't need. Takes effect on this scheduler's next
    /// `interval.tick()`; a change after `DaemonState::new` has already
    /// spawned it has no effect on a tick already in flight.
    pub fn set_materialization_repair_sweep_interval(&self, interval: Duration) {
        *self.materialization_repair_sweep_interval.lock().unwrap_or_else(|p| p.into_inner()) =
            interval;
    }

    /// `pub(crate)`: read by `maintenance::materialization_repair::
    /// MaterializationRepairJob`, which owns this scheduler's sleep-loop
    /// (moved out of this file's own former
    /// `spawn_materialization_repair_scheduler`).
    pub(crate) fn materialization_repair_sweep_interval(&self) -> Duration {
        *self.materialization_repair_sweep_interval.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// This device's coordination-plane address + access token, if recorded
    /// — see [`Self::set_coordination_client_config`]'s doc comment for when
    /// it is (and, notably, isn't: most of this crate's own unit tests never
    /// call the setter) set.
    pub fn coordination_client_config(&self) -> Option<&CoordinationClientConfig> {
        self.coordination_client_config.get()
    }

    /// Stops the real-time periodic `daemon-state-membership-recovery-sweep`
    /// (role-loss + membership reconciliation, unconditional and
    /// real-time -- see that sweep's own doc comment) from acting on THIS
    /// `DaemonState`'s journal rows. A recovery-diagnosis crash-
    /// qualification test builds a real `DaemonState` (through the same
    /// `new()` production callers use) specifically to plant a membership/
    /// role-loss journal row and read it back through the real
    /// `recovery show` path -- the SAME background sweep this daemon would
    /// also run in production would otherwise race that read (some sweep
    /// branches mutate or delete a matching row unconditionally, with no
    /// age gate, regardless of whether a coordination-plane config is even
    /// set), corrupting the very state under test. Must be called
    /// synchronously, before this task's first `.await` after construction
    /// -- the spawned sweep task cannot run even one line of its own code
    /// until the caller yields, so calling this immediately after `new()`
    /// is race-free by construction, not by timing luck.
    #[cfg(test)]
    pub fn disable_membership_recovery_sweep_for_test(&self) {
        self.membership_recovery_sweep_disabled_for_test
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
        self.replica_coordinator
            .role_loss_operation_repository()
            .insert_role_loss_operation(
                &operation_id,
                group_id,
                RoleLossOperationParams {
                    source_device_id: &self.device_id,
                    target_device_id,
                    lease_id: Some(lease_id),
                    action,
                    local_path: Some(local_path),
                    now_unix: now_unix(),
                },
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
    ///   left as a split state. Best-effort: even if this write itself fails
    ///   (row stays `Prepared`), the sweep treats a `Prepared` row the same as
    ///   `WorkerCommitted` at reconciliation time — see
    ///   [`yadorilink_sync_core::index::RoleLossOperationState::Prepared`]'s
    ///   doc comment for why that's safe.
    pub fn mark_role_loss_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .mark_role_loss_worker_committed(operation_id, membership_generation, now_unix())
        {
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
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .delete_role_loss_operation(operation_id)
        {
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
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .advance_role_loss_operation(operation_id, RoleLossOperationState::LocalCommitted, now)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a role-loss operation journal row to LocalCommitted"
            );
        }
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .delete_role_loss_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a LocalCommitted role-loss operation journal row; it will be \
                 cleaned up by the next reconciliation sweep"
            );
        }
    }

    /// Persists a membership-operation journal row -- see
    /// [`yadorilink_sync_core::index::MembershipOperation`]'s doc comment.
    /// Called instead of releasing tickets / falling through to a plain
    /// revoke-remove, so an outcome that MAY already have committed on the
    /// coordination plane is never silently treated as "never happened".
    /// Never overwrites an existing row under `operation_id` -- returns
    /// `Ok(false)` on conflict so the caller can retry under a fresh id
    /// (see `replica_membership_service.rs`'s `open_membership_operation`),
    /// rather than silently clobbering whatever that row already recorded.
    #[allow(clippy::too_many_arguments)]
    pub fn try_persist_membership_operation(
        &self,
        operation_id: &str,
        action: MembershipOperationAction,
        commit_mode: MembershipCommitMode,
        removed_device_id: &str,
        group_ids: &[String],
        target_device_ids: &[String],
        lease_ids: &[Option<String>],
        state: MembershipOperationState,
        durability_scope: MembershipDurabilityScope,
        latch_group_ids: &[String],
        last_error: Option<&str>,
    ) -> Result<bool, String> {
        let inserted = self
            .replica_coordinator
            .membership_operation_repository()
            .try_insert_membership_operation(
                operation_id,
                action,
                commit_mode,
                removed_device_id,
                group_ids,
                target_device_ids,
                lease_ids,
                state,
                durability_scope,
                latch_group_ids,
                last_error,
                now_unix(),
            )
            .map_err(|e| e.to_string())?;
        if inserted && durability_scope == MembershipDurabilityScope::Unknown {
            self.unknown_scope_membership_marker.store(true, Ordering::SeqCst);
        }
        Ok(inserted)
    }

    /// Advances an existing `Prepared` membership-operation row to
    /// `Ambiguous` — the row is KEPT (not deleted), unlike
    /// [`Self::settle_membership_operation`]: an ambiguous commit's real
    /// outcome is still unknown, so its journal row must survive for
    /// `reconcile_ambiguous_membership_operations` to resolve later.
    /// Best-effort: even if this write fails, the row stays `Prepared`,
    /// which the reconciler treats the same way (see
    /// [`yadorilink_sync_core::index::MembershipOperationState::Ambiguous`]'s
    /// doc comment for the analogous role-loss reasoning this mirrors).
    pub fn mark_membership_operation_ambiguous(&self, operation_id: &str, detail: &str) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .mark_membership_operation_state(
                operation_id,
                MembershipOperationState::Ambiguous,
                Some(detail),
                now_unix(),
            )
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a membership operation journal row to Ambiguous"
            );
        }
    }

    /// Marks a membership-operation journal row's outcome as settled
    /// (`Completed`/`DefinitelyRejected`) by deleting it directly --
    /// best-effort, matching [`Self::settle_role_loss_operation_success`].
    /// Deletes in ONE step rather than updating to `final_state` and then
    /// deleting: a row is never re-read after reaching a terminal state
    /// (`scan_open_membership_operations` excludes both terminal states),
    /// so an update that succeeds but is followed by a failed delete would
    /// leave an orphaned row invisible to every future sweep -- there is no
    /// "cleaned up by the next reconciliation sweep" for a row a terminal
    /// state itself hides from that sweep's own query.
    pub fn settle_membership_operation(
        &self,
        operation_id: &str,
        _final_state: MembershipOperationState,
    ) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .delete_membership_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a settled membership operation; its non-terminal journal row \
                 remains available for idempotent recovery"
            );
        }
        self.refresh_unknown_scope_membership_marker();
    }

    /// Deletes a membership-operation journal row whose scope became known
    /// (an unknown-scope marker converted to per-group latches) — matching
    /// [`Self::discard_role_loss_operation`].
    pub fn discard_membership_operation(&self, operation_id: &str) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .delete_membership_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a resolved membership operation journal row"
            );
        }
        self.refresh_unknown_scope_membership_marker();
    }

    /// Advances a membership-operation row to `RecoveryBlocked` -- automatic
    /// recovery refused (an operation_id conflict, a local/remote request
    /// identity mismatch, or a malformed journal row). The row is KEPT (not
    /// deleted): unlike a confirmed terminal outcome, there is nothing safe
    /// to conclude here, so it stays for operator attention and is excluded
    /// from periodic resend/settlement.
    pub fn mark_membership_operation_recovery_blocked(&self, operation_id: &str, detail: &str) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .mark_membership_operation_state(
                operation_id,
                MembershipOperationState::RecoveryBlocked,
                Some(detail),
                now_unix(),
            )
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a membership operation journal row to RecoveryBlocked"
            );
        }
    }

    /// Advances a membership-operation row to `LocalSettlementPending` --
    /// the remote mutation is confirmed committed, but a required local
    /// follow-up (e.g. a post-commit durability latch) failed and must be
    /// retried. The row is KEPT so the next reconciliation sweep retries the
    /// local step; it must never be silently discarded until that step also
    /// succeeds.
    pub fn mark_membership_operation_local_settlement_pending(
        &self,
        operation_id: &str,
        detail: &str,
    ) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .mark_membership_operation_state(
                operation_id,
                MembershipOperationState::LocalSettlementPending,
                Some(detail),
                now_unix(),
            )
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a membership operation journal row to LocalSettlementPending"
            );
        }
    }

    /// Re-derives `unknown_scope_membership_marker` from the journal —
    /// called after any delete/settle that might have resolved the last
    /// outstanding `Unknown`-durability-scope row, so `group_durability_status`
    /// stops forcing `DurabilityUnknown` account-wide once every such row is
    /// resolved.
    fn refresh_unknown_scope_membership_marker(&self) {
        let still_present = self
            .replica_coordinator
            .membership_operation_repository()
            .has_open_unknown_durability_scope_operation()
            .unwrap_or(true);
        self.unknown_scope_membership_marker.store(still_present, Ordering::SeqCst);
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
        let Some(op) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .get_role_loss_operation(operation_id)
            .map_err(|e| e.to_string())?
        else {
            return Ok(());
        };
        if op.state != RoleLossOperationState::Compensating {
            if let Err(e) = self
                .replica_coordinator
                .role_loss_operation_repository()
                .advance_role_loss_operation(
                    operation_id,
                    RoleLossOperationState::Compensating,
                    now_unix(),
                )
            {
                tracing::warn!(
                    error = %e,
                    operation_id,
                    "failed to advance a role-loss operation journal row to Compensating"
                );
            }
        }
        let Some(config) = self.coordination_client_config() else {
            let attempts = self
                .replica_coordinator
                .role_loss_operation_repository()
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
            self.replica_coordinator
                .role_loss_operation_repository()
                .delete_role_loss_operation(operation_id)
                .map_err(|e| e.to_string())?;
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
                if let Err(e) = self
                    .replica_coordinator
                    .role_loss_operation_repository()
                    .advance_role_loss_operation(
                        operation_id,
                        RoleLossOperationState::Completed,
                        now_unix(),
                    )
                {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        "failed to advance a role-loss operation journal row to Completed"
                    );
                }
                if let Err(e) = self
                    .replica_coordinator
                    .role_loss_operation_repository()
                    .delete_role_loss_operation(operation_id)
                {
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
                    .replica_coordinator
                    .role_loss_operation_repository()
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
    /// (`sync_state.handoff_lease_repository().record_handoff_lease_atomic`),
    /// so no retention sweep can evict a row between enumerating it and
    /// pinning it (the gap a separate `record_handoff_lease` call alone
    /// leaves — see its sibling's own doc comment). Ordering the Worker call
    /// first is what makes this
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
    /// the just-written local pin
    /// (`sync_state.handoff_lease_repository().set_handoff_lease_state`,
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
        let (pinned_digest, _pinned_versions) = match self
            .replica_coordinator
            .handoff_lease_repository()
            .record_handoff_lease_atomic(group_id, &grant.lease_id, now_unix(), grant.ttl_seconds)
        {
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
                .replica_coordinator
                .handoff_lease_repository()
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
        if let Err(e) = self
            .replica_coordinator
            .handoff_lease_repository()
            .set_handoff_lease_state(lease_id, HandoffLeaseState::Released)
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
        let session = self.peers.session(target_peer_device_id)?;
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
        let session = self.peers.session(device_id)?;
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
    ) -> Result<(), String> {
        let session = self.peers.session(device_id);
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
                return Err(e.to_string());
            }
            return Ok(());
        }
        Err(format!("no active session for removed device {device_id}"))
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
        for (peer_id, session) in self.peers.all_sessions() {
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
        self.replica_coordinator
            .file_index_repository()
            .enumerate_group_durability_roots(group_id)
            .ok()
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
        for (_, session) in self.peers.all_sessions() {
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
        self.replica_coordinator
            .link_repository()
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
    /// write (folder scan/flush processing in the daemon's own `LinkRuntimeController`,
    /// materialization writes in `hydration.rs`) so
    /// `is_write_safe_point` reports `false` for its duration. Public (not
    /// just crate-visible) since both call sites are in sibling modules
    /// of this same crate but need the exact same guard type
    /// `broadcast_change`'s own private `begin_broadcast` uses internally.
    pub fn begin_write_activity(&self) -> WriteActivityGuard<'_> {
        let liveness = self.block_liveness_gate.begin_reference_write();
        self.active_write_ops.fetch_add(1, Ordering::SeqCst);
        // Every existing call site of this
        // guard (the local-change flush executor started via the daemon's own `LinkRuntimeController`,
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
        self.telemetry.set_task_alive(name, alive);
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
        records: Vec<yadorilink_replica_domain::file::FileRecord>,
    ) {
        if records.is_empty() {
            return;
        }
        self.announce_heads_to_group_peers(group_id).await;
    }

    /// The actual per-session announce loop `broadcast_change` gates on a
    /// non-empty `records` batch -- factored out so a caller that already
    /// knows independently there is something new to announce (the
    /// retroactive conflict-copy repair loop, `engine_wrapper.rs`) can
    /// trigger the same immediate heads announce without needing to first
    /// produce a `FileRecord` for every affected path. That gate is wrong
    /// for the repair loop specifically: it authors a change directly
    /// against the DAG (already durable) and may not yet have the
    /// resulting content materialized locally (`get_file` returns `None`
    /// while blocks are still being fetched), which must not silently
    /// suppress the announce and leave propagation dependent on the next
    /// periodic audit.
    pub(crate) async fn announce_heads_to_group_peers(&self, group_id: &str) {
        let _in_flight = self.begin_broadcast(); // let shutdown wait for this to finish
        for (peer_id, session) in self.peers.all_sessions() {
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

    /// Lazily builds and caches, per group, a `PeerSyncSession` bound to a
    /// `local_session_channel::LoopbackPeerMessageChannel` -- an inert
    /// channel, never a live peer connection -- rather than one drawn from
    /// `self.peers` (`peer_registry::PeerRegistry::sessions_for_group`).
    /// `ConvergenceRetirementService` (`convergence::retirement_service`)
    /// uses this instead of enumerating currently-connected peer sessions
    /// so ephemeral-conflict-copy retirement no longer requires a live
    /// peer to run at all: retirement's own decision (is a copy-shaped
    /// file still justified by the CURRENT frontier?) is driven entirely
    /// by this device's own local DAG/file-index/disk state -- see
    /// `PeerSyncSession::retire_unjustified_ephemeral_conflict_copies`'s
    /// own doc comment -- so which peer object (if any) happens to be
    /// connected was never actually load-bearing for it. Before this, a
    /// solo/newly-linked/currently-offline group's ephemeral conflict
    /// copies could never retire at all: `run_retirement_pass`
    /// (`convergence::engine`) found zero candidate sessions, re-marked
    /// the group dirty, and repeated forever with nothing ever able to
    /// claim it.
    ///
    /// `.run()` is never called on the returned session -- callers use
    /// only its specific per-call methods (`retire_conflict_copies_only`
    /// today), none of which read from or block on the channel for a
    /// purely local tombstone materialize, so
    /// `LoopbackPeerMessageChannel::recv` never resolving is never
    /// observed. `local_device_id` doubles as `peer_device_id` here (this
    /// session never actually talks to a peer named anything else): the
    /// only place that value is visible afterward is the tombstone's
    /// stored `origin_device_id` column (pure display/provenance
    /// metadata -- `yadorilink-cli`'s `version_history` and
    /// `control_socket`'s status API, never a resolver/hazard/conflict
    /// decision input, confirmed by tracing every read site), so
    /// attributing a retirement's tombstone to this device's own id is
    /// strictly more accurate than the previous behavior of attributing
    /// it to whichever connected peer's session happened to be selected
    /// to run the audit.
    pub(crate) fn local_retirement_session(
        self: &Arc<Self>,
        group_id: &str,
    ) -> Arc<yadorilink_peer_session::peer_session::PeerSyncSession> {
        if let Some(existing) = self
            .local_retirement_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_id)
        {
            return existing.clone();
        }
        let group_ids = vec![group_id.to_string()];
        let sync_roots = crate::peer_orchestrator::sync_roots_for_groups(self, &group_ids);
        let dependencies = crate::peer_orchestrator::peer_sync_session_deps(self);
        let session = yadorilink_peer_session::peer_session::PeerSyncSession::new_with_dependencies(
            Arc::new(crate::local_session_channel::LoopbackPeerMessageChannel),
            self.device_id.clone(),
            self.device_id.clone(),
            self.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                self.block_store.clone(),
            )),
            group_ids,
            sync_roots,
            None,
            dependencies,
        );
        self.local_retirement_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), session.clone());
        session
    }
}

/// Bridges an incoming peer-to-peer `HandoffLeaseRequest` (`peer_session.rs`)
/// to this device's own target-side lease machinery
/// ([`DaemonState::request_handoff_lease`]) — installed onto every
/// constructed session via `PeerSyncSession::set_handoff_lease_responder`
/// (`peer_orchestrator.rs`), the same "daemon injects real behavior into a
/// session" shape `PendingLocalChangeFlush for DaemonState` uses
/// (the daemon's own `LinkRuntimeController`). `self.request_handoff_lease(group_id)` below resolves
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
            let session = self.peers.session(target_device_id);
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
    use crate::replica_coordinator::ReplicaCoordinator;
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
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    #[tokio::test]
    async fn custody_stamp_revalidation_rejects_wrong_peer_generation_change_and_demotion() {
        let state = test_state();
        state.set_peer_group_writer("peer-b", "group-a", true);
        state.set_peer_group_full_replica("peer-b", "group-a", true);
        let confirmer = crate::adapters::runtime::custody::P2pCustodyConfirmer::new(&state);
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
        state.links.force_degraded_recheck_due_now(&link_path, now_unix());

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
        state.links.force_degraded_recheck_due_now(&link_path, now_unix());
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
            .replica_coordinator
            .handoff_lease_repository()
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

        let leases = state
            .replica_coordinator
            .handoff_lease_repository()
            .list_handoff_leases_for_group("group-release")
            .unwrap();
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

        let state = test_state();
        let server = MockServer::start().await;
        state.set_coordination_client_config(server.uri(), "test-token".into());

        let sync_state_for_handler = state.replica_coordinator.clone();
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease"))
            .respond_with(move |_req: &Request| {
                let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
                sync_state_for_handler
                    .file_index_repository()
                    .upsert_file_with_origin(
                        "group-1",
                        &FileRecord {
                            path: "b.txt".to_string(),
                            size: 5,
                            mtime_unix_nanos: 0,
                            blocks: vec![],
                            deleted: false,
                        },
                        "device-b",
                        &permit,
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
        let local_leases = state
            .replica_coordinator
            .handoff_lease_repository()
            .list_handoff_leases_for_group("group-1")
            .unwrap();
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
        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
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

        let leases = state
            .replica_coordinator
            .handoff_lease_repository()
            .list_handoff_leases_for_group("group-1")
            .unwrap();
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
        let earliest_deadline = earliest_local_now
            + ttl_seconds
            + yadorilink_sync_sqlite::handoff_lease::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;
        let latest_deadline = latest_local_now
            + ttl_seconds
            + yadorilink_sync_sqlite::handoff_lease::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;
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
            let local_leases = state
                .replica_coordinator
                .handoff_lease_repository()
                .list_handoff_leases_for_group("group-1")
                .unwrap();
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
        let before_restart = ReplicaCoordinator::open(&database_path).unwrap();
        before_restart
            .role_loss_operation_repository()
            .latch_group_durability_unknown("group-1")
            .unwrap();
        drop(before_restart);

        let restarted_store_dir = tempfile::tempdir().unwrap();
        let restarted = DaemonState::new(
            "device-a".into(),
            Arc::new(ReplicaCoordinator::open(&database_path).unwrap()),
            Arc::new(FsBlockStore::new(restarted_store_dir.path()).unwrap()),
        );

        assert_eq!(
            restarted.group_durability_status("group-1"),
            GroupDurabilityStatus::DurabilityUnknown,
            "force history must remain latched after reopening the durable index"
        );
        restarted.clear_group_durability_latch("group-1").unwrap();
        let after_clear = ReplicaCoordinator::open(&database_path).unwrap();
        assert!(after_clear
            .role_loss_operation_repository()
            .list_durability_unknown_latches()
            .unwrap()
            .is_empty());
    }

    // --- Startup-window placeholder-auth race (watcher before policy load) ---
    //
    // `app::run` resumes every already-linked folder's filesystem watcher
    // (the daemon's own `LinkRuntimeController::start`, driven by `sync_state.list_links()`)
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
        use yadorilink_replica_domain::change::{Op, PutOrigin};
        use yadorilink_replica_domain::file::FileMeta;
        use yadorilink_replica_domain::file::RecordKind;
        use yadorilink_replica_domain::ids::SyncPath;
        use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

        let state = test_state();
        let group = "group-1";

        // The group is already linked locally -- exactly the precondition
        // `app::run` checks (`sync_state.list_links()`) before resuming its
        // watcher ahead of the orchestrator. A brand-new group being shared
        // for the first time never reaches this state before its own policy
        // is established, so this precondition is what separates "existing
        // group, not loaded yet" from "genuinely policy-free group".
        state.replica_coordinator.link_repository().add_link("/links/photos", group).unwrap();

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
        let version = yadorilink_replica_domain::file::FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let record = FileRecord {
            path: "note.txt".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let result = state.replica_coordinator.upsert_file_emitting_change(
            group,
            &record,
            "device-a",
            yadorilink_replica_domain::session_state::ChangeContent {
                ops: vec![Op::Put {
                    path: SyncPath("note.txt".into()),
                    version: version.version_hash,
                    origin: PutOrigin::Direct,
                }],
                versions: &[version],
            },
            None,
            crate::replica_coordinator::ReplicaChangeEmission {
                emitter: &emitter,
                permit: &permit,
            },
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
            matches!(result, Err(crate::sync_error::SyncError::PolicyUnavailable)),
            "local emission for an already-linked, policy-not-yet-loaded group must withhold \
             (PolicyUnavailable), not stamp a placeholder-auth change; got {result:?}"
        );
        assert!(
            state.replica_coordinator.sqlite().dag_group_heads(group).unwrap().is_empty(),
            "an already-linked group whose policy state has not loaded yet this run must not get \
             a placeholder-auth change committed to its DAG"
        );
    }
}
