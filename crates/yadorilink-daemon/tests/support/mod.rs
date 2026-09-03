//! Shared scaffolding for the daemon's full-stack integration tests.
//!
//! These tests exercise the real vertical no `--lib` unit test reaches: the
//! filesystem watcher → debounce → scan → index pipeline, real encrypted UDP
//! peer transport, the `PeerSyncSession` protocol, and on-disk materialization
//! — two or more in-process daemons converging on a byte-identical file set.
//!
//! The coordination plane itself is a Cloudflare Worker (HTTP/JSON), not an
//! in-process Rust server. Most tests here do not need it at all: peer
//! discovery is stood in for by [`connect_two_daemons`], which pairs two
//! daemons directly over loopback with a `PeerSyncSession` wired exactly as
//! the orchestrator wires a real one. Tests that specifically exercise
//! coordination-driven behavior (revocation propagation, coordination-plane
//! outage) drive the real `peer_orchestrator` against the in-process fake in
//! [`fake_coordination`] instead.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_daemon::change_policy::{verify_group_policy_log, GroupPolicyLog, GroupPolicyState};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{BlockStore, ContentHash, FsBlockStore, GcReport, StorageError};
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};
use yadorilink_transport::{
    connect_role, ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint,
    TransportHub, TransportError,
};

pub mod control_socket_client;
pub mod fake_coordination;
pub mod topology;

use fake_coordination::FakeCoordination;

/// Wires a daemon into the in-process fake coordination plane for a full-stack
/// orchestrator test: gives it a change-signing key (before its link watch
/// starts, so change emission is on), binds its loopback transport socket, and
/// registers its identity + group membership with the fake so the fake's
/// netmap advertises it to peers.
///
/// A device has one key, so what the fake advertises is that key: peers pin
/// it, verify this device's signed changes against it, and authenticate its
/// connections with it.
///
/// Call this before `spawn_orchestrator` and before `LinkRuntimeController::
/// start_link_watch` for the daemon.
#[allow(dead_code)]
pub async fn register_with_fake(
    fake: &FakeCoordination,
    state: &Arc<DaemonState>,
    device_id: &str,
    groups: &[&str],
) {
    // Bind the device's shared UDP socket to loopback and advertise that
    // socket's address as the device's sole endpoint candidate — mirroring
    // production's `ensure_shared_socket` + endpoint report, but pointed at
    // the in-process fake.
    let shared = device_shared_socket(state).await;
    let endpoint = shared.local_addr().to_string();
    register_with_fake_at(fake, state, device_id, groups, endpoint).await;
}

/// Registers a device advertising `endpoint` rather than the address it is
/// actually listening on.
///
/// A test that wants a device to be *unreachable* has to say so at
/// registration, not immediately afterwards. Registering the real address
/// and then replacing it is two netmap pushes, and a peer that reads the
/// first one has a working address in hand: it will connect on it, and the
/// second push cannot take that back, because nothing tears down a
/// connection merely for being on an address the plane has stopped
/// advertising while it still works. The window is small and the race is
/// therefore intermittent, which is worse than a test that simply fails --
/// it makes the scenario silently not the scenario.
///
/// The socket is still bound, so the device is a real device with a real
/// address it could be reached at; the coordination plane just never names
/// it.
#[allow(dead_code)]
pub async fn register_with_fake_at(
    fake: &FakeCoordination,
    state: &Arc<DaemonState>,
    device_id: &str,
    groups: &[&str],
    endpoint: String,
) {
    let verifying = ensure_device_signing_key(state);
    let _ = device_shared_socket(state).await;
    fake.register_device(device_id, verifying, verifying, endpoint, groups);
}

/// Test-isolation fix (found investigating a session-wide daemon-test
/// failure): the daemon's config dir — and with it the peer-key-pinning store
/// (`peer_keys.json`) — falls back to this device's REAL per-user production
/// config directory whenever `YADORILINK_CONFIG_DIR` isn't set. Every test
/// process on a machine then read and wrote the exact same real file;
/// concurrent writers corrupted it into invalid JSON, which made every
/// daemon-level test's netmap-subscription loop fail permanently —
/// indistinguishable from a real product bug until traced to this shared file.
///
/// Fixed once per test *process* (`std::sync::Once`, not per test function —
/// `std::env::set_var` mutates process-wide state, so a fresh value per
/// concurrently-running test function within the same binary would itself
/// race): point every test binary at its own process-local temp directory, so
/// no daemon-level test ever touches real per-user state, and concurrent test
/// processes can never collide on this path.
pub fn ensure_isolated_config_dir() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // Leaked deliberately: this directory must outlive every test in this
        // process, and the process itself tears it down on exit (or the OS
        // reclaims `/tmp`) — there is no natural cleanup point inside the test
        // binary.
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    });
}

// --- Coordination-free membership shims ------------------------------------
//
// The matrix/convergence tests used the in-process coordination server only to
// mint device/group ids and record "authorized" membership; the actual sync in
// those tests is driven entirely by `connect_two_daemons`, which installs write
// authorization directly. These shims preserve the old call shapes so the
// ported tests read almost unchanged, but stand up no server: `register_device`
// and `create_folder_group` just return the requested name as a stable id, and
// grant/login are inert. Orchestrator-style tests (revocation, coordination
// outage) drive the real `peer_orchestrator` against [`fake_coordination`]
// instead and do not use these.

/// A logged-in account handle. In the coordination-free shims it carries only
/// placeholder values; nothing here contacts a server.
#[allow(dead_code)]
pub struct TestAccount {
    pub coordination_addr: String,
    pub access_token: String,
}

/// No server is started; returns a placeholder address the lightweight tests
/// never actually dial (their sync is driven by `connect_two_daemons`).
#[allow(dead_code)]
pub async fn start_coordination_server() -> String {
    ensure_isolated_config_dir();
    "http://127.0.0.1:0".to_string()
}

#[allow(dead_code)]
pub async fn register_and_login(coordination_addr: &str, _email: &str) -> TestAccount {
    TestAccount { coordination_addr: coordination_addr.to_string(), access_token: "test".into() }
}

/// Returns `name` as the device id. The lightweight tests use distinct names
/// per device, and conflict-copy names embed the device id, so a stable,
/// human-readable id keeps assertions readable.
#[allow(dead_code)]
pub async fn register_device(_account: &TestAccount, name: &str, _public_key: [u8; 32]) -> String {
    name.to_string()
}

/// Returns `name` as the group id (stable, no server).
#[allow(dead_code)]
pub async fn create_folder_group(_account: &TestAccount, name: &str) -> String {
    name.to_string()
}

/// Inert: in the direct-pairing model, write authorization is installed by
/// `connect_two_daemons` when the session is spawned, not by a server grant.
#[allow(dead_code)]
pub async fn grant_access(_account: &TestAccount, _group_id: &str, _device_id: &str) {}

#[allow(dead_code)]
pub async fn wait_until<F: Fn() -> bool>(cond: F, timeout: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            panic!("condition never became true within {timeout:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Like `wait_until`, but a timeout panics with a diagnostic summary (elapsed
/// time plus caller-supplied context) instead of the bare "condition never
/// became true" — enough to triage a CI failure without a local re-run.
/// `context` is only invoked on the timeout path.
///
/// Callers' `context` closures must not dump synced file contents, secret
/// keys, or tokens — keep it to counts, temp-root-scoped paths, and status
/// summaries (see `daemon_status_summary`).
#[allow(dead_code)]
pub async fn wait_until_with_context<F, C>(cond: F, timeout: std::time::Duration, context: C)
where
    F: Fn() -> bool,
    C: Fn() -> String,
{
    let started = tokio::time::Instant::now();
    let deadline = started + timeout;
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            panic!(
                "condition never became true within {timeout:?} (elapsed {:?}):\n{}",
                started.elapsed(),
                context()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Like `wait_until_with_context`, but distinguishes a scenario that is
/// genuinely still making forward progress (just slowly, e.g. a heavy
/// multi-device conflict-collision scenario legitimately needing minutes to
/// converge under real disk/CPU contention) from one that has stopped
/// making progress entirely (a deadlock, a livelock, or a retry-amplification
/// loop) -- the two look identical to a single flat deadline, which forces a
/// choice between "generous enough for the slow-but-healthy case" and "tight
/// enough to catch a genuine stall quickly," when what's actually wanted is
/// both at once.
///
/// `progress` is polled alongside `cond` on the same cadence and must return
/// a value that changes whenever the scenario has moved forward at all (a
/// hash/snapshot of accumulated state works well; a monotonic counter is
/// fine too) -- it is *not* required to reach any particular value, only to
/// change while real progress is happening. `stall_timeout` bounds how long
/// `progress`'s value may stay identical before this panics as stalled, reset
/// every time it changes; `absolute_timeout` is the hard overall ceiling
/// regardless of how recently progress last moved, so a scenario that keeps
/// making just-barely-enough progress to dodge the stall check indefinitely
/// still cannot run forever.
#[allow(dead_code)]
pub async fn wait_until_or_stalled<F, Prog, P, C>(
    cond: F,
    mut progress: Prog,
    absolute_timeout: std::time::Duration,
    stall_timeout: std::time::Duration,
    context: C,
) where
    F: Fn() -> bool,
    Prog: FnMut() -> P,
    P: PartialEq,
    C: Fn() -> String,
{
    let started = tokio::time::Instant::now();
    let absolute_deadline = started + absolute_timeout;
    let mut last_progress_value = progress();
    let mut last_progress_at = started;
    while !cond() {
        let now = tokio::time::Instant::now();
        if now > absolute_deadline {
            panic!(
                "condition never became true within the absolute {absolute_timeout:?} deadline \
                 (elapsed {:?}):\n{}",
                started.elapsed(),
                context()
            );
        }
        let current = progress();
        if current != last_progress_value {
            last_progress_value = current;
            last_progress_at = now;
        } else if now.duration_since(last_progress_at) > stall_timeout {
            panic!(
                "convergence stalled: no progress for over {stall_timeout:?} ({:?} elapsed of the \
                 {absolute_timeout:?} absolute budget):\n{}",
                started.elapsed(),
                context()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// A compact daemon-state status summary for E2E timeout diagnostics —
/// the connected peer session ids. Deliberately limited to ids: no file
/// contents, no secret keys/tokens, no raw paths beyond the caller's own
/// test temp roots.
#[allow(dead_code)]
pub fn daemon_status_summary(state: &DaemonState) -> String {
    let session_ids: Vec<String> =
        state.peers.all_sessions().into_iter().map(|(id, _)| id).collect();
    format!("connected_sessions={session_ids:?}")
}

/// Directory entries, excluding two known transient internal artifacts that can
/// briefly coexist with their own already-materialized final state and would
/// otherwise inflate a raw directory-entry count:
/// - the `<name>.yadorilink-tmp.<pid>.<n>` write-then-rename temp used while
///   materializing every received file, and
/// - any reserved-namespace artefact (`.yadorilink-v1-<kind>.<id>`),
///   including the scratch directories the case-fold and normalization
///   filesystem-behaviour probes create and remove.
///
/// Multi-device tests syncing into a shared root can race either window with
/// their own directory listing — use this instead of a raw `read_dir` count
/// wherever a test asserts "exactly/at-least N real files".
#[allow(dead_code)]
pub fn real_entry_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    !yadorilink_root_authority::reserved_namespace::is_reserved_component(
                        e.file_name().as_os_str(),
                    )
                })
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| {
                    n != yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME
                        && n != yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME
                        && !n.contains(".yadorilink-tmp.")
                })
                .collect()
        })
        .unwrap_or_default();
    // `read_dir` yields entries in whatever order the filesystem stores
    // them, which two devices' sync roots need not agree on even when they
    // hold the identical set of files. Callers compare these lists between
    // devices to decide convergence, so without a total order imposed here
    // that comparison can fail on ordering alone -- confirmed: a
    // rename-onto-a-concurrently-created-path scenario timed out for 20s
    // with both devices already holding exactly `target.txt` plus the same
    // one conflict copy, listed the other way round.
    names.sort();
    names
}

/// Opens a `SyncState` the same way production does (`SyncState::open` —
/// file-backed, WAL, `busy_timeout`) on a fresh per-call temp directory,
/// instead of `SyncState::open_in_memory`'s shared-cache `:memory:` backend.
/// Use this for any daemon integration test whose assertion is
/// concurrency/convergence behavior: the shared-cache in-memory backend is the
/// only configuration in this codebase that manufactures `SQLITE_LOCKED`, a
/// lock class `busy_timeout` does not auto-retry and production's WAL+pool path
/// essentially never reaches — a test built on it can fail on a harness
/// artifact indistinguishable from a genuine regression.
///
/// Returns the `SyncState` alongside the `TempDir` guard that owns its backing
/// file; the caller must keep the guard alive for as long as the `SyncState`
/// is in use.
#[allow(dead_code)]
pub fn open_file_backed_replica_coordinator() -> (ReplicaCoordinator, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = ReplicaCoordinator::open(dir.path().join("index.db")).unwrap();
    (state, dir)
}

/// Pairs two in-process daemons directly over loopback, standing in for the
/// coordination-driven peer discovery and connection the orchestrator performs
/// against a live network. Each side binds a UDP socket, dials the other's
/// address as its sole direct candidate, and runs a `PeerSyncSession` wired
/// exactly as the orchestrator wires a real one. The transport keypairs are
/// throwaway: the channel is only an encrypted pipe, and sync identity is the
/// string device id.
///
/// Both devices must already have their link(s) registered (`add_link`) for
/// every group in `shared_group_ids`, so each session can resolve the local
/// root each group materializes into.
#[allow(dead_code)]
pub async fn connect_two_daemons(
    state_a: &Arc<DaemonState>,
    device_a_id: &str,
    state_b: &Arc<DaemonState>,
    device_b_id: &str,
    shared_group_ids: &[String],
) {
    // Discards the session tasks' `JoinHandle`s: every existing caller pairs a
    // fixed, small set of devices once per test process and lets the process
    // exit, so an unbounded `PeerSyncSession::run()` task per pairing is not a
    // leak in practice. A caller that runs many short-lived pairings in a
    // loop -- and so needs to actually bound how much accumulates -- wants
    // `connect_two_daemons_with_handles` instead; see its doc comment.
    let _handles = connect_two_daemons_with_handles(
        state_a,
        device_a_id,
        state_b,
        device_b_id,
        shared_group_ids,
    )
    .await;
}

/// Like [`connect_two_daemons`], but also returns the two spawned
/// `PeerSyncSession::run()` tasks' `JoinHandle`s.
///
/// `spawn_paired_session`'s spawned task holds a *strong* `Arc<PeerSyncSession>`
/// (deliberately -- see its own `resync_handle`'s doc comment on why that
/// inner task holds only a `Weak` one), and through the session, strong
/// references to `DaemonState` (via `set_pending_local_change_flush`/
/// `set_change_authenticator`/etc.), its `SyncState` connection pool, and
/// everything reachable from those. Nothing about `connect_two_daemons`
/// closes the channel or aborts that task, so it runs for the rest of the
/// process. Fine for a test that pairs its (small, fixed) device set once;
/// a test that calls this inside a loop -- pairing a fresh device set per
/// iteration, as `monkey_chaos.rs`'s `replay_known_failing_seeds` does per
/// corpus seed -- leaks a full daemon mesh's worth of tasks, SQLite pools,
/// and periodic timers *per iteration*, with nothing ever torn down between
/// them. Confirmed as the actual cause of a real CI failure: the second of
/// two corpus seeds failed DAG handshake negotiation within its 10s budget,
/// with the first seed's entire 4-device mesh (12 session tasks, their
/// watcher/debounce/executor/repair tasks, and four SQLite pools) still
/// running underneath it and competing for the same process's CPU/disk.
/// A caller in that shape should abort the returned handles (and call
/// `LinkRuntimeController::stop` for each device's link) once each
/// iteration is done -- ideally from an RAII guard, since a panic mid-
/// iteration must still tear the mesh down before the next one starts.
#[allow(dead_code)]
pub async fn connect_two_daemons_with_handles(
    state_a: &Arc<DaemonState>,
    device_a_id: &str,
    state_b: &Arc<DaemonState>,
    device_b_id: &str,
    shared_group_ids: &[String],
) -> [tokio::task::JoinHandle<()>; 2] {
    let (handles, _channels) = connect_two_daemons_with_channels(
        state_a,
        device_a_id,
        state_b,
        device_b_id,
        shared_group_ids,
    )
    .await;
    handles
}

/// Like [`connect_two_daemons_with_handles`], but also returns the two
/// underlying channels so a caller can later drop them to cleanly sever the
/// pairing.
///
/// Dropping a channel is the real disconnect primitive, unlike
/// `JoinHandle::abort()`
/// on the returned session tasks: `PeerSyncSession::run` spawns its own
/// internal child tasks (`resync_handle`/`handshake_retry_handle`/
/// `credit_hint_refresh_handle`), which only get torn down by `run`'s own
/// exit cleanup -- itself only reached once its `recv()` loop observes the
/// channel close. Aborting the outer task skips that cleanup and orphans
/// those child tasks, which keep running and keep re-announcing this
/// device's DAG state to the (still-live) peer channel -- confirmed,
/// reproduced (see `unix_mode_metadata_conflict.rs`'s PR #31 review
/// addendum). Dropping the channel closes the connection, which makes
/// `recv()` return `None`; `run()` already treats that as "the session
/// ended", so its real exit path -- and the child-task cleanup it performs
/// -- runs normally. A caller that needs a clean disconnect -- e.g. to
/// construct a genuine, isolated concurrent-history divergence on a file
/// both devices already share -- should call this instead of
/// [`connect_two_daemons_with_handles`], hold onto the returned channels,
/// and drop both before making any edit meant to be isolated from the
/// peer.
#[allow(dead_code)]
pub async fn connect_two_daemons_with_channels(
    state_a: &Arc<DaemonState>,
    device_a_id: &str,
    state_b: &Arc<DaemonState>,
    device_b_id: &str,
    shared_group_ids: &[String],
) -> ([tokio::task::JoinHandle<()>; 2], [Arc<QuicPeerChannel>; 2]) {
    // Direct-pairing tests stand in for the coordination plane, so install the
    // verified empty policy snapshot that plane supplies during a group's
    // bootstrap phase. A linked group is intentionally fail-closed when its
    // policy is absent; merely pinning peer writer keys below is not a policy
    // snapshot and therefore correctly causes local DAG emission to be
    // withheld. The empty verified chain admits PLACEHOLDER-auth bootstrap
    // changes while still exercising the same policy resolver as production.
    install_bootstrap_policies(state_a, shared_group_ids);
    install_bootstrap_policies(state_b, shared_group_ids);

    // Each side must pin the other's key so incoming DAG changes verify (the
    // receiver checks every change's signature against the author's pinned
    // key before admitting it) -- and the same key authenticates the
    // connection. The keys are set on each daemon at setup, before its link
    // watch starts, via `ensure_device_signing_key`.
    let verifying_a = ensure_device_signing_key(state_a);
    let verifying_b = ensure_device_signing_key(state_b);

    // One shared UDP socket and one QUIC endpoint per device, reused across
    // every peer that device pairs with -- the production model, and what
    // makes a mesh test share one binding per device rather than one per
    // pairing.
    let addr_a = device_shared_socket(state_a).await.local_addr();
    let addr_b = device_shared_socket(state_b).await.local_addr();
    let endpoint_a = device_quic_endpoint(state_a).await;
    let endpoint_b = device_quic_endpoint(state_b).await;
    let (channel_a, channel_b) = connect_quic_pair(
        &endpoint_a,
        device_a_id,
        verifying_a,
        &endpoint_b,
        device_b_id,
        verifying_b,
        addr_b,
        addr_a,
    )
    .await;
    let (session_a, handle_a) = spawn_paired_session(
        state_a,
        device_a_id,
        device_b_id,
        channel_a.clone(),
        shared_group_ids,
        verifying_b,
    );
    let (session_b, handle_b) = spawn_paired_session(
        state_b,
        device_b_id,
        device_a_id,
        channel_b.clone(),
        shared_group_ids,
        verifying_a,
    );

    // `announce_local_commit` deliberately does nothing until the peer has
    // advertised DAG support. Returning before both ClusterConfig handshakes
    // complete lets a test's first write fall into that window; before the
    // legacy index engine was removed its initial FullIndex happened to mask
    // the race, but DAG-only convergence has no such fallback. Production does
    // not expose a session as ready to callers at this seam, so make the direct
    // pairing helper provide the equivalent readiness guarantee explicitly.
    wait_until(
        || session_a.peer_handshake_received() && session_b.peer_handshake_received(),
        std::time::Duration::from_secs(10),
    )
    .await;

    ([handle_a, handle_b], [channel_a, channel_b])
}

/// Installs the empty, verified bootstrap policy snapshot `connect_two_
/// daemons`/`connect_two_daemons_with_handles` normally install as part of
/// pairing two devices. Exposed as its own `pub` entry point (not just a
/// side effect of connecting) so a test that deliberately wants local DAG
/// emission live on a device BEFORE that device is ever connected to a
/// peer -- e.g. to prove two devices produce genuinely independent local
/// `Change`s with no possibility of racing a live wire connection -- can
/// get there without connecting first. Without this, local DAG emission is
/// withheld entirely (a linked group is intentionally fail-closed when its
/// policy is absent — see this function's own body), so an unconnected
/// device's local edits would never be captured at all, not merely slower.
#[allow(dead_code)]
pub fn install_bootstrap_policy(state: &DaemonState, group_ids: &[String]) {
    install_bootstrap_policies(state, group_ids);
}

fn install_bootstrap_policies(state: &DaemonState, group_ids: &[String]) {
    let service_key = [1u8; 32];
    // `replace_group_policy_states` is a wholesale replace (production
    // semantics: a full netmap resync legitimately wants to discard
    // whatever was there before). A test device that connects to more than
    // one peer -- each `connect_two_daemons` call reaching this helper with
    // only THAT pairing's `shared_group_ids` -- must not have an EARLIER
    // pairing's groups silently wiped out by a LATER, narrower call:
    // confirmed, reproduced (`stage2_block_serve_contract.rs`'s
    // `late_small_requests_from_another_peer_and_group_cut_ahead_of_a_
    // large_backlog`): a source connecting to peer-a for [A, B] then to
    // peer-b for [A] lost B's policy the instant the second call ran,
    // withholding group B from every session (including peer-a's) from
    // that point on. Preserve every already-linked group's existing policy
    // (if any) by re-installing it alongside the new ones, rather than
    // starting from an empty map.
    let mut policies: HashMap<String, GroupPolicyState> = state
        .replica_coordinator
        .link_repository()
        .list_links()
        .map(|links| {
            links
                .into_iter()
                .filter_map(|link| {
                    state.group_policy_state(&link.group_id).map(|p| (link.group_id, p))
                })
                .collect()
        })
        .unwrap_or_default();
    for group_id in group_ids {
        let log = GroupPolicyLog {
            group_id: group_id.clone(),
            current_seq: 0,
            current_epoch: 0,
            policy_head: vec![0; 32],
            records: Vec::new(),
        };
        let policy = verify_group_policy_log(&service_key, &log)
            .expect("empty bootstrap policy must verify");
        policies.insert(group_id.clone(), policy);
    }
    state.replace_group_policy_states(policies);
}

/// Ensures `state` has a change-signing key (generating one if absent) and
/// returns its verifying (public) key bytes — the value a peer pins so this
/// device's DAG changes verify. Call this at device setup, before
/// `LinkRuntimeController::start`: the change-DAG emitter is wired from the
/// signing key when the link watch starts, so a key set afterward would leave
/// emission off and nothing would propagate.
#[allow(dead_code)]
pub fn ensure_device_signing_key(state: &Arc<DaemonState>) -> [u8; 32] {
    if let Some(existing) = state.device_signing_key() {
        return existing.verifying_key().to_bytes();
    }
    let keypair = yadorilink_transport::DeviceSigningKeyPair::generate();
    let verifying = keypair.public_bytes();
    state.set_device_signing_key(keypair.signing);
    verifying
}

/// This device's single shared UDP socket, bound (to loopback) and installed on
/// first use and reused thereafter — the test-harness counterpart to
/// production's `DaemonState::ensure_shared_socket`, but bound explicitly to
/// `127.0.0.1` so the address it advertises as a candidate is directly dialable
/// by the other in-process device.
#[allow(dead_code)]
pub async fn device_shared_socket(state: &Arc<DaemonState>) -> Arc<TransportHub> {
    if let Some(existing) = state.shared_socket() {
        return existing;
    }
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let shared = TransportHub::from_socket(udp);
    state.set_shared_socket(shared.clone());
    shared
}

/// A channel whose peer never answers: sends are accepted and go nowhere, and
/// `recv` never resolves.
///
/// It stands in for a peer that is connected as far as this device is
/// concerned but never replies, which is what a per-peer request's own
/// timeout behavior has to be exercised against. Deliberately not a real
/// connection to an unreachable address: under QUIC there is no such thing --
/// a connection either completed a handshake or does not exist -- so
/// modelling "no answer" means modelling the silence, not the socket.
#[allow(dead_code)]
pub struct SilentPeerChannel;

#[async_trait::async_trait]
impl yadorilink_peer_session::ports::PeerMessageChannel for SilentPeerChannel {
    async fn send(&self, _payload: Vec<u8>) -> Result<(), TransportError> {
        Ok(())
    }

    fn try_send(&self, _payload: Vec<u8>) -> bool {
        true
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        std::future::pending().await
    }

    /// Silent on the block plane too: a stream opens (so a requester really
    /// does commit to waiting, which is the point of this double) and then
    /// nothing ever comes back on it.
    async fn open_block_stream(
        &self,
    ) -> Result<Box<dyn yadorilink_peer_session::ports::PeerBlockStream>, TransportError> {
        Ok(Box::new(SilentBlockStream))
    }

    async fn accept_block_stream(
        &self,
    ) -> Option<Box<dyn yadorilink_peer_session::ports::PeerBlockStream>> {
        std::future::pending().await
    }
}

/// The block-plane half of [`SilentPeerChannel`]: writes are accepted and
/// go nowhere, reads never resolve.
#[allow(dead_code)]
pub struct SilentBlockStream;

#[async_trait::async_trait]
impl yadorilink_peer_session::ports::PeerBlockStream for SilentBlockStream {
    async fn send_message(&mut self, _payload: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    async fn recv_message(&mut self, _max_len: usize) -> Result<Vec<u8>, TransportError> {
        std::future::pending().await
    }

    async fn send_body(&mut self, _body: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    async fn recv_body(&mut self, _len: usize) -> Result<Vec<u8>, TransportError> {
        std::future::pending().await
    }

    fn finish_send(&mut self) {}
}

#[allow(dead_code)]
pub async fn unreachable_channel() -> Arc<SilentPeerChannel> {
    Arc::new(SilentPeerChannel)
}

/// One authenticated QUIC connection between two devices' hubs, from
/// whichever side the device-id ordering names as the dialer -- the same rule
/// production uses, so a test pairing exercises the shipped one.
#[allow(dead_code)]
pub async fn connect_quic_pair(
    endpoint_a: &Arc<QuicPeerEndpoint>,
    device_a_id: &str,
    key_a: [u8; 32],
    endpoint_b: &Arc<QuicPeerEndpoint>,
    device_b_id: &str,
    key_b: [u8; 32],
    addr_b: std::net::SocketAddr,
    addr_a: std::net::SocketAddr,
) -> (Arc<QuicPeerChannel>, Arc<QuicPeerChannel>) {
    endpoint_a.authorize(key_b);
    endpoint_b.authorize(key_a);
    let a_role = connect_role(device_a_id, device_b_id);
    let (dialer, dial_addr, dial_key, acceptor, accept_key) = match a_role {
        ConnectRole::Dial => (endpoint_a, addr_b, key_b, endpoint_b, key_a),
        ConnectRole::Accept => (endpoint_b, addr_a, key_a, endpoint_a, key_b),
    };
    let accepting = {
        let acceptor = acceptor.clone();
        tokio::spawn(async move { acceptor.accept(accept_key).await })
    };
    let dialed = dialer.connect(dial_addr, dial_key).await.expect("the pairing dial must succeed");
    let accepted = accepting.await.expect("accept task").expect("a connection must arrive");
    let dialer_channel = QuicPeerChannel::new(dialed, ConnectRole::Dial);
    let acceptor_channel = QuicPeerChannel::new(accepted, ConnectRole::Accept);
    match a_role {
        ConnectRole::Dial => (dialer_channel, acceptor_channel),
        ConnectRole::Accept => (acceptor_channel, dialer_channel),
    }
}

/// This device's QUIC endpoint, built on its shared socket and cached for
/// the rest of the process.
///
/// Keyed by the socket's address rather than kept on `DaemonState`, because
/// only production owns an endpoint there; a test that pairs one device with
/// several peers must reuse the one endpoint, since a hub refuses a second.
#[allow(dead_code)]
pub async fn device_quic_endpoint(state: &Arc<DaemonState>) -> Arc<QuicPeerEndpoint> {
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    static ENDPOINTS: std::sync::OnceLock<
        StdMutex<HashMap<std::net::SocketAddr, Arc<QuicPeerEndpoint>>>,
    > = std::sync::OnceLock::new();

    let hub = device_shared_socket(state).await;
    let addr = hub.local_addr();
    let signing = state
        .device_signing_key()
        .expect("a paired test device must have its signing key installed first");
    let mut endpoints =
        ENDPOINTS.get_or_init(|| StdMutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner());
    endpoints
        .entry(addr)
        .or_insert_with(|| {
            QuicPeerEndpoint::new(
                hub,
                DeviceSigningKeyPair { verifying: signing.verifying_key(), signing },
            )
            .expect("one QUIC endpoint per test device hub")
        })
        .clone()
}

/// A `BlockStore` that delegates everything to a real `FsBlockStore` except
/// `get`, which — on entry, before delegating — fires a one-shot "entered
/// get()" signal (if a receiver is armed) and then sleeps for a fixed `delay`.
/// `holds_version_durably` (the full-replica responder's side of a
/// `VersionPresentQuery`) calls `get` synchronously, with no `.await` in
/// between, to verify a block's checksum before answering — so wrapping a
/// full replica's store with this and installing it as that device's
/// `DaemonState::block_store` gives a test two things: (1) a deterministic
/// ordering signal — awaiting the "entered get()" notification proves the
/// query already reached this device (so the querier has already captured its
/// pre-round-trip epoch) yet the reply has NOT been produced, the exact
/// window in which a mid-flight membership change must be injected; and (2) a
/// `delay` backstop that keeps that window wide even if the signal is not
/// awaited. The signal makes the test independent of wall-clock racing; the
/// delay is belt-and-suspenders.
#[allow(dead_code)]
pub struct DelayedGetBlockStore {
    inner: Arc<FsBlockStore>,
    delay: std::time::Duration,
    entered_get: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<()>>>,
}

#[allow(dead_code)]
impl DelayedGetBlockStore {
    pub fn new(inner: Arc<FsBlockStore>, delay: std::time::Duration) -> Self {
        Self { inner, delay, entered_get: std::sync::Mutex::new(None) }
    }

    /// Arms (or re-arms) the "entered get()" signal and returns the receiver.
    /// The next and every subsequent `get` entry sends a unit on it; the
    /// caller typically awaits the first. Call this AFTER any positive
    /// baseline (whose own `get` calls would otherwise consume the signal),
    /// immediately before the mid-flight scenario it is meant to observe.
    pub fn arm_entered_get_signal(&self) -> tokio::sync::mpsc::UnboundedReceiver<()> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        *self.entered_get.lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
        rx
    }
}

impl BlockStore for DelayedGetBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        if let Some(tx) = self.entered_get.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = tx.send(());
        }
        std::thread::sleep(self.delay);
        self.inner.get(hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.get_unchecked(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn sweep(
        &self,
        live: &std::collections::HashSet<ContentHash>,
        grace_cutoff: std::time::SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }
}

/// Corrupts a block already `put` into an `FsBlockStore` rooted at `root`:
/// overwrites its bytes in place at the documented sharding path
/// (`<root>/<hash[0..2]>/<hash[2..4]>/<hash>`, see `FsBlockStore`'s struct
/// docs) so the file is still present under its content-addressed name but no
/// longer hashes to it — modeling on-disk corruption (bit rot, a torn write)
/// as distinct from a block that was simply never stored. `get`'s mandatory
/// checksum re-verification is what must catch this; a bare existence check
/// would not.
#[allow(dead_code)]
pub fn corrupt_stored_block(root: &std::path::Path, hash_hex: &str) {
    let path = root.join(&hash_hex[0..2]).join(&hash_hex[2..4]).join(hash_hex);
    std::fs::write(&path, b"corrupted bytes that do not hash to this block's name")
        .expect("overwrite previously-`put` block file");
}

/// Constructs and spawns one direction of a paired session. This deliberately
/// duplicates the session wiring in `peer_orchestrator::spawn_peer_session`
/// (forwarding channel, the shared rate-limiter pair, the pending-local-change
/// flush hook, and the netmap-derived write authorization + change
/// authenticator). If that production wiring changes, mirror it here too — a
/// test that pairs sessions differently from production would silently stop
/// exercising the real behavior.
/// `pub` (not just this module's own `connect_two_daemons_with_channels`
/// helper): a process-isolated pairing test needs each side's session wired
/// independently -- there is no single in-process caller that can build both
/// ends' channels and call this once per side the way `connect_two_daemons_
/// with_channels` does.
#[allow(dead_code)]
pub fn spawn_paired_session(
    state: &Arc<DaemonState>,
    local_device_id: &str,
    peer_device_id: &str,
    channel: Arc<QuicPeerChannel>,
    shared_group_ids: &[String],
    peer_verifying_key: [u8; 32],
) -> (Arc<PeerSyncSession>, tokio::task::JoinHandle<()>) {
    // Mirror the netmap-derived authorization the real orchestrator installs
    // (`record_peer_change_authz`): pin the peer's actual change-signing key so
    // its changes' signatures verify, and mark it a writer for every shared
    // group. Without the writer authorization the change authenticator refuses
    // the peer's changes; with no group policy state present it admits a
    // PLACEHOLDER-auth change from a known writer, which is exactly what two
    // coordination-free daemons emit.
    state.record_peer_signing_key(peer_device_id, peer_verifying_key);
    for group_id in shared_group_ids {
        state.set_peer_group_writer(peer_device_id, group_id, true);
    }

    let sync_roots = sync_roots_for_groups(state, shared_group_ids);
    let session = PeerSyncSession::new_with_dependencies(
        channel,
        local_device_id.to_string(),
        peer_device_id.to_string(),
        state.replica_coordinator.clone(),
        std::sync::Arc::new(
            yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            ),
        ),
        shared_group_ids.to_vec(),
        sync_roots,
        Some(state.forward_tx.clone()),
        // Mirrors production's `peer_orchestrator.rs` wiring for these 4
        // one-time capabilities so a test pairing built with this helper
        // answers exactly like a real daemon would: `handoff_lease_
        // responder`/`handoff_ticket_responder` are subject to `state`
        // itself having coordination-plane config recorded (see
        // `DaemonState::request_handoff_lease`'s doc comment for when they
        // still decline).
        PeerSyncSessionDeps {
            pending_local_change_flush: state.clone(),
            change_authenticator: yadorilink_daemon::change_auth::NetmapChangeAuthenticator::new(
                state.clone(),
            ),
            handoff_lease_responder: state.clone(),
            handoff_ticket_responder: state.clone(),
            // Mirrors production's `peer_orchestrator.rs` wiring for this
            // one-time capability too -- `DaemonState` implements
            // `RootCommitAuthorityProvider` directly. Missing this left every
            // caller of this helper on `PeerSyncSessionDeps::standalone()`'s
            // deny-by-default provider, so every unapplied-change projection
            // attempt failed closed with "no live root-commit authority ...
            // no provider injected" forever, no matter how long the test
            // waited -- not a convergence bug, a construction gap in this
            // helper alone.
            root_commit_authority_provider: state.clone(),
            ..PeerSyncSessionDeps::standalone()
        },
    );
    session.set_rate_limiters(state.rate_limiters.clone());
    // Mirrors production's `peer_orchestrator.rs` wiring: without this, a
    // test pairing built with this helper never advertises
    // `supports_block_serve_credit` and always falls back to the legacy
    // `BlockResponse` path, silently never exercising stage 2's
    // credit-gated/coalesced serving at all.
    session.set_block_serve_engine(state.block_serve_engine.clone());
    // Integration tests deliberately generate dense concurrent bursts over
    // lossy loopback UDP. Re-announce the DAG frontier at a test cadence so a
    // dropped one-shot HeadsAnnounce is retried within the assertion budget;
    // this is the same anti-entropy mechanism production runs every 90s.
    session.set_maintenance_reconcile_interval(std::time::Duration::from_secs(1));
    // Same rationale, for the daemon-level (not per-session) materialization-
    // repair backstop (`DaemonState::set_materialization_repair_sweep_
    // interval`): a heavy multi-device test can legitimately run out of
    // organic retry triggers (no new local write, no incoming traffic) for
    // a stretch and have only this periodic sweep left to re-drive a change
    // still unapplied. At production's 90s cadence that shows up as tens of
    // seconds with zero forward progress -- confirmed as a genuine,
    // pre-existing gap (not a deadlock) via `taguchi_collision_matrix.rs`'s
    // stall-detecting convergence wait. Idempotent across every pairing
    // this same device appears in, so setting it again per-pairing is
    // harmless.
    state.set_materialization_repair_sweep_interval(std::time::Duration::from_secs(1));
    if state.disk_headroom_enforcement_enabled() {
        session.set_headroom_enforced(true);
    }
    state.peers.register_session(peer_device_id.to_string(), session.clone());
    let peer_id = peer_device_id.to_string();
    let running_session = session.clone();
    // Kept alive (not moved into `run()`) purely so the exit handler below
    // can `Arc::ptr_eq`-identify this exact session instance afterward.
    let identity_session = session.clone();
    let state_for_task = state.clone();
    let handle = tokio::spawn(async move {
        let result = running_session.run().await;
        // Without this, a session that exits (error or otherwise) leaves a
        // stale entry in `state.peers.sessions` -- anything that later consults
        // that map (e.g. a fresh re-pairing keyed on the same peer id) would
        // see a dead session as if it were live. Guard on `Arc::ptr_eq`
        // rather than unconditionally removing by key: a newer pairing for
        // the same peer may already have replaced this entry by the time
        // this exit handler runs, and removing *that* one would be wrong.
        state_for_task.peers.remove_if_current(&peer_id, &identity_session);
        if let Err(error) = result {
            tracing::error!(%error, peer = %peer_id, "paired peer session exited");
        }
    });
    (session, handle)
}

/// The local materialization root for each of `group_ids`, read from this
/// device's registered links — the same mapping the orchestrator builds for a
/// real session.
fn sync_roots_for_groups(
    state: &Arc<DaemonState>,
    group_ids: &[String],
) -> HashMap<String, PathBuf> {
    let mut roots = HashMap::new();
    if let Ok(links) = state.replica_coordinator.link_repository().list_links() {
        for link in links {
            if group_ids.contains(&link.group_id) {
                roots.insert(link.group_id, PathBuf::from(link.local_path));
            }
        }
    }
    roots
}
