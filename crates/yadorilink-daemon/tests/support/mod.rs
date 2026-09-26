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
use yadorilink_local_storage::{
    BlockStore, ContentHash, GcReport, SegmentBlockStore, StorageError,
};
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};
use yadorilink_transport::{
    connect_role, ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint,
    TransportHub,
};

pub mod control_socket_client;
/// An independent, synchronous model of the change-DAG semantics, used by the
/// Strong Eventual Consistency property suite.
///
/// Here rather than in `dst_support/` because it needs no simulated runtime,
/// and `dst_support` is gated `#![cfg(turmoil)]` for the modules that do.
/// Keeping it here lets the property suite run on every plain `cargo test`.
/// It takes about a second.
// Only `dst_sec_convergence` uses it; every other binary compiles it unused.
#[allow(dead_code)]
pub mod dag_sec;
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
    ensure_no_public_relays();
    let verifying = ensure_device_signing_key(state);
    let _ = device_shared_socket(state).await;
    fake.register_device(device_id, verifying, endpoint, groups);
}

/// Keeps this test process off public relay infrastructure.
///
/// A daemon now starts its reconciliation stack unconditionally, and its
/// default relay configuration is Iroh's own public relays. That is right for
/// production and wrong for a test: a suite whose result depends on reachable
/// third-party servers reports the network's state as often as the code's, and
/// a test that quietly relays through public infrastructure is also telling
/// that infrastructure who is running it.
///
/// A test that needs a relay runs one in-process — see
/// `yadorilink_sync_substrate::testing::InProcessRelay` — and configures it
/// explicitly rather than inheriting one.
///
/// Called from [`ensure_isolated_config_dir`] rather than left to each test,
/// for the same reason that function exists: a hermetic-test property nobody
/// has to remember is the only kind that holds.
pub fn ensure_no_public_relays() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // SAFETY: inside a `Once`, before any test in this process has had a
        // chance to read it -- the same single-shot, process-wide pattern
        // `ensure_isolated_config_dir` itself uses.
        unsafe { std::env::set_var("YADORILINK_SYNC_RELAYS", "none") };
    });
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
    ensure_no_public_relays();
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
    pub auth: yadorilink_fapi_client::CoordinationAuth,
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
    TestAccount {
        coordination_addr: coordination_addr.to_string(),
        auth: yadorilink_fapi_client::test_support::offline_auth(),
    }
}

/// Returns `name` as the device id. The lightweight tests use distinct names
/// per device, and conflict-copy names embed the device id, so a stable,
/// human-readable id keeps assertions readable.
#[allow(dead_code)]
pub async fn register_device(_account: &TestAccount, name: &str, _public_key: [u8; 32]) -> String {
    ensure_fast_convergence_backstops_for_tests();
    name.to_string()
}

/// Sets two process-wide backstop-interval defaults to 1s, once per test
/// process, BEFORE the first `DaemonState`/`ReconciliationDriver` this
/// process constructs.
///
/// Both setters below only take effect on their own task's *next* sleep —
/// see each one's own doc comment — so a caller racing them against
/// `DaemonState::new` (already spawning a materialization-repair task by
/// the time it returns) or `ensure_reconciliation` (already spawning a
/// driver pump by the time it returns) cannot guarantee the override lands
/// before that task's own first read, especially on a multi-threaded
/// runtime where a newly-spawned task can start executing on a different
/// worker thread immediately, no `.await` required. `spawn_paired_session`'s
/// own late, per-instance `state.set_materialization_repair_sweep_
/// interval(1s)` call is exactly this race and cannot substitute for the
/// global default here.
///
/// Investigating `multiway_conflict_matrix.rs`/`directory_conflict_matrix.rs`
/// stalling at ~90s found BOTH gaps stacked: with only the sweep-interval
/// race closed, the sweep ran every second from startup and still never
/// unstalled these tests, because `MaterializationRepairJob::run_once`
/// only re-drives paths this device's OWN index already tracks as
/// materialization candidates — it cannot discover a Change this device
/// never admitted into its DAG at all. The actual gap is one level up, in
/// `sync_adapter::driver`: `SyncStack::sync_with` can complete a round that
/// wants a hash and stages nothing, with no error (see that module's own
/// doc comment for the exact race), and nothing before
/// `RECONCILIATION_BACKSTOP_INTERVAL` existed ever asked that one pairing
/// again once its single wake had fired — organically covered in most
/// tests by literally any later local edit or netmap churn touching either
/// side, which every one of these rows' single-write-then-converge
/// scenarios never provides. `set_default_materialization_repair_sweep_
/// interval_for_tests` (used correctly by `row14_strict_acceptance.rs`/
/// `durability_unobtainable_content.rs`/`monkey_chaos.rs` already) and
/// `sync_adapter::driver::set_default_reconciliation_backstop_interval_
/// for_tests` (new) seed every subsequently-constructed instance's own
/// interval directly, closing both races this file's own
/// `setup_device`/`register_device` ordering could not.
#[allow(dead_code)]
fn ensure_fast_convergence_backstops_for_tests() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        yadorilink_daemon::daemon_state::set_default_materialization_repair_sweep_interval_for_tests(
            std::time::Duration::from_secs(1),
        );
        yadorilink_daemon::sync_adapter::driver::set_default_reconciliation_backstop_interval_for_tests(
            std::time::Duration::from_secs(1),
        );
        // NOT shrinking `engine::REPAIR_FAILOVER_RANK_INTERVAL` here, despite
        // that override existing (added, then deliberately left at its
        // production 5s default, while investigating this exact stall):
        // measured making it materially faster (200ms) rather than fixing
        // the multi-device staggered rows made them WORSE, including
        // regressing `three_devices_staggered` from passing to losing a
        // second device's content outright. The interval's whole job is
        // giving rank 0's single repair attempt time to actually land and
        // propagate before rank 1 also considers itself eligible; shrinking
        // it defeats that on a fast loopback test just as it would in
        // production, producing MORE concurrent racing authors for the same
        // obligation, not faster correct convergence.
    });
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
/// device's DAG state to the (still-live) peer channel. Dropping the channel closes the connection, which makes
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
    // Under checkpoint admission, a Pending Change also needs a real `AuthorizationCheckpoint`
    // to become Published and reach the peer at all -- `checkpoint_fake_for`
    // wires both states to a shared in-process `FakeCoordination` (reused
    // across multiple `connect_two_daemons` calls touching the same device,
    // so a mesh test's later pairing doesn't leave an earlier one's device
    // pointed at a coordination plane that never heard of the new pairing's
    // groups). See `checkpoint_fake_for`'s own doc comment for the case this
    // does NOT safely handle (a mesh bridging two previously-separate pairs)
    // -- use `TestPeerMesh` instead for that shape of test.
    let fake = checkpoint_fake_for(state_a, state_b).await;
    connect_two_daemons_with_shared_fake(
        &fake,
        state_a,
        device_a_id,
        state_b,
        device_b_id,
        shared_group_ids,
    )
    .await
}

/// Shared implementation behind both `connect_two_daemons_with_channels`
/// (which derives `fake` from the process-wide `checkpoint_fake_for`
/// registry) and `TestPeerMesh::connect_with_handles` (which always passes
/// its own single owned fake) -- everything below this point is agnostic to
/// where `fake` came from.
async fn connect_two_daemons_with_shared_fake(
    fake: &FakeCoordination,
    state_a: &Arc<DaemonState>,
    device_a_id: &str,
    state_b: &Arc<DaemonState>,
    device_b_id: &str,
    shared_group_ids: &[String],
) -> ([tokio::task::JoinHandle<()>; 2], [Arc<QuicPeerChannel>; 2]) {
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

    // Direct-pairing tests stand in for the coordination plane, so install the
    // verified empty policy snapshot that plane supplies during a group's
    // bootstrap phase. A linked group is intentionally fail-closed when its
    // policy is absent; merely pinning peer writer keys above is not a policy
    // snapshot and therefore correctly causes local DAG emission to be
    // withheld. The empty verified chain admits PLACEHOLDER-auth bootstrap
    // changes while still exercising the same policy resolver as production.
    // `fake`'s OWN signing key must be the bootstrap policy's declared
    // authority -- otherwise a checkpoint it issues would sign under a key
    // neither device's own verified policy recognizes, and `flush_pending_
    // checkpoint`'s own authority-key check would reject it.
    let service_key: [u8; 32] = fake
        .policy_signing_key()
        .expect("checkpoint_fake_for always enables signed policy")
        .verifying_key()
        .to_bytes();
    fake.register_device(device_a_id, verifying_a, addr_a.to_string(), &[]);
    fake.register_device(device_b_id, verifying_b, addr_b.to_string(), &[]);
    state_a.set_coordination_client_config(
        fake.addr(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    state_b.set_coordination_client_config(
        fake.addr(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    install_bootstrap_policies(state_a, shared_group_ids, service_key);
    install_bootstrap_policies(state_b, shared_group_ids, service_key);
    // Either device may already hold Pending Changes captured BEFORE this
    // pairing ever ran (e.g. a test that deliberately connects two ALREADY-
    // diverged devices) -- `broadcast_change`'s own checkpoint-flush hook
    // only fires on a NEW local mutation, and this lightweight pairing never
    // runs a real `peer_orchestrator::run` netmap loop to provide the OTHER
    // production trigger (reconnect). Flush explicitly here so pre-existing
    // Pending content becomes Published (and so reaches the peer once the
    // session below comes up) instead of staying stuck forever.
    for group_id in shared_group_ids {
        state_a.flush_pending_checkpoint_for_group_for_test(group_id).await;
        state_b.flush_pending_checkpoint_for_group_for_test(group_id).await;
    }
    // Reconciliation is how Changes converge, so a paired device needs its
    // stack up and reachable before anything expects convergence.
    //
    // Stood up here rather than per test because this is the one function
    // every pairing goes through. A test that pairs devices is asking for
    // them to converge; which mechanism does that is not a decision each of
    // ninety test files should be making separately.
    ensure_reconciliation_between(state_a, device_a_id, state_b, device_b_id).await;

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
    let (_session_a, handle_a) = spawn_paired_session(
        state_a,
        device_a_id,
        device_b_id,
        channel_a.clone(),
        shared_group_ids,
        verifying_b,
    );
    let (_session_b, handle_b) = spawn_paired_session(
        state_b,
        device_b_id,
        device_a_id,
        channel_b.clone(),
        shared_group_ids,
        verifying_a,
    );

    ([handle_a, handle_b], [channel_a, channel_b])
}

/// The reconciliation stack for `state`, started if it has none yet.
///
/// Idempotent per device: the driver lives on `DaemonState` and owns the
/// stack, so a device paired many times over a mesh stands up exactly one
/// endpoint -- the production model, and what keeps a six-device mesh from
/// opening fifteen of them.
pub async fn ensure_reconciliation(
    state: &Arc<DaemonState>,
) -> Arc<yadorilink_daemon::sync_adapter::SyncStack> {
    if let Some(driver) = state.reconciliation_driver() {
        return driver.stack().clone();
    }

    let authenticator =
        yadorilink_daemon::change_auth::NetmapChangeAuthenticator::new(state.clone());
    let stack = Arc::new(
        yadorilink_daemon::sync_adapter::SyncStack::spawn(
            state.clone(),
            authenticator,
            yadorilink_sync_substrate::NetworkConfig::direct_only(),
        )
        .await
        .expect("a test device must be able to start its reconciliation stack"),
    );
    state.install_reconciliation_driver(
        yadorilink_daemon::sync_adapter::ReconciliationDriver::start(state.clone(), stack.clone()),
    );
    stack
}

/// Both devices' stacks, each told where the other is.
///
/// The addresses stand in for what an applied netmap push supplies. Nothing
/// else about reachability is arranged: a device that was never told an
/// address cannot dial, exactly as in production.
pub async fn ensure_reconciliation_between(
    state_a: &Arc<DaemonState>,
    device_a_id: &str,
    state_b: &Arc<DaemonState>,
    device_b_id: &str,
) {
    let stack_a = ensure_reconciliation(state_a).await;
    let stack_b = ensure_reconciliation(state_b).await;

    // Into each other's address directory, which is what the substrate asks.
    // See `sync_adapter::address_directory`.
    let _ = (device_a_id, device_b_id);
    let addr_a = stack_a.local_address();
    let addr_b = stack_b.local_address();
    stack_a.address_directory().record(
        addr_b.peer(),
        addr_b.direct_addrs().copied().collect(),
        addr_b.relay_urls().map(ToString::to_string).collect(),
    );
    stack_b.address_directory().record(
        addr_a.peer(),
        addr_a.direct_addrs().copied().collect(),
        addr_a.relay_urls().map(ToString::to_string).collect(),
    );
}

/// Severs the reconciliation link between two paired devices, so a test that
/// simulates a network partition actually partitions.
///
/// Closing the `PeerSyncSession` channels no longer does that on its own.
/// Changes converge over the reconciliation stack, which dials its own iroh
/// endpoint using addresses the netmap supplied — a legacy channel closing
/// tells it nothing. A test that closed channels and then made divergent
/// edits was quietly still converging them, which is worse than failing: it
/// silently stops testing divergence at all.
///
/// Forgetting the peer's addresses is the faithful stand-in. A device with no
/// address for a peer cannot dial it, exactly as in production; nothing is
/// disabled, and re-pairing restores it (`connect_two_daemons` calls
/// `ensure_reconciliation_between` again).
#[allow(dead_code)]
pub async fn sever_reconciliation(state_a: &Arc<DaemonState>, state_b: &Arc<DaemonState>) {
    // Forgetting where the peer's substrate answers, which is what the
    // substrate consults -- see `ensure_reconciliation_between`.
    if let (Some(driver_a), Some(driver_b)) =
        (state_a.reconciliation_driver(), state_b.reconciliation_driver())
    {
        let peer_a = driver_a.stack().local_address().peer();
        let peer_b = driver_b.stack().local_address().peer();
        driver_a.stack().address_directory().record(peer_b, Vec::new(), Vec::new());
        driver_b.stack().address_directory().record(peer_a, Vec::new(), Vec::new());
    }
    // Forgetting the addresses is not enough on its own. iroh keeps its own
    // address book for a node it has already talked to, so a device that has
    // ever reconciled with a peer still reaches it after our record of where
    // it lives is cleared -- measured, not assumed: a test that severed only
    // the addresses still had one device's branch arrive at the other and
    // become its ancestor, so the two "concurrent" branches were never
    // concurrent at all.
    //
    // Dropping the driver drops the stack and with it the endpoint, which is
    // what actually makes the peer unreachable. `connect_two_daemons` builds
    // a fresh one on the way back, at a new address, the way a device
    // returning from a real outage would.
    drop(state_a.take_reconciliation_driver());
    drop(state_b.take_reconciliation_driver());
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
    install_bootstrap_policies(state, group_ids, [1u8; 32]);
}

/// Process-wide registry of which in-process `FakeCoordination` each
/// `connect_two_daemons`-paired `DaemonState` is already wired to, keyed by
/// the `Arc`'s pointer identity. Every `#[tokio::test]` constructs its own
/// fresh `Arc<DaemonState>`s (never reused across tests, and this crate's
/// tests never deallocate one mid-test -- every `TestDaemon`/equivalent
/// fixture is held for the whole test body), so pointer identity is a safe,
/// process-unique key here despite living in a `static`: two concurrently
/// running tests can never collide on the same pointer value while both are
/// still using it, and a stale entry from an already-finished test is
/// simply never looked up again.
static DEVICE_CHECKPOINT_FAKES: std::sync::OnceLock<
    std::sync::Mutex<HashMap<usize, FakeCoordination>>,
> = std::sync::OnceLock::new();

/// Returns the shared `FakeCoordination` either `state_a` or `state_b` is
/// already registered with, or starts and registers a fresh one if neither
/// has one yet.
///
/// This can NOT correctly serve a mesh test that pairs more than two
/// devices with overlapping membership across calls (e.g. A-B, then C-D,
/// then a bridging B-C): once a device's `coordination_client_config` is
/// set it is a `OnceLock` and can never be changed again (see
/// `DaemonState::set_coordination_client_config`'s own doc comment -- this
/// is a real production invariant, not a test-harness shortcut, so it must
/// not be worked around here). That means there is no way to migrate an
/// already-paired device onto a different fake after the fact; a mesh whose
/// devices get lazily assigned fakes pair-by-pair can permanently settle
/// into more than one coordination-authority island, each trusting only its
/// own island's key. A Published Change crossing an island boundary is
/// still delivered over the real P2P session, but verifies against the
/// WRONG authority key and is silently dropped -- indistinguishable, from a
/// test's own diagnostics, from "never received at all". A 6-device,
/// 15-pairing round-robin mesh (as in `row14_strict_acceptance`) would
/// settle into 3 stable 2-device islands.
///
/// A test that pairs more than two devices, where any device is paired more
/// than once, MUST use [`TestPeerMesh`] instead of calling
/// `connect_two_daemons`/`checkpoint_fake_for` directly -- `TestPeerMesh`
/// owns exactly one `FakeCoordination` from construction, so there is only
/// ever one component and no migration is ever needed. This function
/// detects the unsafe case (two already-registered devices found on two
/// different fakes) and panics with that guidance rather than silently
/// producing a split-brain authority.
async fn checkpoint_fake_for(
    state_a: &Arc<DaemonState>,
    state_b: &Arc<DaemonState>,
) -> FakeCoordination {
    let registry = DEVICE_CHECKPOINT_FAKES.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let key_a = Arc::as_ptr(state_a) as usize;
    let key_b = Arc::as_ptr(state_b) as usize;

    let fake_a = registry.lock().unwrap().get(&key_a).cloned();
    let fake_b = registry.lock().unwrap().get(&key_b).cloned();

    let fake = match (fake_a, fake_b) {
        (Some(fa), Some(fb)) => {
            assert_eq!(
                fa.addr(),
                fb.addr(),
                "checkpoint_fake_for: state_a and state_b are already registered with two \
                 DIFFERENT FakeCoordination instances ({} vs {}). This pairing would bridge two \
                 previously-separate islands, which cannot be done safely after the fact -- \
                 DaemonState::coordination_client_config is a OnceLock and cannot be migrated. \
                 Use TestPeerMesh for any test that pairs more than two devices with overlapping \
                 membership across calls.",
                fa.addr(),
                fb.addr(),
            );
            fa
        }
        (Some(fa), None) => fa,
        (None, Some(fb)) => fb,
        (None, None) => {
            let fake = FakeCoordination::start().await;
            fake.enable_signed_policy();
            fake
        }
    };

    let mut map = registry.lock().unwrap();
    map.entry(key_a).or_insert_with(|| fake.clone());
    map.entry(key_b).or_insert_with(|| fake.clone());
    fake
}

/// An explicit, single-authority mesh fixture for a test that pairs more
/// than two devices. Owns exactly one `FakeCoordination`, created once at
/// construction, so every device ever paired through it ends up on the
/// SAME coordination authority regardless of pairing order -- unlike the
/// free-function `connect_two_daemons`/`checkpoint_fake_for` path, which
/// lazily creates a fake per never-before-seen device pair and can settle
/// a mesh into several permanently separate authority islands once a
/// bridging pairing arrives after both sides have already committed their
/// (immutable, `OnceLock`-backed) coordination client config. See
/// `checkpoint_fake_for`'s doc comment for the full explanation.
///
/// Any test pairing 3+ devices, where at least one device is paired more
/// than once (i.e. an actual mesh, not just several independent 2-device
/// pairs in one test body), should use this instead of calling
/// `connect_two_daemons` directly.
#[allow(dead_code)]
pub struct TestPeerMesh {
    fake: FakeCoordination,
}

#[allow(dead_code)]
impl TestPeerMesh {
    pub async fn new() -> Self {
        let fake = FakeCoordination::start().await;
        fake.enable_signed_policy();
        TestPeerMesh { fake }
    }

    /// Pairs two devices onto this mesh's single shared authority --
    /// otherwise identical to [`connect_two_daemons`]. Safe to call
    /// repeatedly with overlapping devices in any order/topology, since
    /// there is only ever this one `FakeCoordination` to converge on.
    pub async fn connect(
        &self,
        state_a: &Arc<DaemonState>,
        device_a_id: &str,
        state_b: &Arc<DaemonState>,
        device_b_id: &str,
        shared_group_ids: &[String],
    ) {
        let _handles = self
            .connect_with_handles(state_a, device_a_id, state_b, device_b_id, shared_group_ids)
            .await;
    }

    /// Like [`Self::connect`], but also returns the two spawned
    /// `PeerSyncSession::run()` tasks' `JoinHandle`s -- see
    /// [`connect_two_daemons_with_handles`]'s doc comment for the same
    /// leak/lifetime caveat.
    pub async fn connect_with_handles(
        &self,
        state_a: &Arc<DaemonState>,
        device_a_id: &str,
        state_b: &Arc<DaemonState>,
        device_b_id: &str,
        shared_group_ids: &[String],
    ) -> [tokio::task::JoinHandle<()>; 2] {
        let (handles, _channels) = connect_two_daemons_with_shared_fake(
            &self.fake,
            state_a,
            device_a_id,
            state_b,
            device_b_id,
            shared_group_ids,
        )
        .await;
        handles
    }
}

/// Delivers every listed device's reconciliation-substrate address to all
/// the others.
///
/// Needed by any fixture that wires its own devices instead of going
/// through `connect_two_daemons`/`support::topology`. The substrate listens
/// on a DIFFERENT socket with a DIFFERENT ALPN than the legacy peer-session
/// transport and publishes its address through `AddressDirectory`.
///
/// Production carries that address over the coordination plane end to end.
/// These fixtures do not, for two reasons that are both on the test side --
/// no endpoint reporter is spawned, and `FakeCoordination`'s netmap has no
/// `substrateReachability` field. `support::topology::
/// advertise_substrate_endpoints` documents both in full, along with why
/// teaching the fake that route is separate work.
///
/// Without this a fixture reaches a registered session -- which is what
/// most of them wait on -- while the plane that actually carries DAG changes
/// has no route at all, and nothing ever converges. Measured in
/// `reconnect_coordinator_scenarios`: a leaf authored a change (`heads=1`)
/// while the hub sat at `heads=0` with no file rows and no obligations for
/// 55+ seconds, both sides reporting a live session.
///
/// Call after the orchestrators start (the substrate has no address before
/// its stack is serving) and before anything waits for convergence.
#[allow(dead_code)]
pub async fn advertise_substrate_between(states: &[&Arc<DaemonState>]) {
    advertise_substrate_over(&DaemonSubstrateDevices(states)).await;
    keep_substrate_advertised(states);
}

/// Keeps every device's substrate address CURRENT in the others'
/// directories, by reacting to changes rather than reading once.
///
/// The barrier above distributes the address each device is serving on at
/// the moment it runs. That address is not final. iroh keeps learning about
/// this endpoint after it binds -- `SubstrateNode::watch_local_address`'s own
/// doc comment says so outright: "The first value may name no relay at all:
/// registration with the home relay completes after the endpoint binds. A
/// publisher must therefore react to changes rather than read once at
/// startup, or a device would advertise 'no relay' for the life of the
/// process and be unreachable to every peer that cannot reach it directly."
///
/// Production does react: that is what the endpoint reporter is for. These
/// fixtures did not, and the gap is not theoretical. Measured in
/// `topology_restart_convergence`: a restarted node was advertised at one
/// port, changed to another about two seconds later, and its peer's
/// directory kept the first one forever. Every later dial went to a socket
/// nothing answers on, with no relay to fall back to and no deadline on the
/// dial, so six block-lane attempts in a row simply never returned and were
/// each cut silently by the caller's own 5s timeout.
///
/// Deliberately NOT a poll, a retry, or a "wait until the address stops
/// changing": an address that changes later is correct behaviour, not a race
/// to be waited out, so the fixture subscribes instead of sampling.
///
/// Watchers hold `Weak` references and stop when the device they serve is
/// dropped, so a restart's old generation is still free to go away. They are
/// registered process-wide rather than returned as a guard: every existing
/// caller becomes reactive without changing its signature, and a test binary
/// is short-lived.
#[allow(dead_code)]
pub fn keep_substrate_advertised(states: &[&Arc<DaemonState>]) {
    static WATCHERS: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>> =
        std::sync::Mutex::new(Vec::new());

    let owned: Vec<Arc<DaemonState>> = states.iter().map(|state| (*state).clone()).collect();
    for (index, source) in owned.iter().enumerate() {
        let Some(driver) = source.reconciliation_driver() else { continue };
        let addresses = driver.stack().watch_local_address();
        let targets: Vec<std::sync::Weak<DaemonState>> = owned
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, state)| Arc::downgrade(state))
            .collect();
        let handle = tokio::spawn(republish_on_change(addresses, move |address| {
            for target in &targets {
                let Some(target) = target.upgrade() else { continue };
                let Some(driver) = target.reconciliation_driver() else { continue };
                driver.stack().address_directory().record(
                    address.0,
                    address.1.clone(),
                    address.2.clone(),
                );
            }
        }));
        WATCHERS.lock().unwrap_or_else(|p| p.into_inner()).push(handle);
    }
}

/// Where a device's substrate is serving: its endpoint identity, its direct
/// socket addresses, and its relay URLs.
#[allow(dead_code)]
pub type SubstrateAddress =
    (yadorilink_sync_substrate::PeerId, Vec<std::net::SocketAddr>, Vec<String>);

/// Everything [`advertise_substrate_over`] needs of a set of devices, and
/// nothing else.
///
/// Extracted so the barrier below can be exercised against devices whose
/// readiness order is chosen by the test rather than by whichever
/// orchestrator runtime happened to finish starting first. Standing up real
/// daemons cannot express "B is still starting when A is already serving" on
/// purpose, so without this seam the ordering contract has no test that can
/// fail for the right reason -- see `substrate_advertisement_barrier.rs`.
#[allow(dead_code)]
pub trait SubstrateDevices {
    fn device_count(&self) -> usize;

    /// `None` until this device's stack is serving an address -- the state a
    /// single-pass distribution skipped and never revisited.
    fn serving_address(&self, index: usize) -> Option<SubstrateAddress>;

    /// Delivers `address` into `target`'s own address directory.
    fn record(&self, target: usize, address: &SubstrateAddress);

    /// Named in the assertion when a device never starts serving.
    fn describe(&self, index: usize) -> String {
        format!("device {index}")
    }
}

/// Delivers every device's substrate address to all the others, whatever
/// order their stacks come up in.
///
/// Two phases, and the barrier between them is the point. A single pass that
/// waits only for the SOURCE and skips a target that is not serving yet
/// silently drops that direction forever: with A's stack up and B's still
/// starting, A->B is skipped, and by the time B is ready only B->A gets
/// recorded. The result is a one-way route decided by orchestrator startup
/// order -- a device that can answer but never ask. Collecting every address
/// behind a barrier first, and only then distributing, makes that
/// unrepresentable.
#[allow(dead_code)]
pub async fn advertise_substrate_over<D: SubstrateDevices + ?Sized>(devices: &D) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let count = devices.device_count();

    let mut addresses = Vec::with_capacity(count);
    for index in 0..count {
        let address = loop {
            if let Some(address) = devices.serving_address(index) {
                break address;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{} never published a reconciliation-substrate address",
                devices.describe(index)
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        addresses.push(address);
    }

    for (source, address) in addresses.iter().enumerate() {
        for target in 0..count {
            // By index, not by identity: passing the same device twice is a
            // caller error, and treating the duplicate as "self" would hide
            // it by silently dropping a direction -- the very failure this
            // barrier exists to remove.
            if source == target {
                continue;
            }
            devices.record(target, address);
        }
    }
}

/// Delivers every address change on `addresses` to `record`, until the
/// publisher goes away.
///
/// The whole of the reactive half, with the delivery injected so it can be
/// exercised without standing up daemons -- see
/// `substrate_advertisement_barrier.rs`.
#[allow(dead_code)]
pub async fn republish_on_change<R>(
    mut addresses: tokio::sync::watch::Receiver<yadorilink_sync_substrate::PeerAddress>,
    record: R,
) where
    R: Fn(&SubstrateAddress),
{
    while addresses.changed().await.is_ok() {
        let update = {
            let address = addresses.borrow_and_update();
            let direct: Vec<std::net::SocketAddr> = address.direct_addrs().copied().collect();
            let relays: Vec<String> = address.relay_urls().map(ToString::to_string).collect();
            (address.peer(), direct, relays)
        };
        // An address naming nowhere is not an update worth distributing:
        // recording it would replace a working entry with one that cannot be
        // dialled.
        if update.1.is_empty() && update.2.is_empty() {
            continue;
        }
        record(&update);
    }
}

/// The real devices: daemons whose substrate address comes from their
/// reconciliation driver's stack.
struct DaemonSubstrateDevices<'a>(&'a [&'a Arc<DaemonState>]);

impl SubstrateDevices for DaemonSubstrateDevices<'_> {
    fn device_count(&self) -> usize {
        self.0.len()
    }

    fn serving_address(&self, index: usize) -> Option<SubstrateAddress> {
        let driver = self.0[index].reconciliation_driver()?;
        let address = driver.stack().local_address();
        let direct: Vec<std::net::SocketAddr> = address.direct_addrs().copied().collect();
        let relays: Vec<String> = address.relay_urls().map(ToString::to_string).collect();
        // A stack that exists but has bound nothing yet is not serving: its
        // address names no route, and recording it would be indistinguishable
        // from never advertising at all.
        (!direct.is_empty() || !relays.is_empty()).then_some((address.peer(), direct, relays))
    }

    fn record(&self, target: usize, (peer, direct, relays): &SubstrateAddress) {
        self.0[target]
            .reconciliation_driver()
            .expect("every device was proven to be serving in the phase above")
            .stack()
            .address_directory()
            .record(*peer, direct.clone(), relays.clone());
    }
}

/// One checkpoint-issuing authority shared by every device in a test.
///
/// `checkpoint_fake_for` deliberately handles exactly two devices and
/// asserts loudly when a pairing would bridge two islands, because
/// `coordination_client_config` is a `OnceLock` that cannot be migrated
/// afterwards. A test with three or more devices therefore has to decide
/// its authority up front rather than discovering it pairwise, which is
/// what this is for: build one fake, point every device at it, and install
/// the same bootstrap policy on all of them.
///
/// Issuing checkpoints is the whole job. No orchestrator, netmap loop or
/// reconciliation stack is started, so a caller that wires its own
/// transport keeps doing exactly that; this only supplies the authority
/// that lets a locally-authored Change reach Published, which
/// block-serving authorization requires.
///
/// Every device must be passed in one call. Registering a device with a
/// second fake later is the island-bridging case above and cannot work.
#[allow(dead_code)]
pub async fn shared_checkpoint_authority(
    devices: &[(&str, &Arc<DaemonState>)],
    group_ids: &[String],
) -> FakeCoordination {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    // The fake's own signing key must be the bootstrap policy's declared
    // authority, or a checkpoint it issues is signed under a key the
    // device's verified policy does not recognise and
    // `flush_pending_checkpoint`'s authority check rejects it.
    let service_key: [u8; 32] = fake
        .policy_signing_key()
        .expect("enable_signed_policy was just called")
        .verifying_key()
        .to_bytes();
    for (device_id, state) in devices {
        let verifying = ensure_device_signing_key(state);
        fake.register_device(device_id, verifying, String::new(), &[]);
        state.set_coordination_client_config(
            fake.addr(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );
        install_bootstrap_policies(state, group_ids, service_key);
    }
    fake
}

fn install_bootstrap_policies(state: &DaemonState, group_ids: &[String], service_key: [u8; 32]) {
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
                    state.authority.group_policy_state(&link.group_id).map(|p| (link.group_id, p))
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
    state.authority.replace_group_policy_states(policies);
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

/// This device's single shared UDP socket for the harness's own control
/// plane, bound (to loopback) on first use and reused thereafter.
///
/// Process-local rather than held on `DaemonState`: production has no
/// shared UDP socket of its own any more -- peer connectivity is the iroh
/// endpoint's, which binds and owns its own -- so this is entirely the
/// harness's, used to pair two devices over an authenticated QUIC
/// connection that is not the sync path.
///
/// Keyed by the `DaemonState` INSTANCE, not by its `device_id`. One test
/// binary runs many tests, and they reuse a small vocabulary of device ids
/// ("device-a", "device-b"): keying by id would hand a second test the
/// first test's hub, whose QUIC endpoint authenticates with the first
/// device's signing key, and every pairing dial would then fail its
/// certificate check. A `Weak` is held rather than an `Arc` so a finished
/// test's state is still dropped, and dead entries are swept on every call
/// so a later state cannot inherit a freed one's address.
#[allow(dead_code)]
pub async fn device_shared_socket(state: &Arc<DaemonState>) -> Arc<TransportHub> {
    use std::sync::{Mutex as StdMutex, Weak};
    type Sockets = StdMutex<Vec<(Weak<DaemonState>, Arc<TransportHub>)>>;
    static SOCKETS: std::sync::OnceLock<Sockets> = std::sync::OnceLock::new();
    let sockets = SOCKETS.get_or_init(|| StdMutex::new(Vec::new()));
    {
        let mut held = sockets.lock().unwrap_or_else(|p| p.into_inner());
        held.retain(|(owner, _)| owner.strong_count() > 0);
        if let Some((_, hub)) = held
            .iter()
            .find(|(owner, _)| owner.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, state)))
        {
            return hub.clone();
        }
    }
    let udp = yadorilink_transport::sim_net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let shared = TransportHub::from_socket(udp);
    let mut held = sockets.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, hub)) = held
        .iter()
        .find(|(owner, _)| owner.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, state)))
    {
        return hub.clone();
    }
    held.push((Arc::downgrade(state), shared.clone()));
    shared
}

/// One authenticated QUIC connection between two devices' hubs, from
/// whichever side the device-id ordering names as the dialer -- the same rule
/// production uses, so a test pairing exercises the shipped one.
#[allow(dead_code)]
// Shared test-support helper; grouping these into a params struct is out
// of scope for a lint cleanup.
#[allow(clippy::too_many_arguments)]
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
    let mut endpoints = ENDPOINTS
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
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

/// A `BlockStore` that delegates everything to a real `SegmentBlockStore` except
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
    inner: Arc<SegmentBlockStore>,
    delay: std::time::Duration,
    entered_get: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<()>>>,
}

#[allow(dead_code)]
impl DelayedGetBlockStore {
    pub fn new(inner: Arc<SegmentBlockStore>, delay: std::time::Duration) -> Self {
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

/// Corrupts a block already `put` into the `SegmentBlockStore` rooted at
/// `root`: overwrites its stored payload in place, leaving the record's own
/// framing and the index mapping intact, so the store still believes it
/// holds the block but its bytes no longer hash to their key — modeling
/// on-disk corruption (bit rot, a torn write) as distinct from a block that
/// was simply never stored. `get`'s mandatory checksum re-verification is
/// what must catch this; a bare existence check would not.
#[allow(dead_code)]
pub fn corrupt_stored_block(root: &std::path::Path, hash_hex: &str) {
    yadorilink_local_storage::segment_store::testing::corrupt_block_payload(
        root,
        hash_hex,
        b"corrupted bytes that do not hash to this block's name",
    )
    .expect("overwrite a previously-`put` block's stored payload");
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
    // This helper's whole precondition (see its own doc comment) is that a
    // caller already brought this device's reconciliation stack up --
    // `connect_two_daemons_with_channels` always calls
    // `ensure_reconciliation_between` first, and every other caller must
    // too. `SessionTransports` is a required `PeerSyncSession` constructor
    // parameter now (mirrors production's own `peer_orchestrator.rs`
    // exactly: a session is never constructed without one), so a caller
    // that skipped that precondition fails loudly here rather than
    // producing a session that looks connected but cannot reach its peer.
    let transports = state.session_transports_for(peer_device_id).expect(
        "spawn_paired_session requires this device's reconciliation stack to already exist -- \
         call ensure_reconciliation/ensure_reconciliation_between first",
    );
    let peer_store = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            state.block_store.clone(),
        ),
    );
    let replica_engine =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &state.replica_coordinator,
            peer_store.clone(),
        );
    let session = PeerSyncSession::over_substrate(
        local_device_id.to_string(),
        peer_device_id.to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        shared_group_ids.to_vec(),
        sync_roots.clone(),
        transports,
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
            // caller of this helper on `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()`'s
            // deny-by-default provider, so every unapplied-change projection
            // attempt failed closed with "no live root-commit authority ...
            // no provider injected" forever, no matter how long the test
            // waited -- not a convergence bug, a construction gap in this
            // helper alone.
            root_commit_authority_provider: state.clone(),
            ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
        },
    );
    session.set_rate_limiters(state.rate_limiters.clone());
    // Mirrors production's `peer_orchestrator.rs` wiring: without this, a
    // test pairing built with this helper never advertises
    // `supports_block_serve_credit` and always falls back to the legacy
    // `BlockResponse` path, silently never exercising stage 2's
    // credit-gated/coalesced serving at all.
    session.set_block_serve_engine(state.block_serve_engine.clone());
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
    state.register_peer_session(peer_device_id, session.clone(), sync_roots);
    if state.disk_headroom_enforcement_enabled() {
        // The knob moved from the session to the executor beside it, so it is
        // set after registration, on the executor that registration built.
        state
            .peers
            .convergence(peer_device_id)
            .expect("sanity: the session was just registered")
            .set_headroom_enforced_for_tests(true);
    }
    let peer_id = peer_device_id.to_string();
    // Kept alive purely so the exit handler below can `Arc::ptr_eq`-identify
    // this exact session instance afterward.
    let identity_session = session.clone();
    let state_for_task = state.clone();
    // The pairing's connection is this session's lifetime token: nothing is
    // exchanged over it, and closing it ends the pairing, the way a test
    // disconnects two devices. The session itself talks only over the
    // reconciliation stack's transports.
    let handle = tokio::spawn(async move {
        while channel.recv().await.is_some() {}
        // Without this, a pairing that ends leaves a stale entry in
        // `state.peers.sessions`. Guard on `Arc::ptr_eq` rather than removing
        // by key: a newer pairing for the same peer may already have replaced
        // this entry, and removing *that* one would be wrong.
        state_for_task.peers.remove_if_current(&peer_id, &identity_session);
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
