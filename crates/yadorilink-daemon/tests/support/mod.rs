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

use boringtun::x25519::{PublicKey, StaticSecret};
use yadorilink_daemon::change_policy::{verify_group_policy_log, GroupPolicyLog, GroupPolicyState};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{BlockStore, ContentHash, FsBlockStore, GcReport, StorageError};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_transport::{public_key_from_bytes, PeerChannel, TransportHub};

pub mod fake_coordination;

use fake_coordination::FakeCoordination;

/// Wires a daemon into the in-process fake coordination plane for a full-stack
/// orchestrator test: gives it a change-signing key (before its link watch
/// starts, so change emission is on), binds its loopback transport socket, and
/// registers its identity + group membership with the fake so the fake's
/// netmap advertises it to peers. `transport_public` is the device's real
/// WireGuard/transport public key — the same one passed to
/// `peer_orchestrator::run` as its `DeviceKeyPair`'s public bytes — so a peer
/// dialing the endpoint completes the handshake against a matching key.
///
/// Call this before `spawn_orchestrator` and before `link_manager::
/// start_link_watch` for the daemon.
#[allow(dead_code)]
pub async fn register_with_fake(
    fake: &FakeCoordination,
    state: &Arc<DaemonState>,
    device_id: &str,
    transport_public: [u8; 32],
    groups: &[&str],
) {
    let verifying = ensure_device_signing_key(state);
    // Bind the device's shared UDP socket to loopback with its real transport
    // public key installed (so the hub's MAC1 initiation gate is keyed on it),
    // and advertise that socket's address as the device's sole endpoint
    // candidate — mirroring production's `ensure_shared_socket` + endpoint
    // report, but pointed at the in-process fake.
    state.set_device_static_public(transport_public);
    let shared = if let Some(existing) = state.shared_socket() {
        existing
    } else {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let device_public = public_key_from_bytes(&transport_public).ok();
        let shared = TransportHub::from_socket(udp, device_public);
        state.set_shared_socket(shared.clone());
        shared
    };
    fake.register_device(
        device_id,
        transport_public,
        verifying,
        shared.local_addr().to_string(),
        groups,
    );
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

/// A compact daemon-state status summary for E2E timeout diagnostics —
/// the connected peer session ids. Deliberately limited to ids: no file
/// contents, no secret keys/tokens, no raw paths beyond the caller's own
/// test temp roots.
#[allow(dead_code)]
pub fn daemon_status_summary(state: &DaemonState) -> String {
    let session_ids: Vec<String> =
        state.sessions.lock().unwrap_or_else(|p| p.into_inner()).keys().cloned().collect();
    format!("connected_sessions={session_ids:?}")
}

/// Directory entries, excluding two known transient internal artifacts that can
/// briefly coexist with their own already-materialized final state and would
/// otherwise inflate a raw directory-entry count:
/// - the `<name>.yadorilink-tmp.<pid>.<n>` write-then-rename temp used while
///   materializing every received file, and
/// - the `.yl-case-probe-<pid>-<n>` case-fold-collision probe file.
///
/// Multi-device tests syncing into a shared root can race either window with
/// their own directory listing — use this instead of a raw `read_dir` count
/// wherever a test asserts "exactly/at-least N real files".
#[allow(dead_code)]
pub fn real_entry_names(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| {
                    n != yadorilink_sync_core::root_identity::ROOT_MARKER_FILE_NAME
                        && !n.contains(".yadorilink-tmp.")
                        && !n.starts_with(".yl-case-probe-")
                })
                .collect()
        })
        .unwrap_or_default()
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
pub fn open_file_backed_sync_state() -> (SyncState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = SyncState::open(dir.path().join("index.db")).unwrap();
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
/// `link_manager::stop_link_watch` for each device's link) once each
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
    // Direct-pairing tests stand in for the coordination plane, so install the
    // verified empty policy snapshot that plane supplies during a group's
    // bootstrap phase. A linked group is intentionally fail-closed when its
    // policy is absent; merely pinning peer writer keys below is not a policy
    // snapshot and therefore correctly causes local DAG emission to be
    // withheld. The empty verified chain admits PLACEHOLDER-auth bootstrap
    // changes while still exercising the same policy resolver as production.
    install_bootstrap_policies(state_a, shared_group_ids);
    install_bootstrap_policies(state_b, shared_group_ids);

    // One shared UDP socket per device, bound once and reused across every
    // channel that device opens — the production model (the socket lives on
    // DaemonState). In a mesh this is what lets a device's channels to two
    // different peers ride the same socket, demultiplexed by session index.
    let shared_a = device_shared_socket(state_a).await;
    let shared_b = device_shared_socket(state_b).await;
    let addr_a = shared_a.local_addr();
    let addr_b = shared_b.local_addr();
    // `session_index` must be unique per live channel on a device; the number
    // of sessions already established on each side is a monotonic, collision-
    // free choice for the sequential pairing these tests do.
    let index_a = state_a.sessions.lock().unwrap_or_else(|p| p.into_inner()).len() as u32;
    let index_b = state_b.sessions.lock().unwrap_or_else(|p| p.into_inner()).len() as u32;

    // Each side must pin the other's change-signing verifying key so incoming
    // DAG changes verify (the receiver checks every change's signature against
    // the author's pinned key before admitting it). The keys are set on each
    // daemon at setup — before its link watch starts, so change emission is on
    // from the first edit — via `ensure_device_signing_key`.
    let verifying_a = ensure_device_signing_key(state_a);
    let verifying_b = ensure_device_signing_key(state_b);

    let (secret_a, public_a) = gen_transport_keypair();
    let (secret_b, public_b) = gen_transport_keypair();
    let channel_a = Arc::new(
        PeerChannel::connect(secret_a, public_b, index_a, vec![addr_b], shared_a).await.unwrap(),
    );
    let channel_b = Arc::new(
        PeerChannel::connect(secret_b, public_a, index_b, vec![addr_a], shared_b).await.unwrap(),
    );
    let (session_a, handle_a) = spawn_paired_session(
        state_a,
        device_a_id,
        device_b_id,
        channel_a,
        shared_group_ids,
        verifying_b,
    );
    let (session_b, handle_b) = spawn_paired_session(
        state_b,
        device_b_id,
        device_a_id,
        channel_b,
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
        || session_a.change_dag_negotiated() && session_b.change_dag_negotiated(),
        std::time::Duration::from_secs(10),
    )
    .await;

    [handle_a, handle_b]
}

fn install_bootstrap_policies(state: &DaemonState, group_ids: &[String]) {
    let service_key = [1u8; 32];
    let policies: HashMap<String, GroupPolicyState> = group_ids
        .iter()
        .map(|group_id| {
            let log = GroupPolicyLog {
                group_id: group_id.clone(),
                current_seq: 0,
                current_epoch: 0,
                policy_head: vec![0; 32],
                records: Vec::new(),
            };
            let policy = verify_group_policy_log(&service_key, &log)
                .expect("empty bootstrap policy must verify");
            (group_id.clone(), policy)
        })
        .collect();
    state.replace_group_policy_states(policies);
}

/// Ensures `state` has a change-signing key (generating one if absent) and
/// returns its verifying (public) key bytes — the value a peer pins so this
/// device's DAG changes verify. Call this at device setup, before
/// `link_manager::start_link_watch`: the change-DAG emitter is wired from the
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
    // `None` for the device static public key disables the hub's MAC1
    // initiation gate (offer-to-all fallback). These tests use per-channel
    // throwaway transport keypairs with no single device-wide static key, so
    // the gate has nothing to key on — correct and fine over loopback.
    let shared = TransportHub::from_socket(udp, None);
    state.set_shared_socket(shared.clone());
    shared
}

fn gen_transport_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// A live `PeerChannel` with no reachable peer on the far end — sending on it
/// simply queues the datagram (the send half stays open) rather than erroring,
/// so a caller awaiting a reply always times out rather than failing fast.
/// Stands in for a peer that never completes any handshake at all, which is
/// exactly what a session whose `ClusterConfig` negotiation never ran (or ran
/// with an old peer's defaults) looks like from the querying side — useful for
/// exercising a per-peer request's own capability-skip/timeout behavior
/// without standing up a second live daemon.
#[allow(dead_code)]
pub async fn unreachable_channel() -> Arc<PeerChannel> {
    let (secret, _) = gen_transport_keypair();
    let (_, peer_public) = gen_transport_keypair();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let hub = TransportHub::from_socket(udp, None);
    Arc::new(PeerChannel::connect(secret, peer_public, 0, Vec::new(), hub).await.unwrap())
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
fn spawn_paired_session(
    state: &Arc<DaemonState>,
    local_device_id: &str,
    peer_device_id: &str,
    channel: Arc<PeerChannel>,
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
    let session = PeerSyncSession::new_with_forwarding(
        channel,
        local_device_id.to_string(),
        peer_device_id.to_string(),
        state.sync_state.clone(),
        state.block_store.clone(),
        shared_group_ids.to_vec(),
        sync_roots,
        Some(state.forward_tx.clone()),
    );
    session.set_rate_limiters(state.rate_limiters.clone());
    // Integration tests deliberately generate dense concurrent bursts over
    // lossy loopback UDP. Re-announce the DAG frontier at a test cadence so a
    // dropped one-shot HeadsAnnounce is retried within the assertion budget;
    // this is the same anti-entropy mechanism production runs every 90s.
    session.set_full_index_resync_interval(std::time::Duration::from_secs(1));
    if state.disk_headroom_enforcement_enabled() {
        session.set_headroom_enforced(true);
    }
    session.set_pending_local_change_flush(state.clone());
    session.set_change_authenticator(
        yadorilink_daemon::change_auth::NetmapChangeAuthenticator::new(state.clone()),
    );
    // Mirrors production's `peer_orchestrator.rs` wiring so a test pairing
    // built with this helper can answer a peer's `HandoffLeaseRequest`
    // exactly like a real daemon would (subject to `state` itself having
    // coordination-plane config recorded -- see `DaemonState::request_
    // handoff_lease`'s doc comment for when it still declines).
    session.set_handoff_lease_responder(state.clone());
    // Mirrors production's `peer_orchestrator.rs` wiring for the removed-
    // device handoff-ticket flow, the same way as the `HandoffLeaseRequest`
    // wiring just above.
    session.set_handoff_ticket_responder(state.clone());
    state
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(peer_device_id.to_string(), session.clone());
    let peer_id = peer_device_id.to_string();
    let running_session = session.clone();
    let handle = tokio::spawn(async move {
        if let Err(error) = running_session.run().await {
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
    if let Ok(links) = state.sync_state.list_links() {
        for link in links {
            if group_ids.contains(&link.group_id) {
                roots.insert(link.group_id, PathBuf::from(link.local_path));
            }
        }
    }
    roots
}
