use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use boringtun::x25519::{PublicKey, StaticSecret};
use ed25519_dalek::SigningKey;
use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_peer_session::peer_session::{
    BlockWriteActivityProvider, ChangeAuthenticator, PeerSyncSession, PeerSyncSessionDeps,
    RootCommitAuthorityProvider,
};
use yadorilink_peer_session::rate_limiter::RateLimiters;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_transport::PeerChannel;

// Reusable non-madsim change-DAG test support (pinned-key authenticator +
// signed-change producer). Only `pinned_authenticator` is used here; the
// module is `#![allow(dead_code)]` so the unused `DagProducer` is fine.
mod dag_wire_support;
use dag_wire_support::{pinned_authenticator, DagProducer};

const GROUP: &str = "shared-photos";

// Peers connect directly (the relay was removed). This still binds a
// throwaway listener so it hands back a real, unused address and the
// existing call sites keep their shape; `connect_pair` ignores it and wires
// a direct loopback pair instead.
async fn bind_unused_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

struct Device {
    device_id: String,
    root: tempfile::TempDir,
    store: Arc<FsBlockStore>,
    state: Arc<ReplicaCoordinator>,
    // This device's Ed25519 change-signing key. Local edits go through the
    // change DAG (`processor()` wires this as the `ChangeEmitter`), and the
    // peer pins the matching verifying key so it admits the signed changes.
    signing_key: SigningKey,
}

struct BlockingActivityProvider {
    attempted: std::sync::mpsc::SyncSender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockWriteActivityProvider for BlockingActivityProvider {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        self.attempted.send(()).unwrap();
        let (released, wake) = &*self.release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        Box::new(())
    }
}

impl Device {
    fn new(device_id: &str) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        // Deterministic per-id key so the peer can pin the verifying key and a
        // failing run is reproducible.
        let seed: [u8; 32] = sha256_bytes(device_id.as_bytes()).try_into().unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // Link `GROUP` at this device's root, the same way linking the folder
        // would. A session's sync roots are *derived from* the link table in
        // production (`sync_roots_for_groups` reads `list_links`), and the
        // peer-apply path re-reads that table for every write it makes — so a
        // device holding a root with no matching link row is a state the daemon
        // cannot produce, and one the apply path deliberately refuses to write
        // for. Registering it here keeps the fixture's invariant the same as
        // production's; the tests that care about pause/unlink/policy still
        // drive those explicitly on top.
        state
            .link_repository()
            .add_link(&root.path().canonicalize().unwrap().to_string_lossy(), GROUP)
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        // A linked group also owes a completed startup reconciliation before
        // the peer-apply path will admit anything for it: `wait_group_ready`
        // defers a batch for a live link whose startup never registered a gate,
        // on the grounds that the index may be half-built. The daemon's link
        // manager runs that startup for real; these tests have no link manager,
        // so stand in for it and declare the group's startup finished. Without
        // this, a linked fixture device would defer every incoming batch —
        // which is also why an *unlinked* fixture device was admitted here
        // before: no link means no startup is owed.
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        Device {
            device_id: device_id.to_string(),
            root,
            store: Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            state,
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// A `ChangeEmitter` signing as this device. Recreated on demand — its
    /// lamport/parent state lives in the group's DAG in `ReplicaCoordinator`, not in the
    /// emitter, so a fresh instance auto-parents from the current heads.
    fn emitter(&self) -> Arc<ChangeEmitter> {
        Arc::new(ChangeEmitter::new(self.device_id.clone(), self.signing_key.clone()))
    }

    fn processor(&self) -> LocalChangeProcessor {
        LocalChangeProcessor::new(
            self.state.clone(),
            self.store.clone(),
            self.device_id.clone(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(self.emitter())
    }

    /// A signed-change producer over this device's state/store, for scenarios
    /// that need to inject a specific record as a genuine DAG commit rather than
    /// via a real on-disk edit (`commit_create` stores the block and emits a
    /// signed Create, the same primitive the local-change producer drives).
    fn producer(&self) -> DagProducer {
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> = self.store.clone();
        DagProducer::new(self.state.clone(), store, &self.device_id, self.signing_key.clone())
    }

    /// Canonicalized root path. `LocalChangeProcessor::process_event`
    /// canonicalizes its `root` argument internally (real OS watchers
    /// report fully-resolved paths — see its doc comment), so tests that
    /// hand-construct `FsChangeEvent`s must build paths consistently from
    /// an already-canonical root, exactly as a real watcher's paths would be.
    fn root_path(&self) -> std::path::PathBuf {
        self.root.path().canonicalize().unwrap()
    }

    fn sync_roots(&self) -> HashMap<String, std::path::PathBuf> {
        HashMap::from([(GROUP.to_string(), self.root_path())])
    }
}

/// Links `local_path` to [`GROUP`] and takes the group's startup gate through
/// to Ready — the state every live link is in on a real daemon, and therefore
/// the only one a test that expects peer records to apply should set up.
///
/// A daemon never leaves a live link without a gate: `app::run` arms one for
/// every non-orphaned link at boot before any fallible watcher setup, and the
/// `AddLink` control path arms one via `start_link_watch` in the same call that
/// commits the row. Peer apply for a live link with no gate therefore defers —
/// on the change-DAG path and the legacy convergence path alike — so a link set
/// up with a bare `add_link` would silently defer every incoming record for the
/// whole test budget instead of exercising what the test means to check.
fn link_with_completed_startup(state: &ReplicaCoordinator, local_path: &str) {
    state.link_repository().add_link(local_path, GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        std::path::Path::new(local_path),
        GROUP,
        state,
    )
    .unwrap();
    let generation = state.startup_readiness().begin_group_startup(GROUP);
    state.startup_readiness().mark_group_ready(GROUP, generation);
}

async fn connect_pair(_addr: std::net::SocketAddr) -> (Arc<PeerChannel>, Arc<PeerChannel>) {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    // Direct loopback: bind each side's UDP socket and hand the other its
    // address as the sole direct candidate — the same wiring the daemon's
    // peer orchestrator uses, minus the coordination-plane candidate
    // discovery.
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();
    (Arc::new(a), Arc::new(b))
}

/// Completes the exact-generation `ClusterConfig` handshake that
/// `PeerSyncSession::run()`'s `exact_generation_preflight` requires as the
/// very first message exchange, from the perspective of a raw
/// (not-`PeerSyncSession`-wrapped) test peer. Must be called on `channel`
/// after the OTHER side has been `spawn_session()`-started and before
/// `channel` sends (or, for a hand-written fake responder, before it starts
/// waiting to receive) any application message (`BlockRequest`,
/// `BlockReply`, etc.) — otherwise the peer's `run()` task's own
/// `exact_generation_preflight` never sees a `ClusterConfig` come back, so
/// it fails after its bounded retries and `run()` exits silently (the test
/// harness discards the `JoinHandle`), and every subsequent
/// `recv_matching_*`/`fetch_block`/`hydrate_file_with_timeout` call that
/// depends on that peer's message-dispatch loop hangs or times out waiting
/// for a reply that will never come.
///
/// Returns any non-`ClusterConfig` messages received while draining for it,
/// in receipt order, as raw encoded bytes. `PeerSyncSession::run()`'s own
/// `exact_generation_preflight` send is NOT the only thing that can put a
/// message on the wire before this function is called: a caller that spawns
/// this raw-peer task and then immediately calls a session method that
/// sends independent of `run()` (e.g. `fetch_block`/`hydrate_file_with_timeout`,
/// which call `self.send` directly, not gated on the handshake) races that
/// send against `run()`'s own preflight send on the SAME peer — either can
/// reach this side first. A caller doing that must replay the returned
/// messages into its own subsequent processing rather than assume the very
/// first message it ever sees post-handshake is guaranteed fresh.
///
/// `session` must be the `PeerSyncSession` on the OTHER end of `channel`
/// (the one started via `spawn_session`/`spawn_session_without_convergence_
/// driver`) — its `change_dag_negotiated()` flag only flips true once that
/// session's own recv loop has actually processed the second, inner-layer
/// `ClusterConfig` this function sends, which is the direct causal signal
/// that the handshake fully landed (not a fixed sleep guessing at it).
async fn complete_raw_peer_handshake(
    channel: &PeerChannel,
    session: &PeerSyncSession,
) -> Vec<Vec<u8>> {
    // Receive the peer's own ClusterConfig (sent first by
    // exact_generation_preflight) and reply with one that satisfies
    // `PeerSyncSession::validate_exact_peer_config`'s "exact generation"
    // check in full: protocol_version match, all 4 `supports_*` bools true,
    // zstd present in `supported_compression`, and both inflight budgets
    // greater than zero. Any other message received first is buffered and
    // returned rather than asserted away -- see this function's own doc
    // comment for why that race is real.
    let mut buffered = Vec::new();
    loop {
        let bytes = channel.recv().await.expect("channel closed during handshake");
        let message = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        if matches!(message.payload, Some(proto::sync_message::Payload::ClusterConfig(_))) {
            break;
        }
        buffered.push(bytes);
    }

    // `supported_compression` MUST include zstd here: `validate_exact_peer_
    // config`'s "exact generation" check requires it unconditionally, so
    // this outer reply cannot omit it without failing the preflight itself.
    channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                    protocol_version: PeerSyncSession::PROTOCOL_VERSION,
                    supports_reliable_delivery: true,
                    supports_change_dag: true,
                    supports_version_present: true,
                    supports_version_hash_exact: true,
                    supported_compression: vec![proto::Compression::Zstd as i32],
                    max_inflight_requests: 64,
                    max_inflight_bytes: 64 * 1024 * 1024,
                    ..Default::default()
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
    channel.enable_reliable_delivery();

    // The exact-generation exchange above is a separate, outer gate
    // (`PeerSyncSession::run`'s own `exact_generation_preflight`) from the
    // *inner* session's feature negotiation (compression, reliable
    // delivery, version-present/hash-exact — `handle_message`'s
    // `ClusterConfig` arm, driven off `self.inner.clone().run()`'s own
    // `ClusterConfig` it sends once the preflight succeeds). The
    // preflight's `channel.recv()` above already consumed this peer's only
    // `ClusterConfig` on the wire, so the inner layer never saw it and
    // every `record_peer_*_support` flag (e.g. `reliable_delivery_
    // negotiated`) would otherwise stay false. Send a second one so the
    // inner recv loop — now running — processes it too. Deliberately
    // WITHOUT zstd here, unlike the outer reply above: `record_peer_
    // compression_support` is sticky-true-only (never resets a peer back to
    // "does not support compression" once set), and most tests using this
    // helper assert on literal, uncompressed reply bytes -- a test that
    // specifically wants compression negotiated (`compression_negotiated()`
    // == true) must send its own additional zstd-advertising `ClusterConfig`
    // after this call returns.
    channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                    protocol_version: PeerSyncSession::PROTOCOL_VERSION,
                    supports_reliable_delivery: true,
                    supports_change_dag: true,
                    supports_version_present: true,
                    supports_version_hash_exact: true,
                    supported_compression: vec![],
                    max_inflight_requests: 64,
                    max_inflight_bytes: 64 * 1024 * 1024,
                    ..Default::default()
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
    // The inner recv loop processes this second ClusterConfig on a spawned
    // `handle_message` task, asynchronously with respect to this function
    // returning. A caller that immediately sends an application message
    // right after this call needs that task to have actually landed first
    // -- wait on the direct causal evidence that it has
    // (`change_dag_negotiated()` only flips once `session` has processed
    // this exact `ClusterConfig`) instead of a fixed sleep guessing at
    // machine speed, which would just be a fresh instance of the same
    // zero-margin-timeout class of flake this helper exists to avoid
    // elsewhere.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !session.change_dag_negotiated() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("inner ClusterConfig was not processed by the peer session in time");
    buffered
}

fn spawn_session(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> Arc<PeerSyncSession> {
    spawn_session_with_groups(channel, device, peer_device_id, vec![GROUP.to_string()])
}

/// Like `spawn_session`, but with `change_authenticator` explicitly wired at
/// construction instead of defaulting to `DerivedKeyAuthenticator` -- for a
/// test whose subject needs a different authenticator (a fixed pinned key
/// set via `dag_authenticator`/`pinned_authenticator`, a permissive or
/// multi-device stand-in, etc.) than the automatic per-device-id derivation
/// `spawn_session` installs.
fn spawn_session_with_authenticator(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    change_authenticator: Arc<dyn ChangeAuthenticator>,
) -> Arc<PeerSyncSession> {
    spawn_session_configured_ex(
        channel,
        device,
        peer_device_id,
        vec![GROUP.to_string()],
        Some(TEST_RESYNC_INTERVAL),
        true,
        change_authenticator,
        Some(AlwaysValidRootCommitAuthorityProvider::shared()),
    )
}

/// Admits any device whose signing key matches the deterministic per-id key
/// `Device::new` assigns (Sha256(device_id)) — the trust material the daemon
/// would inject from the coordination plane's netmap. Wired automatically by
/// `spawn_session` so a pair admits each other's signed changes over the change
/// DAG without per-test key plumbing.
struct DerivedKeyAuthenticator;

impl ChangeAuthenticator for DerivedKeyAuthenticator {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        let seed: [u8; 32] = sha256_bytes(device_id.as_bytes()).try_into().ok()?;
        Some(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }
    fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
        true
    }
}

/// `PeerSyncSessionDeps::standalone()` wires the deny-by-default provider
/// (mirroring the daemon-facing `PeerSyncSessionOneTimeDeps::denied()`),
/// which makes every real-mutation call (`materialize`, `hydrate_file_with_
/// timeout`, ...) fail fast with "no live root-commit authority" -- correct
/// for a caller that never established a link, wrong for a test standing in
/// for the daemon's real per-link `RootLease` (installed by
/// `yadorilink-daemon`'s `DaemonState` once `start_link_watch` acquires the
/// link's `SyncRootLock`). The crate-internal equivalent
/// (`AlwaysValidRootCommitAuthorityProvider` in `peer_session.rs`) is not
/// part of the crate's public surface, so this integration test binary
/// needs its own -- mirrors `tests/dag_wire_support/mod.rs`'s identically
/// named/shaped provider, duplicated rather than shared because the two are
/// separate integration test binaries.
struct AlwaysValidRootCommitAuthorityProvider {
    lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
}

impl AlwaysValidRootCommitAuthorityProvider {
    fn shared() -> Arc<dyn RootCommitAuthorityProvider> {
        Arc::new(Self {
            lease: Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        })
    }
}

impl RootCommitAuthorityProvider for AlwaysValidRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        Some(self.lease.clone())
    }
}

/// The periodic frontier re-announce cadence used by tests whose subject is not
/// the startup push itself. Production re-announces every 90s; shortening it
/// here means a single dropped startup datagram over loopback UDP cannot stall
/// convergence. It also masks a broken startup announce, which is why it is a
/// deliberate per-session choice rather than a harness-wide constant — see
/// `spawn_session_production_resync`.
const TEST_RESYNC_INTERVAL: Duration = Duration::from_millis(200);

fn spawn_session_with_groups(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
) -> Arc<PeerSyncSession> {
    spawn_session_configured(
        channel,
        device,
        peer_device_id,
        shared_group_ids,
        Some(TEST_RESYNC_INTERVAL),
        Arc::new(DerivedKeyAuthenticator),
    )
}

/// Spawns a session that keeps the *production* periodic-resync default, so the
/// post-negotiation startup heads-announce is the only thing that can deliver a
/// peer's pre-existing files inside a test-length timeout.
///
/// Use this — and no manual `announce_local_commit` — for any test whose subject
/// is the startup push. `spawn_session_with_groups`'s short interval re-drives
/// the frontier every 200ms and would let a completely dead startup announce
/// pass.
fn spawn_session_production_resync(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> Arc<PeerSyncSession> {
    spawn_session_configured(
        channel,
        device,
        peer_device_id,
        vec![GROUP.to_string()],
        None,
        Arc::new(DerivedKeyAuthenticator),
    )
}

/// Fallback poll interval for `spawn_test_convergence_driver` when the wake
/// notification is missed (mirrors the production engine's own event+fallback
/// `tokio::select!` shape in `convergence/engine.rs`).
const TEST_CONVERGENCE_FALLBACK: Duration = Duration::from_millis(100);

/// The production daemon's `ConvergenceEngine` is the only thing that turns an
/// admitted DAG change into on-disk content: `handle_change_batch` now only
/// admits the change and enqueues a `materialization_jobs` row. This harness's
/// sessions have no daemon and thus no engine, so any test that asserts on
/// disk content (not just DAG admission) needs this driver running, or it will
/// hang until its own timeout regardless of how correct the sync logic is.
///
/// Deliberately polls `reconcile_local_materialization_audit` rather than
/// re-deriving the engine's own job-scheduling logic — this harness only
/// needs *some* driver of materialization, not a second implementation of it.
fn spawn_test_convergence_driver(
    session: &Arc<PeerSyncSession>,
    state: Arc<ReplicaCoordinator>,
    group_ids: Vec<String>,
) {
    let weak_session = Arc::downgrade(session);

    tokio::spawn(async move {
        loop {
            let Some(session) = weak_session.upgrade() else {
                return;
            };

            for group_id in &group_ids {
                if let Err(error) =
                    session.clone().reconcile_local_materialization_audit(group_id).await
                {
                    tracing::debug!(
                        %error,
                        %group_id,
                        "test convergence driver deferred materialization"
                    );
                }
            }

            // Drop the strong ref before waiting so the session can still be
            // torn down while this loop sleeps between passes.
            drop(session);

            tokio::select! {
                _ = state.materialization_wake().materialization_wake_notified() => {}
                _ = tokio::time::sleep(TEST_CONVERGENCE_FALLBACK) => {}
            }
        }
    });
}

/// Shared spawn seam: `resync_interval` of `None` leaves the production default
/// in place, `Some(i)` shortens the periodic frontier re-announce to `i`.
fn spawn_session_configured(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
    resync_interval: Option<Duration>,
    change_authenticator: Arc<dyn ChangeAuthenticator>,
) -> Arc<PeerSyncSession> {
    spawn_session_configured_ex(
        channel,
        device,
        peer_device_id,
        shared_group_ids,
        resync_interval,
        true,
        change_authenticator,
        Some(AlwaysValidRootCommitAuthorityProvider::shared()),
    )
}

/// Like `spawn_session_configured`, but skips installing the test-only
/// convergence driver: a hand-written fake responder in a test that answers
/// exactly one `BlockRequest` (to model a specific corrupt/mismatched/bomb
/// reply and assert on the resulting error) can otherwise have that single
/// reply consumed by the driver's own legitimate background repair fetch for
/// the same placeholder, racing the test's own explicit
/// `hydrate_file_with_timeout` call for it. Use this for any test whose
/// subject is hydration's own request/response handling (timeout, corrupt or
/// mismatched bytes, request-id correlation) rather than end-to-end disk
/// convergence.
fn spawn_session_without_convergence_driver(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> Arc<PeerSyncSession> {
    spawn_session_configured_ex(
        channel,
        device,
        peer_device_id,
        vec![GROUP.to_string()],
        Some(TEST_RESYNC_INTERVAL),
        false,
        Arc::new(DerivedKeyAuthenticator),
        None,
    )
}

/// Like `spawn_session_without_convergence_driver`, but wires a permissive
/// `AlwaysValidRootCommitAuthorityProvider` instead of `PeerSyncSessionDeps::
/// standalone()`'s deny-by-default one, so `hydrate_file_with_timeout` (and
/// any other real mutation path) can actually attempt its fetch instead of
/// failing closed before ever sending a `BlockRequest` -- for a test whose
/// fake responder depends on that request actually arriving.
fn spawn_session_without_convergence_driver_with_root_authority(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> Arc<PeerSyncSession> {
    spawn_session_configured_ex(
        channel,
        device,
        peer_device_id,
        vec![GROUP.to_string()],
        Some(TEST_RESYNC_INTERVAL),
        false,
        Arc::new(DerivedKeyAuthenticator),
        Some(AlwaysValidRootCommitAuthorityProvider::shared()),
    )
}

fn spawn_session_with_block_serve_engine(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    block_serve_engine: Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
) -> Arc<PeerSyncSession> {
    let session = PeerSyncSession::new_with_dependencies(
        channel,
        device.device_id.clone(),
        peer_device_id.to_owned(),
        device.state.clone(),
        device.store.clone(),
        vec![GROUP.to_owned()],
        device.sync_roots(),
        None,
        PeerSyncSessionDeps {
            change_authenticator: Arc::new(DerivedKeyAuthenticator),
            root_commit_authority_provider: AlwaysValidRootCommitAuthorityProvider::shared(),
            block_serve_engine,
            full_index_resync_interval: TEST_RESYNC_INTERVAL,
            ..PeerSyncSessionDeps::standalone()
        },
    );
    spawn_test_convergence_driver(&session, device.state.clone(), vec![GROUP.to_owned()]);
    tokio::spawn(session.clone().run());
    session
}

/// Shared spawn seam. `change_authenticator` defaults to
/// `DerivedKeyAuthenticator` at every call site above except
/// `spawn_session_with_authenticator`, which lets a test wire in a
/// different one at construction (this field is no longer settable after
/// the fact -- see `PeerSyncSessionOneTimeDeps`'s doc comment in
/// `yadorilink_peer_session::peer_session_impl`).
#[allow(clippy::too_many_arguments)]
fn spawn_session_configured_ex(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
    resync_interval: Option<Duration>,
    install_convergence_driver: bool,
    change_authenticator: Arc<dyn ChangeAuthenticator>,
    root_commit_authority_provider: Option<Arc<dyn RootCommitAuthorityProvider>>,
) -> Arc<PeerSyncSession> {
    let convergence_groups = shared_group_ids.clone();
    let convergence_state = device.state.clone();

    let mut deps =
        PeerSyncSessionDeps { change_authenticator, ..PeerSyncSessionDeps::standalone() };
    if let Some(provider) = root_commit_authority_provider {
        deps.root_commit_authority_provider = provider;
    }

    // Every spawned pair admits each other's signed changes (deterministic keys,
    // or whatever `change_authenticator` the caller supplied), so a pre-existing
    // file propagates over the DAG via the startup heads-announce exactly as it
    // would with a coordination-plane netmap.
    let session = PeerSyncSession::new_with_dependencies(
        channel,
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone(),
        device.store.clone(),
        shared_group_ids,
        device.sync_roots(),
        None,
        deps,
    );
    // Block serving is no longer optional: every real (`DaemonState`-backed)
    // session always has an engine installed (see
    // `PeerSyncSession::set_block_serve_engine`'s own doc comment), so this
    // harness's own sessions get one too rather than falling into
    // `handle_block_request`'s defensive "no engine installed" fail-closed
    // path on any test that happens to exercise a `BlockRequest`. Generous,
    // effectively unlimited budgets -- these tests aren't about credit
    // exhaustion unless they say so.
    session.set_block_serve_engine(yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1_000,
    ));
    if let Some(interval) = resync_interval {
        session.set_full_index_resync_interval(interval);
    }
    if install_convergence_driver {
        spawn_test_convergence_driver(&session, convergence_state, convergence_groups);
    }
    tokio::spawn(session.clone().run());
    session
}

fn expect_file_changed(outcome: LocalChangeOutcome) -> yadorilink_replica_domain::file::FileRecord {
    match outcome {
        LocalChangeOutcome::FileChanged(record) => record,
        other => panic!("expected FileChanged, got {other:?}"),
    }
}

async fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            panic!("condition never became true within timeout");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A `ChangeAuthenticator` that pins every listed device's verifying key and
/// treats each as a writer — the trust material the daemon injects from the
/// coordination plane's netmap. Wire it onto both sessions of a pair so each
/// admits the other's signed changes.
fn dag_authenticator(devices: &[&Device]) -> Arc<dyn ChangeAuthenticator> {
    let pairs: Vec<(&str, &SigningKey)> =
        devices.iter().map(|d| (d.device_id.as_str(), &d.signing_key)).collect();
    pinned_authenticator(&pairs)
}

/// Waits until both sessions have negotiated the change DAG over the handshake
/// (both advertise support, so this is automatic once the run() loops connect).
async fn wait_dag_negotiated(
    a: &Arc<PeerSyncSession>,
    b: &Arc<PeerSyncSession>,
    timeout: Duration,
) {
    wait_until(|| a.change_dag_negotiated() && b.change_dag_negotiated(), timeout).await;
}

/// Drives `announce_local_commit` (the idempotent HeadsAnnounce the daemon's
/// `broadcast_change` sends for a DAG peer) on a short interval until `cond`
/// holds. A single dropped HeadsAnnounce/ChangeRequest datagram over lossy
/// loopback UDP would otherwise stall convergence until the slow periodic
/// frontier audit; re-announcing is exactly that audit at a test cadence and
/// never changes what the DAG decides.
async fn announce_until<F: Fn() -> bool>(
    session: &Arc<PeerSyncSession>,
    group: &str,
    cond: F,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let _ = session.announce_local_commit(group).await;
        for _ in 0..8 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("condition never became true within timeout");
        }
    }
}

/// Whether `name` is a *final*, fully-materialized conflict-copy filename
/// — i.e. contains "conflicted copy" but is not a transient
/// `unique_tmp_path` artifact (`chunker.rs`, suffixed
/// `.yadorilink-tmp.<pid>.<n>`) that `reconstruct_file`/`write_placeholder`
/// briefly create before their final rename. A plain
/// `.contains("conflicted copy")` check can transiently match that
/// in-progress temp file too (its name is built from the final
/// conflict-copy name plus the tmp suffix), which is a real, if narrow,
/// race window in tests polling directory listings — this filters it out
/// so tests only observe the fully-written final file.
fn is_final_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy") && !name.contains(".yadorilink-tmp.")
}

/// The post-negotiation startup heads-announce must be load-bearing on its own.
/// It is the only mechanism by which a freshly connected peer learns files that
/// already existed before the session started: `announce_local_commit` fires
/// only for a *new* local commit, and the periodic frontier audit is 90s away.
/// Once the change DAG is the sole convergence authority it is the only path
/// for initial sync, so a regression here means every first sync stalls.
///
/// This test therefore keeps the production resync default and never announces
/// by hand. The 30s bound is deliberately well inside the 90s frontier audit,
/// so nothing can rescue a broken startup push: if the announce at the end of
/// config negotiation stops firing, this test fails and nothing else in this
/// file does.
///
/// Do not "stabilize" this test by shortening the resync interval or adding a
/// manual announce loop — either one silently deletes the only coverage of the
/// startup push. If it proves flaky, fix the flake, not the assertion.
#[tokio::test]
async fn startup_heads_announce_alone_replicates_a_pre_existing_file() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Written before either session exists, so no local commit will ever be
    // announced for it — only the startup push can carry it to device-b.
    let file_path = device_a.root_path().join("pre-existing.bin");
    std::fs::write(&file_path, vec![0x5Au8; 200_000]).unwrap(); // spans multiple blocks
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session_production_resync(channel_a, &device_a, "device-b");
    let session_b = spawn_session_production_resync(channel_b, &device_b, "device-a");
    // The startup heads-announce is the ONLY thing that can carry this file:
    // the unconditional startup full index that used to deliver it — and would
    // have let this assertion pass with the heads-announce completely dead — no
    // longer exists, so this test is load-bearing by construction rather than
    // by opting into a boundary switch.
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated = device_b.root_path().join("pre-existing.bin");
    wait_until(|| replicated.exists(), Duration::from_secs(30)).await;

    assert_eq!(
        std::fs::read(&replicated).unwrap(),
        std::fs::read(device_a.root_path().join("pre-existing.bin")).unwrap(),
        "the startup heads-announce must replicate the pre-existing file's content"
    );
}

/// sync-engine spec: "Initial sync reconciles existing files" — device A
/// already has a file before B ever connects; B must end up with an
/// identical copy after the session starts.
#[tokio::test]
async fn initial_sync_replicates_existing_file_to_new_peer() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("vacation.jpg");
    std::fs::write(&file_path, vec![0xABu8; 300_000]).unwrap(); // spans multiple blocks
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // device-a's pre-existing file is already in its DAG (process_event above);
    // the startup heads-announce carries it to device-b once negotiated.
    let replicated_path = device_b.root_path().join("vacation.jpg");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;

    let original = std::fs::read(device_a.root_path().join("vacation.jpg")).unwrap();
    let replicated = std::fs::read(&replicated_path).unwrap();
    assert_eq!(original, replicated);

    let record =
        device_b.state.file_index_repository().get_file(GROUP, "vacation.jpg").unwrap().unwrap();
    assert!(!record.deleted);
    assert_eq!(record.size, 300_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eager_peer_adoption_waits_for_block_deletion_gate_before_index_commit() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let content = b"old orphan block adopted from eager peer";

    let orphan_hash = device_b.store.put(content).unwrap();
    let file_path = device_a.root_path().join("restored.txt");
    std::fs::write(&file_path, content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    // A short periodic heads-announce reliably carries device-a's committed
    // change to device-b over loopback so the eager adoption enters the gate.
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let session_b = PeerSyncSession::new_with_dependencies(
        channel_b,
        device_b.device_id.clone(),
        "device-a".into(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
        None,
        PeerSyncSessionDeps {
            change_authenticator: auth.clone(),
            root_commit_authority_provider: AlwaysValidRootCommitAuthorityProvider::shared(),
            block_write_activity_provider: Arc::new(BlockingActivityProvider {
                attempted: attempted_tx,
                release: release.clone(),
            }),
            ..PeerSyncSessionDeps::standalone()
        },
    );
    spawn_test_convergence_driver(&session_b, device_b.state.clone(), vec![GROUP.to_string()]);
    tokio::spawn(session_b.clone().run());

    tokio::task::spawn_blocking(move || {
        attempted_rx.recv_timeout(Duration::from_secs(10)).expect("eager adoption must enter gate")
    })
    .await
    .unwrap();
    assert!(
        !device_b
            .state
            .materialization_state_repository()
            .live_block_hashes()
            .unwrap()
            .contains(&orphan_hash),
        "eager adoption must not commit its first block reference during physical deletion"
    );

    {
        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    let restored_path = device_b.root_path().join("restored.txt");
    wait_until(|| restored_path.exists(), Duration::from_secs(10)).await;
    assert_eq!(device_b.store.put(content).unwrap(), orphan_hash);
    assert_eq!(std::fs::read(restored_path).unwrap(), content);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ondemand_peer_adoption_waits_for_block_deletion_gate_before_index_commit() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(&root_b, MaterializationPolicy::OnDemand)
        .unwrap();
    let content = b"old orphan block adopted as an on-demand placeholder";

    let orphan_hash = device_b.store.put(content).unwrap();
    let file_path = device_a.root_path().join("ondemand-restored.txt");
    std::fs::write(&file_path, content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    // A short periodic heads-announce reliably carries device-a's committed
    // change to device-b over loopback so the on-demand adoption enters the gate.
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let session_b = PeerSyncSession::new_with_dependencies(
        channel_b,
        device_b.device_id.clone(),
        "device-a".into(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
        None,
        PeerSyncSessionDeps {
            change_authenticator: auth.clone(),
            root_commit_authority_provider: AlwaysValidRootCommitAuthorityProvider::shared(),
            block_write_activity_provider: Arc::new(BlockingActivityProvider {
                attempted: attempted_tx,
                release: release.clone(),
            }),
            ..PeerSyncSessionDeps::standalone()
        },
    );
    spawn_test_convergence_driver(&session_b, device_b.state.clone(), vec![GROUP.to_string()]);
    tokio::spawn(session_b.clone().run());

    tokio::task::spawn_blocking(move || {
        attempted_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("on-demand adoption must enter the reference-write gate")
    })
    .await
    .unwrap();
    assert!(
        !device_b
            .state
            .materialization_state_repository()
            .live_block_hashes()
            .unwrap()
            .contains(&orphan_hash),
        "on-demand adoption must not commit a block reference during physical deletion"
    );

    {
        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    wait_until(
        || {
            device_b
                .state
                .file_index_repository()
                .get_file(GROUP, "ondemand-restored.txt")
                .ok()
                .flatten()
                .is_some()
        },
        Duration::from_secs(10),
    )
    .await;
    let adopted = device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "ondemand-restored.txt")
        .unwrap()
        .unwrap();
    assert!(adopted.blocks.iter().any(|block| hex::encode(&block.hash) == orphan_hash));
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "ondemand-restored.txt")
            .unwrap(),
        Some(MaterializationState::Placeholder)
    );
}

#[tokio::test]
async fn same_version_resync_rehydrates_a_missing_eager_file() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let file_name = "stuck.bin";
    let contents = vec![0x5Au8; 300_000];
    let file_path = device_a.root_path().join(file_name);
    std::fs::write(&file_path, &contents).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    session_b.set_full_index_resync_interval(Duration::from_millis(100));
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join(file_name);
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;

    std::fs::remove_file(&replicated_path).unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            file_name,
            MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        session_b.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        if std::fs::read(&replicated_path).ok().as_deref() == Some(contents.as_slice()) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "repair audit never rehydrated the file");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(std::fs::read(&replicated_path).unwrap(), contents);
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, file_name)
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
}

#[tokio::test]
async fn same_version_resync_does_not_hydrate_an_ondemand_placeholder() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(&root_b, MaterializationPolicy::OnDemand)
        .unwrap();

    let file_name = "ondemand.bin";
    let contents = vec![0xA5u8; 300_000];
    let file_path = device_a.root_path().join(file_name);
    std::fs::write(&file_path, &contents).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    session_b.set_full_index_resync_interval(Duration::from_millis(100));
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join(file_name);
    announce_until(
        &session_a,
        GROUP,
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, file_name)
                .ok()
                .flatten()
                == Some(MaterializationState::Placeholder)
        },
        Duration::from_secs(20),
    )
    .await;

    session_b.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, file_name)
            .unwrap(),
        Some(MaterializationState::Placeholder)
    );
    assert!(replicated_path.exists());
    assert_eq!(std::fs::metadata(&replicated_path).unwrap().len(), contents.len() as u64);
    assert_ne!(std::fs::read(&replicated_path).unwrap(), contents);
}

/// Every link is bidirectional: a never-seen-before incoming peer change
/// is always applied — written to disk and adopted into the local index —
/// with no directional gate that could reject it or record it as
/// divergence. This is the baseline the removed send-only mode used to
/// suppress; it must now always take effect.
#[tokio::test]
async fn bidirectional_link_applies_incoming_change() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let contents = vec![0xABu8; 300_000];
    let file_path = device_a.root_path().join("vacation.jpg");
    std::fs::write(&file_path, &contents).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    announce_until(
        &session_a,
        GROUP,
        || device_b.root_path().join("vacation.jpg").exists(),
        Duration::from_secs(20),
    )
    .await;

    assert!(
        device_b.root_path().join("vacation.jpg").exists(),
        "a bidirectional link must materialize an incoming change to disk"
    );
    assert!(device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "vacation.jpg")
        .unwrap()
        .is_some());
    assert_eq!(std::fs::read(device_b.root_path().join("vacation.jpg")).unwrap(), contents);
}

/// Pause always trumps everything: a paused link never applies an
/// incoming change — this module previously never gated on
/// `paused` at all on the incoming-apply path (only the daemon's
/// local→peer broadcast did). Pause suspends the link entirely; the file
/// is simply not applied while paused.
#[tokio::test]
async fn paused_link_does_not_apply_an_incoming_change() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b.state.link_repository().set_paused(&root_b, true).unwrap();

    let file_path = device_a.root_path().join("vacation.jpg");
    std::fs::write(&file_path, vec![0xABu8; 300_000]).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Announce device-a's change repeatedly; a paused link must drop every
    // HeadsAnnounce/ChangeBatch (handle_heads_announce and handle_change_batch
    // both gate on is_paused_for_group), so nothing ever lands on device-b.
    for _ in 0..5 {
        let _ = session_a.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!device_b.root_path().join("vacation.jpg").exists());
    assert!(device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "vacation.jpg")
        .unwrap()
        .is_none());
}

/// Unlinking a folder detaches it and leaves the user's files alone — the
/// promise the unlink surface makes in as many words. Nothing tears a live peer
/// session down when the link row is deleted (teardown aborts the local watcher
/// task and deletes the row; it holds no reference to a session), so a session
/// that was mid-conversation keeps receiving batches for the group and must
/// refuse them on its own.
///
/// The tombstone is the case that destroys data rather than merely writing
/// unwanted files: an incoming delete runs `remove_file` against a path resolved
/// under the group's root, so a session still holding the detached folder as its
/// root deletes the user's real files inside it.
#[tokio::test]
async fn unlinked_folder_never_lets_a_peer_tombstone_delete_local_files() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.link_repository().add_link(&root_b, GROUP).unwrap();

    // Sync the file across for real first: the session must be live and already
    // applying for this group, otherwise the test could pass for the trivial
    // reason that nothing was ever connected.
    let contents = vec![0xABu8; 300_000];
    let file_path = device_a.root_path().join("vacation.jpg");
    std::fs::write(&file_path, &contents).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let landed = device_b.root_path().join("vacation.jpg");
    announce_until(&session_a, GROUP, || landed.exists(), Duration::from_secs(20)).await;
    assert!(landed.exists(), "precondition: the file must sync while the link is live");

    // The user unlinks. This is the entire local teardown — `session_b` is
    // untouched and stays live, which is exactly the situation under test.
    device_b.state.link_repository().remove_link(&root_b).unwrap();

    // device-a deletes the file and pushes the tombstone at the detached folder.
    std::fs::remove_file(&file_path).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::Removed },
        )
        .await
        .unwrap();
    for _ in 0..5 {
        let _ = session_a.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        landed.exists(),
        "a peer tombstone deleted a file inside a folder the user had unlinked; unlink promises \
         local files are left alone"
    );
    assert_eq!(
        std::fs::read(&landed).unwrap(),
        contents,
        "the unlinked folder's file must be left byte-for-byte alone"
    );
}

/// An existing link's root is the user's folder: it was created when the link
/// was made, so finding it missing when a session starts means something is
/// wrong — most often an external volume whose mountpoint is gone — not that
/// setup is owed. Creating it would rebuild the user's folder as an empty
/// directory on the internal disk, which makes a broken link look healthy, hides
/// the real fault, and lets peer content start filling the boot volume in place
/// of the detached one.
#[tokio::test]
async fn session_construction_never_creates_a_missing_sync_root() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");

    // The shape of an external volume that is not mounted: the link row still
    // names a path, and nothing is there. Re-point the fixture's link at that
    // path rather than adding a second one, so the group has exactly one row.
    let missing_root = device_b.root_path().join("not-mounted");
    device_b.state.link_repository().remove_link(&device_b.root_path().to_string_lossy()).unwrap();
    device_b.state.link_repository().add_link(&missing_root.to_string_lossy(), GROUP).unwrap();
    assert!(!missing_root.exists(), "precondition: the root must start absent");

    let (_channel_a, channel_b) = connect_pair(addr).await;
    let _session = PeerSyncSession::new(
        channel_b,
        device_b.device_id.clone(),
        "device-a".to_string(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), missing_root.clone())]),
    );

    assert!(
        !missing_root.exists(),
        "session construction recreated an existing link's root on the internal disk; a missing \
         root must surface as a fault, not be silently rebuilt"
    );
}

/// The write half of the same guarantee: after an unlink, a peer's *new* file
/// must not appear inside the detached folder either. The link row is the only
/// record that the folder is ours to write into, and it is gone.
#[tokio::test]
async fn unlinked_folder_does_not_apply_an_incoming_peer_change() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.link_repository().add_link(&root_b, GROUP).unwrap();
    device_b.state.link_repository().remove_link(&root_b).unwrap();

    let file_path = device_a.root_path().join("vacation.jpg");
    std::fs::write(&file_path, vec![0xABu8; 300_000]).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    for _ in 0..5 {
        let _ = session_a.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !device_b.root_path().join("vacation.jpg").exists(),
        "a peer change was written into a folder with no link row"
    );
    assert!(device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "vacation.jpg")
        .unwrap()
        .is_none());
}

/// sync-engine spec: "Local file edit detected" + incremental propagation
///  — a change made *after* the initial sync must also reach
/// the peer, sent as an index update rather than a full re-sync.
#[tokio::test]
async fn incremental_change_after_initial_sync_propagates() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(addr).await;
    // Pin each device's signing key on both sessions so B admits A's signed
    // change, then wait for the automatic change-DAG negotiation.
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // A local edit on A: `process_event` emits a signed Create into the DAG.
    let file_path = device_a.root_path().join("notes.txt");
    std::fs::write(&file_path, b"first draft").unwrap();
    let _record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    // Announce A's new commit; the DAG wire loop (HeadsAnnounce ->
    // ChangeRequest -> ChangeBatch) carries it to B, which materializes it.
    let replicated_path = device_b.root_path().join("notes.txt");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;
    assert_eq!(std::fs::read(&replicated_path).unwrap(), b"first draft");
}

/// sync-engine spec: "Concurrent edit produces conflicted copy" — both
/// devices edit the same file before either has seen the other's change;
/// version vectors must detect this as a true conflict (not a simple
/// ordering), and both copies must survive on both devices.
#[tokio::test]
async fn concurrent_edit_produces_conflict_copy_on_both_sides() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Each device independently creates "shared.txt" with different content
    // before either has seen the other — two concurrent root Creates for the
    // same path. The DAG must resolve this as a conflict (by lamport /
    // change-hash, not mtime), preserving both contents on both devices.
    std::fs::write(device_a.root_path().join("shared.txt"), b"edited on A").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent {
                path: device_a.root_path().join("shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();

    std::fs::write(device_b.root_path().join("shared.txt"), b"edited on B, which is longer")
        .unwrap();
    device_b
        .processor()
        .process_event(
            GROUP,
            &device_b.root_path(),
            &FsChangeEvent {
                path: device_b.root_path().join("shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();

    // Sanity check: this really is a concurrent edit, not a sequential one —
    // neither device's version vector dominates the other's.
    // Causality is DAG ancestry now: the two edits are concurrent exactly when
    // each device authored its own change for the path and neither has yet
    // admitted the other's, so neither can be the other's ancestor.
    let author_a = device_a
        .state
        .file_index_repository()
        .get_authoring_change_hash(GROUP, "shared.txt")
        .unwrap()
        .expect("A authored");
    let author_b = device_b
        .state
        .file_index_repository()
        .get_authoring_change_hash(GROUP, "shared.txt")
        .unwrap()
        .expect("B authored");
    assert_ne!(author_a, author_b, "the two devices must have authored distinct changes");
    assert!(
        device_a.state.sqlite().dag_get_change(&author_b).unwrap().is_none(),
        "A must not yet know B's change"
    );
    assert!(
        device_b.state.sqlite().dag_get_change(&author_a).unwrap().is_none(),
        "B must not yet know A's change"
    );

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Both devices should end up with two files: the winning content at
    // "shared.txt" and a conflict-marked copy of the losing content. Both sides
    // announce their concurrent commit (re-driven until settled), and the wait
    // is specifically for a *final* conflict-copy name (not just "2 entries
    // exist"), which a transient `unique_tmp_path` artifact could satisfy too —
    // see `is_final_conflict_copy`'s doc comment.
    let both_have_final_conflict_copy = || {
        let has_copy = |root: std::path::PathBuf| {
            std::fs::read_dir(root)
                .unwrap()
                .any(|e| is_final_conflict_copy(&e.unwrap().file_name().to_string_lossy()))
        };
        has_copy(device_a.root_path()) && has_copy(device_b.root_path())
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while !both_have_final_conflict_copy() && tokio::time::Instant::now() < deadline {
        let _ = session_a.announce_local_commit(GROUP).await;
        let _ = session_b.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        both_have_final_conflict_copy(),
        "both devices must converge to a winner plus a final conflict copy"
    );

    for device in [&device_a, &device_b] {
        let names: Vec<String> = std::fs::read_dir(device.root_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"shared.txt".to_string()), "missing winner file: {names:?}");
        assert!(
            names.iter().any(|n| is_final_conflict_copy(n)),
            "missing conflict copy: {names:?}"
        );
    }
}

/// (guards ): a delete-vs-edit
/// conflict where the tombstone is the *loser* must never leave an empty
/// ghost file behind, and disk state must match the index exactly — only
/// the winner's real content, at the original path, no conflict-copy
/// file for the tombstone (fix: `resolve_and_apply_conflict`
/// skips creating a conflict copy for a tombstone loser entirely, since
/// "conflict copy of a deletion" has no content to preserve).
#[tokio::test]
async fn delete_vs_edit_conflict_tombstone_as_loser_leaves_no_ghost_file() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_a = device_a.root_path().to_string_lossy().to_string();
    let root_b = device_b.root_path().to_string_lossy().to_string();
    // Register both roots as links so the partition below (set_paused) applies.
    link_with_completed_startup(&device_a.state, &root_a);
    link_with_completed_startup(&device_b.state, &root_b);

    // A common base for shared.txt, created on A and delivered to B over the DAG.
    std::fs::write(device_a.root_path().join("shared.txt"), b"base content").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent {
                path: device_a.root_path().join("shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    announce_until(
        &session_a,
        GROUP,
        || device_b.root_path().join("shared.txt").exists(),
        Duration::from_secs(20),
    )
    .await;

    // Partition the link so the divergent edit and tombstone are genuinely
    // concurrent (neither device applies the other's change while diverging).
    device_a.state.link_repository().set_paused(&root_a, true).unwrap();
    device_b.state.link_repository().set_paused(&root_b, true).unwrap();

    // device_a wins: two successive edits raise its lamport clock above
    // device_b's single tombstone, so the DAG — which resolves by
    // (lamport, change-hash), not mtime — picks the edit.
    let content_a: &[u8] = b"edited on A after the delete";
    std::fs::write(device_a.root_path().join("shared.txt"), b"first edit on A").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent {
                path: device_a.root_path().join("shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();
    std::fs::write(device_a.root_path().join("shared.txt"), content_a).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent {
                path: device_a.root_path().join("shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();

    // device_b loses: a single tombstone descending the base.
    std::fs::remove_file(device_b.root_path().join("shared.txt")).unwrap();
    device_b
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "shared.txt",
            "device-b",
            1000,
            &device_b.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Reconnect the link and let the concurrent changes cross and resolve.
    device_a.state.link_repository().set_paused(&root_a, false).unwrap();
    device_b.state.link_repository().set_paused(&root_b, false).unwrap();

    // The edit wins on both devices: converge to content_a with no ghost and no
    // conflict copy for the tombstone loser (a deletion has no content to keep).
    let converged = || {
        [&device_a, &device_b].iter().all(|d| {
            std::fs::read(d.root_path().join("shared.txt")).ok().as_deref() == Some(content_a)
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while !converged() && tokio::time::Instant::now() < deadline {
        let _ = session_a.announce_local_commit(GROUP).await;
        let _ = session_b.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(converged(), "both devices must converge to the winning edit's content");
    // Let any (incorrect) conflict-copy write settle before asserting its absence.
    tokio::time::sleep(Duration::from_millis(200)).await;

    for device in [&device_a, &device_b] {
        let entries: Vec<String> = std::fs::read_dir(device.root_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| name != yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME)
            .collect();
        assert_eq!(entries, vec!["shared.txt".to_string()], "unexpected extra file: {entries:?}");
        assert_eq!(
            std::fs::read(device.root_path().join("shared.txt")).unwrap(),
            content_a,
            "disk content must match the winner's real content, not an empty ghost file"
        );
        let record =
            device.state.file_index_repository().get_file(GROUP, "shared.txt").unwrap().unwrap();
        assert!(!record.deleted);
        assert_eq!(record.size, content_a.len() as u64);
    }
}

/// Security regression test: a session must ignore index/block messages
/// for a folder group it wasn't constructed with (the ACL-verified
/// intersection from the coordination plane), even if a peer sends them —
/// a peer naming an unrelated group_id in a message must not be able to
/// read or write files outside what it's actually authorized to share.
#[tokio::test]
async fn unauthorized_group_id_in_incoming_message_is_ignored() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("private.txt");
    std::fs::write(&file_path, b"not for device-b").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    // A still thinks it shares GROUP with B (e.g. a stale/incorrect local
    // assumption); B's session was constructed with an *empty* shared-group
    // list, simulating "the coordination plane's ACL does not actually
    // authorize this pairing for GROUP."
    let _session_a =
        spawn_session_with_groups(channel_a, &device_a, "device-b", vec![GROUP.to_string()]);
    let _session_b = spawn_session_with_groups(channel_b, &device_b, "device-a", vec![]);

    // Give plenty of time for A's full index send to arrive and (if the
    // guard were missing) be materialized.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(
        !device_b.root_path().join("private.txt").exists(),
        "file for an unauthorized group must never be written to disk"
    );
    assert!(device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "private.txt")
        .unwrap()
        .is_none());
}

/// spec "OnDemand folder creates placeholders
/// instead of full content": adopting a file into an `OnDemand`-policy
/// folder must index it and write a correctly-sized placeholder — without
/// ever fetching its blocks from the peer.
#[tokio::test]
async fn ondemand_folder_adopts_placeholder_without_fetching_blocks() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Device B links the folder group as `OnDemand` — this is what
    // `PeerSyncSession::materialize` consults to decide placeholder vs.
    // full hydration (the design).
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let file_path = device_a.root_path().join("big-video.mp4");
    let content = vec![0x42u8; 300_000]; // spans multiple blocks
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let placeholder_path = device_b.root_path().join("big-video.mp4");
    wait_until(|| placeholder_path.exists(), Duration::from_secs(10)).await;

    // Correct size (so the file manager shows accurate metadata) but no
    // real content — a sparse placeholder, not the actual video bytes.
    let metadata = std::fs::metadata(&placeholder_path).unwrap();
    assert_eq!(metadata.len(), 300_000);
    let on_disk = std::fs::read(&placeholder_path).unwrap();
    assert_ne!(on_disk, content, "placeholder must not contain the real content");

    let record =
        device_b.state.file_index_repository().get_file(GROUP, "big-video.mp4").unwrap().unwrap();
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "big-video.mp4")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
    assert_eq!(record.size, 300_000);
    assert!(!record.blocks.is_empty(), "the block list is still recorded, just not fetched");

    // The whole point: device B's block store must be empty for this
    // file's blocks — no network fetch happened at all.
    for block in &record.blocks {
        let hash_hex = hex::encode(&block.hash);
        assert!(
            !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &hash_hex)
                .unwrap(),
            "OnDemand adoption must not fetch blocks"
        );
    }
}

/// spec "Opening a placeholder triggers
/// hydration": `PeerSyncSession::hydrate_file` must fetch a placeholder's
/// blocks on demand and materialize its real content, transitioning to
/// `Hydrated` — the on-access path, independent of ordinary index
/// reconciliation.
#[tokio::test]
async fn hydrate_file_fetches_and_materializes_placeholder_content() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let content = vec![0x77u8; 300_000];
    let file_path = device_a.root_path().join("report.pdf");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let placeholder_path = device_b.root_path().join("report.pdf");
    wait_until(|| placeholder_path.exists(), Duration::from_secs(10)).await;
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "report.pdf")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );

    session_b.hydrate_file(GROUP, "report.pdf").await.unwrap();

    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "report.pdf")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(&placeholder_path).unwrap(), content);

    let record =
        device_b.state.file_index_repository().get_file(GROUP, "report.pdf").unwrap().unwrap();
    for block in &record.blocks {
        let hash_hex = hex::encode(&block.hash);
        assert!(yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &hash_hex)
            .unwrap());
    }
}

/// If a concurrent update supersedes a row's authoring identity WHILE
/// `hydrate_file` is mid-fetch (a peer's own materialize landing a
/// newer version for the same path), this attempt must not go on to
/// write the OLD version's bytes to disk and then claim `Hydrated` for
/// what is now a different, newer row -- it must detect the identity
/// change and fail instead, leaving the newer row's own state alone.
/// An independent Codex review's own counter-scenario to the rollback-
/// only fix (`HydratingStateGuard`'s authoring-bound CAS alone does not
/// protect the SUCCESSFUL commit path, only the failure-rollback path).
#[tokio::test]
async fn hydrate_file_detects_a_superseding_authoring_change_mid_fetch() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // A larger file (many blocks) so the real block-by-block fetch has
    // enough wall-clock duration for the race below to land reliably,
    // without relying on a fixed sleep -- the race is synchronized on a
    // real state transition (`Hydrating`), not a timing guess.
    let content = vec![0x77u8; 4_000_000];
    let file_path = device_a.root_path().join("bigfile.bin");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let placeholder_path = device_b.root_path().join("bigfile.bin");
    wait_until(|| placeholder_path.exists(), Duration::from_secs(10)).await;

    // A second, unrelated real file, synced the same way -- this gives a
    // genuinely admitted, verified authoring change hash to use as the
    // "superseding" identity below, satisfying the DAG-backed-row
    // invariant that a `current` row's authoring hash must reference an
    // admitted change (`files_require_authoring_identity_on_update`).
    // Which real change it is does not matter for what this test proves;
    // only that it differs from `bigfile.bin`'s own.
    let marker_path = device_a.root_path().join("marker.txt");
    std::fs::write(&marker_path, b"unrelated").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: marker_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    wait_until(
        || device_b.state.file_index_repository().get_file(GROUP, "marker.txt").unwrap().is_some(),
        Duration::from_secs(10),
    )
    .await;
    let superseding_hash = device_b
        .state
        .file_index_repository()
        .get_authoring_change_hash(GROUP, "marker.txt")
        .unwrap()
        .unwrap();

    let session_b_clone = session_b.clone();
    let hydrate_task =
        tokio::spawn(async move { session_b_clone.hydrate_file(GROUP, "bigfile.bin").await });

    // Real synchronization point (not a sleep): wait for this attempt to
    // actually start (state flips to `Hydrating`), then immediately
    // simulate a concurrent update superseding the row's identity --
    // exactly what a peer's own materialize landing a newer version
    // would do to this same column.
    wait_until(
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "bigfile.bin")
                .unwrap()
                == Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrating)
        },
        Duration::from_secs(10),
    )
    .await;
    device_b
        .state
        .file_index_repository()
        .set_authoring_change_hash(GROUP, "bigfile.bin", &superseding_hash)
        .unwrap();

    let result = hydrate_task.await.unwrap();

    assert!(
        result.is_err(),
        "hydration must detect the superseding authoring change and fail, not report Hydrated \
         for a version it never actually materialized: {result:?}"
    );
    assert_ne!(
        std::fs::read(&placeholder_path).unwrap(),
        content,
        "the old version's bytes must not have been written to disk for what is now a \
         different, newer row"
    );
    assert_eq!(
        device_b
            .state
            .file_index_repository()
            .get_authoring_change_hash(GROUP, "bigfile.bin")
            .unwrap(),
        Some(superseding_hash),
        "the superseding identity must survive untouched"
    );
}

/// An independent review's finding: `hydrate_file_with_timeout_locked`
/// re-verified the row's authoring identity before its physical write
/// (the test above), but never checked disk identity at all -- an
/// external editor writing real content directly into a `Placeholder`
/// row's already-on-disk sparse placeholder file, while this attempt is
/// mid-fetch, bypasses `path_lock` entirely (a plain filesystem write
/// goes through no lock this codebase controls), so the authoring column
/// never changes and that check alone cannot detect it. Genuine
/// interleaving is forced the same way as the test above: a real,
/// multi-block network fetch gives a real await window, synchronized on
/// the row actually reaching `Hydrating` rather than a timing guess.
#[tokio::test]
async fn hydrate_file_detects_a_concurrent_disk_edit_mid_fetch() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let content = vec![0x77u8; 4_000_000];
    let file_path = device_a.root_path().join("bigfile.bin");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let placeholder_path = device_b.root_path().join("bigfile.bin");
    wait_until(|| placeholder_path.exists(), Duration::from_secs(10)).await;

    let session_b_clone = session_b.clone();
    let hydrate_task =
        tokio::spawn(async move { session_b_clone.hydrate_file(GROUP, "bigfile.bin").await });

    wait_until(
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "bigfile.bin")
                .unwrap()
                == Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrating)
        },
        Duration::from_secs(10),
    )
    .await;
    // Simulate an external editor writing directly to the placeholder's
    // path -- no lock, no index interaction, exactly what a real editor
    // does.
    let edited_content = b"an editor's unsaved-by-the-index-yet edit";
    std::fs::write(&placeholder_path, edited_content).unwrap();

    let result = hydrate_task.await.unwrap();

    assert!(
        result.is_err(),
        "hydration must detect the concurrent disk edit and fail, not silently overwrite it: \
         {result:?}"
    );
    assert_eq!(
        std::fs::read(&placeholder_path).unwrap(),
        edited_content,
        "the external editor's content must survive untouched -- hydration must never have \
         called reconstruct_file over it"
    );
}

/// `hydrate_file` fetching every block but then finding a filename hazard
/// must report `HydrationOutcome::Held`, not something indistinguishable
/// from `Hydrated`: the blocks are genuinely in the local block store (so
/// this device can still serve them onward to a peer), but the file is
/// NOT written to disk under this name, and a caller (especially
/// `pin_and_hydrate_file`, whose own doc promises "pinning forces
/// hydration") must be able to tell the two outcomes apart rather than
/// reading a plain `Ok` as "the pinned file now has content on disk".
#[tokio::test]
async fn hydrate_file_reports_held_not_hydrated_when_a_hazard_collision_exists() {
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&std::env::temp_dir()) {
        eprintln!("skipping: temp dir is case-sensitive here");
        return;
    }
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&device_b.root_path()) {
        eprintln!("skipping: {} is case-sensitive here", device_b.root_path().display());
        return;
    }

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // A genuine, live, case-fold-colliding sibling already on device_b --
    // present before the incoming placeholder even arrives.
    std::fs::write(device_b.root_path().join("Photo.jpg"), b"sibling bytes").unwrap();
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "Photo.jpg".into(),
                size: b"sibling bytes".len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let content = vec![0x55u8; 50_000];
    let file_path = device_a.root_path().join("photo.jpg");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // The incoming "photo.jpg" record lands in the index (held, per the
    // tombstone/create hazard-hold path this crate already has for
    // ordinary reconciliation), but `hydrate_file` is a SEPARATE,
    // on-access path this test drives directly regardless of how the
    // index row got there.
    wait_until(
        || device_b.state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().is_some(),
        Duration::from_secs(10),
    )
    .await;

    let outcome = session_b.hydrate_file(GROUP, "photo.jpg").await.unwrap();

    let yadorilink_peer_session::peer_session::HydrationOutcome::Held { reason } = outcome else {
        panic!("a hazard-collision hydration must report Held, not Hydrated: {outcome:?}");
    };
    assert!(reason.starts_with("case_collision"), "unexpected reason: {reason}");
    assert!(
        !device_b.root_path().join("photo.jpg").exists()
            || std::fs::read(device_b.root_path().join("photo.jpg")).unwrap() == b"sibling bytes",
        "the incoming content must never land on disk under this colliding name"
    );
    assert_eq!(
        std::fs::read(device_b.root_path().join("Photo.jpg")).unwrap(),
        b"sibling bytes",
        "the sibling must remain untouched"
    );
}

/// hydrating a file with no peer connected at
/// all must fail with a clear, bounded error rather than hanging forever —
/// the plain (no-network) case of "no reachable peer holds the blocks."
#[tokio::test]
async fn hydrate_file_without_any_connected_peer_fails_immediately() {
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    // A placeholder entry with no session/peer at all attached to it —
    // `hydrate_file` needs *some* `PeerSyncSession` to call it on, so
    // simulate "adopted as a placeholder, but the only peer that has it
    // is now disconnected" by constructing a session whose channel points
    // at a peer that immediately drops.
    let (secret_b, public_b) = gen_keypair();
    // A channel to a peer public key nobody is listening on: the daemon
    // side of this pairing never responds to any BlockRequest. The direct
    // candidate is a real port that was bound then dropped, so it stays
    // unbound and nothing ever answers.
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ghost_addr = {
        let throwaway = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        throwaway.local_addr().unwrap()
    };
    let (_ghost_secret, ghost_public) = gen_keypair();
    let channel_b = std::sync::Arc::new(
        PeerChannel::connect(
            secret_b,
            ghost_public,
            0,
            vec![ghost_addr],
            yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
        )
        .await
        .unwrap(),
    );
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "unreachable.bin".into(),
                size: 100,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xCDu8; 32],
                    offset: 0,
                    size: 100,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "unreachable.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        session_b.hydrate_file_with_timeout(GROUP, "unreachable.bin", Duration::from_millis(500)),
    )
    .await
    .expect("hydrate_file must respect its own bounded timeout, not hang past it")
    .unwrap_err();
    assert!(matches!(err, yadorilink_peer_session::PeerSessionError::HydrationFailed(_)));

    // Left as a placeholder, not stuck at `Hydrating`.
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "unreachable.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
}

/// hydrate → evict → re-hydrate must round-trip
/// to byte-identical content — eviction doesn't touch sync state (version,
/// block list), so a second hydration from the same (or any other) peer
/// reconstructs exactly the same bytes.
#[tokio::test]
async fn evict_then_rehydrate_round_trips_to_identical_content() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let content = vec![0x99u8; 250_000];
    let file_path = device_a.root_path().join("archive.zip");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let path_on_b = device_b.root_path().join("archive.zip");
    wait_until(|| path_on_b.exists(), Duration::from_secs(10)).await;

    session_b.hydrate_file(GROUP, "archive.zip").await.unwrap();
    assert_eq!(std::fs::read(&path_on_b).unwrap(), content);

    struct RejectCustody;
    impl yadorilink_replica_engine::custody::FullReplicaCustody for RejectCustody {
        fn confirm_exact_version(
            &self,
            _group_id: &str,
            _path: &str,
            _version_hash: &yadorilink_replica_domain::ids::VersionHash,
            _blocks: &[yadorilink_replica_domain::file::VersionBlock],
        ) -> Option<yadorilink_replica_engine::custody::CustodyStamp> {
            None
        }

        fn confirmation_still_valid(
            &self,
            _group_id: &str,
            _stamp: &yadorilink_replica_engine::custody::CustodyStamp,
        ) -> bool {
            false
        }
    }

    let permit = RootCommitPermit::for_tests();
    yadorilink_filesystem_sync::materialization_eviction::evict_file(
        yadorilink_filesystem_sync::materialization_eviction::MaterializationContext {
            state: device_b.state.as_ref(),
            liveness_gate: &yadorilink_filesystem_sync::block_liveness::BlockLivenessGate::default(
            ),
            store: device_b.store.as_ref(),
            root: &device_b.root_path(),
            permit: &permit,
        },
        GROUP,
        "archive.zip",
        false,
        // Custody unconfirmed here: this exercises the placeholder transition
        // and subsequent re-hydration, not block reclamation, so the cached
        // blocks are retained (fail closed) and re-hydration is a local no-op.
        &RejectCustody,
    )
    .unwrap();
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "archive.zip")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
    assert_ne!(
        std::fs::read(&path_on_b).unwrap(),
        content,
        "evicted file must no longer hold real content"
    );

    session_b.hydrate_file(GROUP, "archive.zip").await.unwrap();
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "archive.zip")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrated)
    );
    assert_eq!(
        std::fs::read(&path_on_b).unwrap(),
        content,
        "re-hydration must reconstruct identical content"
    );
}

/// three devices, one `OnDemand` folder group —
/// a file created on A appears as a placeholder on both B and C with no
/// content transfer; hydrating on B fetches content only there, C stays a
/// placeholder throughout.
#[tokio::test]
async fn three_devices_on_demand_hydration_is_per_device_not_group_wide() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let device_c = Device::new("device-c");

    for device in [&device_b, &device_c] {
        let root = device.root_path().to_string_lossy().to_string();
        link_with_completed_startup(&device.state, &root);
        device
            .state
            .link_repository()
            .set_materialization_policy(
                &root,
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            )
            .unwrap();
    }

    let content = vec![0x99u8; 300_000];
    let file_path = device_a.root_path().join("presentation.pptx");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    // A is connected to both B and C directly (a star topology) — each
    // gets A's full index independently on connect.
    let (channel_a_b, channel_b) = connect_pair(addr).await;
    let (channel_a_c, channel_c) = connect_pair(addr).await;
    let _session_a_b = spawn_session(channel_a_b, &device_a, "device-b");
    let _session_a_c = spawn_session(channel_a_c, &device_a, "device-c");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let _session_c = spawn_session(channel_c, &device_c, "device-a");

    let path_on_b = device_b.root_path().join("presentation.pptx");
    let path_on_c = device_c.root_path().join("presentation.pptx");
    wait_until(|| path_on_b.exists() && path_on_c.exists(), Duration::from_secs(10)).await;

    // Both adopted a placeholder — correct size, no real content, and no
    // block bytes fetched over the wire at all (the design's whole point).
    for (device, path) in [(&device_b, &path_on_b), (&device_c, &path_on_c)] {
        assert_eq!(std::fs::metadata(path).unwrap().len(), 300_000);
        assert_ne!(std::fs::read(path).unwrap(), content);
        assert_eq!(
            device
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "presentation.pptx")
                .unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
        );
        let record = device
            .state
            .file_index_repository()
            .get_file(GROUP, "presentation.pptx")
            .unwrap()
            .unwrap();
        for block in &record.blocks {
            let hash_hex = hex::encode(&block.hash);
            assert!(
                !yadorilink_local_storage::BlockStore::exists(device.store.as_ref(), &hash_hex)
                    .unwrap(),
                "adopting a placeholder must not fetch any block content"
            );
        }
    }

    // Opening it on B hydrates only B.
    session_b.hydrate_file(GROUP, "presentation.pptx").await.unwrap();
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "presentation.pptx")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(&path_on_b).unwrap(), content);

    // C was never asked to hydrate and remains an untouched placeholder.
    assert_eq!(
        device_c
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "presentation.pptx")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
    assert_ne!(std::fs::read(&path_on_c).unwrap(), content);
    let record_c = device_c
        .state
        .file_index_repository()
        .get_file(GROUP, "presentation.pptx")
        .unwrap()
        .unwrap();
    for block in &record_c.blocks {
        let hash_hex = hex::encode(&block.hash);
        assert!(
            !yadorilink_local_storage::BlockStore::exists(device_c.store.as_ref(), &hash_hex)
                .unwrap(),
            "hydrating on B must not fetch any block content to C"
        );
    }
}

/// hydration with no reachable peer holding the
/// blocks must time out with a clear, catchable error, never hang the
/// caller indefinitely — exercised here with a short timeout to keep the
/// test itself fast (production uses `DEFAULT_HYDRATION_TIMEOUT`, task ).
/// Simulated with a real, connected channel whose peer side simply never
/// runs (so a `BlockRequest` is sent but never answered) — a stalled peer
/// is a more realistic "unreachable" case than a channel that fails to
/// establish at all, and exercises the same timeout path either way.
#[tokio::test]
async fn hydration_chaos_no_reachable_peer_times_out_cleanly() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // A placeholder exists locally (as if adopted from a peer earlier),
    // but the connected peer never answers the resulting block request.
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "orphaned.bin".into(),
                size: 5_000,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0x11u8; 32],
                    offset: 0,
                    size: 5_000,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "orphaned.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    yadorilink_local_storage::write_placeholder(
        &device_b.root_path().join("orphaned.bin"),
        5_000,
        0,
    )
    .unwrap();

    // `channel_nobody` is kept alive (so the connection stays open — this
    // tests the *timeout* path, not a connection-closed error) but
    // intentionally never driven by a `.run` loop, so nothing ever
    // reads the `BlockRequest` `hydrate_file_with_timeout` sends over
    // `channel_b`.
    let (_channel_nobody, channel_b) = connect_pair(addr).await;
    let session_b = spawn_session(channel_b, &device_b, "device-nobody");

    let started = tokio::time::Instant::now();
    let result = session_b
        .hydrate_file_with_timeout(GROUP, "orphaned.bin", Duration::from_millis(300))
        .await;
    let elapsed = started.elapsed();

    assert!(result.is_err(), "hydration with no reachable peer must return an error, not hang");
    assert!(
        elapsed < Duration::from_secs(2),
        "hydration must fail promptly on timeout, took {elapsed:?}"
    );
    // The failed attempt leaves the file as a placeholder, not stuck
    // "Hydrating" forever — a retry later is still possible.
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "orphaned.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
}

/// a peer response is not trusted just because it arrives on the
/// encrypted channel. The bytes must match the requested block's hash and
/// size before they are persisted or materialized.
#[tokio::test]
async fn hydration_rejects_block_response_with_wrong_hash_or_size() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x42u8; 4096];
    let expected_hash = sha256_bytes(&expected);
    let bad_data = vec![0x24u8; 4096];
    assert_ne!(sha256_bytes(&bad_data), expected_hash);

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "tampered.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "tampered.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    yadorilink_local_storage::write_placeholder(
        &device_b.root_path().join("tampered.bin"),
        expected.len() as u64,
        0,
    )
    .unwrap();

    let (responder_channel, channel_b) = connect_pair(addr).await;
    // Not `spawn_session`: see the identical note in
    // `hydration_rejects_a_decompression_bomb_block_response` -- this test's
    // one hand-written fake responder answers exactly one `BlockRequest`,
    // which the test-only convergence driver's own concurrent repair fetch
    // for this same placeholder could otherwise race and consume.
    // `_with_root_authority`: `hydrate_file_with_timeout` below is a real
    // mutation path gated on a live root-commit authority --
    // `PeerSyncSessionDeps::standalone()`'s deny-by-default provider would
    // otherwise make it fail fast with `NotFound` before ever sending the
    // `BlockRequest` this test's fake responder is waiting to answer.
    let session_b = spawn_session_without_convergence_driver_with_root_authority(
        channel_b, &device_b, "device-a",
    );
    let handshake_session_b = session_b.clone();
    let responder = tokio::spawn(async move {
        let mut buffered: std::collections::VecDeque<Vec<u8>> =
            complete_raw_peer_handshake(&responder_channel, &handshake_session_b).await.into();
        loop {
            let bytes = match buffered.pop_front() {
                Some(bytes) => bytes,
                None => responder_channel.recv().await.unwrap(),
            };
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockReply(
                            proto::BlockReply {
                                block_hash: req.block_hash,
                                outcome: Some(proto::block_reply::Outcome::Found(
                                    proto::BlockReplyFound {
                                        data: bad_data,
                                        compression: proto::Compression::None as i32,
                                    },
                                )),
                                request_id: req.request_id,
                            },
                        )),
                    }
                    .encode_to_vec(),
                )
                .await
                .unwrap();
            break;
        }
    });

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "tampered.bin", Duration::from_secs(3)).await;
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "invalid block bytes must fail hydration, got {result:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "mismatched bytes must not be persisted under the expected block hash"
    );
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "tampered.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
}

#[tokio::test]
async fn requester_honors_busy_retry_after_before_retrying_same_peer() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");
    let data = b"available after one busy response".to_vec();
    let hash = sha256_bytes(&data);

    let (responder_channel, channel_b) = connect_pair(addr).await;
    let session_b = spawn_session_without_convergence_driver(channel_b, &device_b, "device-a");
    let handshake_session_b = session_b.clone();
    let responder = tokio::spawn(async move {
        let mut buffered: std::collections::VecDeque<Vec<u8>> =
            complete_raw_peer_handshake(&responder_channel, &handshake_session_b).await.into();
        let mut first_request_at = None;
        let mut first_request_id = None;
        loop {
            let bytes = match buffered.pop_front() {
                Some(bytes) => bytes,
                None => responder_channel.recv().await.unwrap(),
            };
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };

            if first_request_at.is_none() {
                first_request_at = Some(tokio::time::Instant::now());
                first_request_id = Some(req.request_id);
                responder_channel
                    .send(
                        proto::SyncMessage {
                            payload: Some(proto::sync_message::Payload::BlockReply(
                                proto::BlockReply {
                                    block_hash: req.block_hash,
                                    outcome: Some(proto::block_reply::Outcome::Busy(
                                        proto::BlockReplyBusy {
                                            retry_after_ms: 80,
                                            queue_depth: 1,
                                        },
                                    )),
                                    request_id: req.request_id,
                                },
                            )),
                        }
                        .encode_to_vec(),
                    )
                    .await
                    .unwrap();
                continue;
            }

            let retry_delay = first_request_at.unwrap().elapsed();
            let second_request_id = req.request_id;
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockReply(
                            proto::BlockReply {
                                block_hash: req.block_hash,
                                outcome: Some(proto::block_reply::Outcome::Found(
                                    proto::BlockReplyFound {
                                        data,
                                        compression: proto::Compression::None as i32,
                                    },
                                )),
                                request_id: req.request_id,
                            },
                        )),
                    }
                    .encode_to_vec(),
                )
                .await
                .unwrap();
            break (first_request_id.unwrap(), second_request_id, retry_delay);
        }
    });

    let received = session_b
        .fetch_block(GROUP, "busy.bin", &hash)
        .await
        .unwrap()
        .expect("the retry must receive the block");
    let (first_request_id, second_request_id, retry_delay) = responder.await.unwrap();

    assert_eq!(&received[..], b"available after one busy response");
    assert_ne!(first_request_id, second_request_id, "a retry needs fresh correlation");
    assert!(
        retry_delay >= Duration::from_millis(70),
        "retry ignored the peer's 80ms backoff hint: {retry_delay:?}"
    );
}

/// group authorization alone is not enough to serve arbitrary
/// block-store contents. The requested hash must be referenced by the
/// requested file record in that group.
#[tokio::test]
async fn block_request_for_unreferenced_hash_is_refused() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let public_data = b"public file contents".to_vec();
    let public_hash = sha256_bytes(&public_data);
    let secret_data = b"secret orphan block".to_vec();
    let secret_hash = sha256_bytes(&secret_data);
    device_a.store.put(&public_data).unwrap();
    device_a.store.put(&secret_data).unwrap();

    device_a
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "public.bin".into(),
                size: public_data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: public_hash,
                    offset: 0,
                    size: public_data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    complete_raw_peer_handshake(&requester_channel, &session_a).await;
    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "public.bin".to_string(),
                    block_hash: secret_hash.clone(),
                    request_id: 0,
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let reply = loop {
        let bytes = requester_channel.recv().await.unwrap();
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        if let Some(proto::sync_message::Payload::BlockReply(reply)) = msg.payload {
            break reply;
        }
    };

    assert_eq!(reply.block_hash, secret_hash);
    assert!(
        matches!(reply.outcome, Some(proto::block_reply::Outcome::DontHave(true))),
        "unreferenced block hash must be refused, got {:?}",
        reply.outcome
    );
}

/// (security review): a hydration request's
/// underlying `BlockRequest` goes through the exact same
/// `handle_block_request` authorization check as any other block fetch —
/// there is no separate, unchecked path for on-access hydration. Verified
/// here by having the *responding* peer's session independently lack
/// authorization for the group (simulating a coordination-plane ACL that
/// doesn't actually cover this pairing), even though the requester
/// believes it does — content must never be leaked either way.
#[tokio::test]
async fn hydration_block_request_is_refused_for_a_group_the_peer_does_not_authorize() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let content = vec![0xCCu8; 5_000];
    let file_path = device_a.root_path().join("secret.bin");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    // B already has an (independently-constructed) placeholder for this
    // group/path, as if adopted earlier while genuinely authorized.
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    let record =
        device_a.state.file_index_repository().get_file(GROUP, "secret.bin").unwrap().unwrap();
    device_b
        .state
        .file_index_repository()
        .upsert_file(GROUP, &record, &RootCommitPermit::for_tests())
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "secret.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    yadorilink_local_storage::write_placeholder(&device_b.root_path().join("secret.bin"), 5_000, 0)
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    // A's session (which will *answer* B's block requests) is constructed
    // with an empty shared-group list — A is no longer actually
    // authorized to share GROUP with B, regardless of what B believes.
    let _session_a = spawn_session_with_groups(channel_a, &device_a, "device-b", vec![]);
    let session_b =
        spawn_session_with_groups(channel_b, &device_b, "device-a", vec![GROUP.to_string()]);

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "secret.bin", Duration::from_secs(3)).await;

    assert!(result.is_err(), "hydration must fail when the peer does not authorize the group");
    assert_ne!(
        std::fs::read(device_b.root_path().join("secret.bin")).unwrap(),
        content,
        "content must never be leaked across an unauthorized group boundary"
    );
    let hash_hex = hex::encode(&record.blocks[0].hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &hash_hex).unwrap(),
        "the refused block must never land in B's block store either"
    );
}

/// Waits for and returns the next `BlockReply` matching `hash` on
/// `channel`, ignoring any other message types (handshake `ClusterConfig`/
/// etc.) that may arrive interleaved — same pattern
/// `block_request_for_unreferenced_hash_is_refused` inlines, factored out
/// here since the mid-session-revocation test below needs it twice.
async fn recv_matching_block_reply(channel: &PeerChannel, hash: &[u8]) -> proto::BlockReply {
    loop {
        let bytes = channel.recv().await.unwrap();
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        if let Some(proto::sync_message::Payload::BlockReply(reply)) = msg.payload {
            if reply.block_hash == hash {
                return reply;
            }
        }
    }
}

/// "A mid-session revocation stops further block requests without
/// waiting for teardown": a block request that was valid when the
/// session started must be refused once a netmap update
/// revokes that group edge mid-session — even though nothing here tears
/// down the transport-level `PeerChannel`/tunnel (that reaction is a
/// separate concern, deliberately exercised nowhere in this test).
/// `PeerSyncSession::revoke_group` is the hook a daemon-level netmap-diff
/// reaction is expected to call; this test calls it directly to simulate
/// that reaction landing mid-session, proving the sync-engine layer's own
/// defense works independently of whether transport teardown has happened
/// yet.
#[tokio::test]
async fn block_request_is_refused_after_mid_session_group_revocation() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let data = b"public file contents, initially authorized".to_vec();
    let hash = sha256_bytes(&data);
    device_a.store.put(&data).unwrap();
    // Mirrors what `LocalChangeProcessor` does for a real local edit
    // (`record_group_block_provenance`'s doc comment): without this, the
    // block-serving path refuses this block as never having been obtained
    // through the group.
    device_a
        .state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();

    device_a
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "public.bin".into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    // session_a is the *answering* side — its live authorization is what
    // gets revoked mid-session below.
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    assert!(session_a.shares_group(GROUP), "sanity: session starts out authorized for GROUP");
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    let send_request = |channel: Arc<PeerChannel>, hash: Vec<u8>| async move {
        channel
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockRequest(
                        proto::BlockRequest {
                            folder_group_id: GROUP.to_string(),
                            file_path: "public.bin".to_string(),
                            block_hash: hash,
                            request_id: 0,
                        },
                    )),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    };

    // Baseline: while still authorized, the request succeeds.
    send_request(requester_channel.clone(), hash.clone()).await;
    let first_reply = recv_matching_block_reply(&requester_channel, &hash).await;
    assert!(
        matches!(first_reply.outcome, Some(proto::block_reply::Outcome::Found(_))),
        "block request must succeed while peer is authorized, got {:?}",
        first_reply.outcome
    );
    let Some(proto::block_reply::Outcome::Found(found)) = first_reply.outcome else {
        unreachable!()
    };
    assert_eq!(found.data, data);

    // Simulate a netmap update revoking device-b's authorization for GROUP
    // as seen by device-a's session, mid-session — nothing here touches
    // `requester_channel`/`channel_a`, so the transport-level tunnel stays
    // fully connected and open throughout.
    session_a.revoke_group(GROUP);
    assert!(
        !session_a.shares_group(GROUP),
        "revoke_group must be reflected immediately, without waiting for anything else"
    );

    // Same request, same still-open tunnel, now refused.
    send_request(requester_channel.clone(), hash.clone()).await;
    let second_reply = recv_matching_block_reply(&requester_channel, &hash).await;
    assert!(
        matches!(second_reply.outcome, Some(proto::block_reply::Outcome::Rejected(_))),
        "block request must be refused once a mid-session revocation is reflected in local \
         netmap/ACL state, even though the transport tunnel hasn't been torn down -- got {:?}",
        second_reply.outcome
    );
}

/// Regression for a confirmed disclosure window: `handle_block_request`
/// checks `shares_group` once, then `handle_block_request_with_credit`
/// can wait up to `DISPATCH_WAIT_BUDGET` (~2s) for a fair dispatch turn
/// before ever reading or sending the block. If authorization is revoked
/// WHILE a request is merely waiting its turn, the (fixed) code must
/// re-check before proceeding -- otherwise a just-revoked peer would
/// still receive content for however long its request happened to be
/// queued. Forces the exact race deterministically: this test itself
/// holds `device-b`/`GROUP`'s one dispatch slot (via the same public
/// `acquire_dispatch_turn` the real session calls), so the real
/// `BlockRequest` sent below is GUARANTEED to be queued, not granted
/// immediately -- revocation happens while it waits, and only then does
/// this test release the slot to let it proceed.
#[tokio::test]
async fn block_request_is_rejected_if_authorization_is_revoked_while_waiting_for_a_dispatch_turn() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let data = b"content revoked mid-dispatch-wait".to_vec();
    let hash = sha256_bytes(&data);
    device_a.store.put(&data).unwrap();
    device_a
        .state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();

    device_a
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "dispatch-wait.bin".into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1,
    );
    session_a.set_block_serve_engine(engine.clone());
    assert!(session_a.shares_group(GROUP), "sanity: session starts out authorized for GROUP");

    // Occupy the one dispatch slot for exactly the key ("device-b", GROUP)
    // the real request below will need, so it is guaranteed to queue.
    let holder_guard = engine.acquire_dispatch_turn("device-b", GROUP, 1).await.unwrap();

    complete_raw_peer_handshake(&requester_channel, &session_a).await;
    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "dispatch-wait.bin".to_string(),
                    block_hash: hash.clone(),
                    request_id: 0,
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
    // Give the recv loop a moment to spawn the handler and reach (and
    // block on) `acquire_dispatch_turn`.
    tokio::time::sleep(Duration::from_millis(200)).await;

    session_a.revoke_group(GROUP);
    assert!(!session_a.shares_group(GROUP));

    // Release the slot now -- the queued request is granted its turn only
    // AFTER the revocation above.
    drop(holder_guard);

    let reply = tokio::time::timeout(
        Duration::from_secs(3),
        recv_matching_block_reply(&requester_channel, &hash),
    )
    .await
    .expect("the request must resolve promptly once its dispatch turn is granted");
    assert!(
        matches!(reply.outcome, Some(proto::block_reply::Outcome::Rejected(_))),
        "a peer whose authorization was revoked WHILE its request merely waited for a dispatch \
         turn must be refused, not served -- got {:?}",
        reply.outcome
    );
}

/// "An index update from a just-revoked peer is rejected": an index
/// update from a peer whose authorization for the named group was
/// revoked *before* the update is processed must be rejected, not
/// applied — even though the update arrives over an already-established
/// session whose transport-level tunnel is untouched by this test.
#[tokio::test]
async fn index_update_from_just_revoked_peer_is_rejected() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    assert!(session_b.shares_group(GROUP), "sanity: B starts out authorizing A for GROUP");

    // Simulate a netmap update revoking device-a's authorization for GROUP as
    // seen by device-b's session (the *receiving* side for the change about to
    // be announced) — before the change is ever sent, i.e. "revoked before the
    // change was processed".
    session_b.revoke_group(GROUP);

    // device-a commits a change and announces it. device-b, no longer sharing
    // GROUP, must drop the announce/change: handle_heads_announce and
    // handle_change_batch both gate on shares_group.
    device_a.producer().commit_create(GROUP, "sneaky.txt", b"data", 0);
    let _ = session_a.announce_local_commit(GROUP).await;
    // Give plenty of time (and a second announce) for the change to arrive and
    // (if the revalidation were missing) be applied.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = session_a.announce_local_commit(GROUP).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        device_b.state.file_index_repository().get_file(GROUP, "sneaky.txt").unwrap().is_none(),
        "a change from a just-revoked peer must not be applied to the local index"
    );
    assert!(
        !device_b.root_path().join("sneaky.txt").exists(),
        "a change from a just-revoked peer must never be materialized to disk"
    );
}

/// An authorized peer is served the content it requests via `BlockRequest`:
/// block reads are gated only on group authorization (`shares_group`), and
/// every authorized device is a full bidirectional peer, so a peer sharing
/// the group is served existing content normally. Mirrors
/// `block_request_is_refused_after_mid_session_group_revocation`'s structure,
/// but here authorization stays in place, so the request must NOT be refused.
#[tokio::test]
async fn block_requests_are_served_to_an_authorized_peer() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let data = b"authorized peers may read this content".to_vec();
    let hash = sha256_bytes(&data);
    device_a.store.put(&data).unwrap();
    // See the identical comment in
    // `block_request_is_refused_after_mid_session_group_revocation` above.
    device_a
        .state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();

    device_a
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "readable.bin".into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    // session_a is the *answering* side, playing the sharer who has
    // authorized device-b for GROUP.
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    assert!(session_a.shares_group(GROUP), "sanity: the peer is authorized for the group");
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    let send_request = |channel: Arc<PeerChannel>, hash: Vec<u8>| async move {
        channel
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockRequest(
                        proto::BlockRequest {
                            folder_group_id: GROUP.to_string(),
                            file_path: "readable.bin".to_string(),
                            block_hash: hash,
                            request_id: 0,
                        },
                    )),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    };

    send_request(requester_channel.clone(), hash.clone()).await;
    let reply = recv_matching_block_reply(&requester_channel, &hash).await;
    let Some(proto::block_reply::Outcome::Found(found)) = reply.outcome else {
        panic!(
            "an authorized peer must be served existing content: block requests are gated only \
             on group authorization (shares_group) -- got {:?}",
            reply.outcome
        );
    };
    assert_eq!(found.data, data);
}

// --- Characterization tests for `docs/design/phase7-peer-handler-
// inventory.md`'s "Deep dive: handle_block_request /
// handle_block_request_with_credit / handle_block_reply invariant
// ordering" section. These pin the exact examination-permit-drop and
// dispatch/credit-guard drop ORDERING that section's own line-level
// reading of the source established, so a future mechanical
// extraction/refactor that reorders any of them fails a fast, deterministic
// test instead of only ever showing up as an intermittent cross-peer
// fairness/DoS regression under load.

/// Shared setup for the four `examination_permit_is_released_before_reply_*`
/// tests below: stores `data` in `device`'s block store, records the
/// group's provenance for its hash, and upserts a one-block `FileRecord` at
/// `path` referencing it -- the same pattern several tests above already
/// inline individually, factored out here since these tests need it for
/// more than one distinct hash each.
fn seed_referenced_block(device: &Device, path: &str, data: &[u8]) -> Vec<u8> {
    let hash = sha256_bytes(data);
    device.store.put(data).unwrap();
    device
        .state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    device
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: path.into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    hash
}

/// Like `seed_referenced_block`, but deliberately withholds
/// `record_group_block_provenance` -- the block is referenced by a live
/// `FileRecord` (so `block_request_is_referenced` passes) but has no
/// verified group provenance (so `group_has_block_provenance` fails),
/// isolating that specific rejection path from the "not referenced at all"
/// one `seed_referenced_block`'s absence would otherwise also trigger.
fn seed_referenced_block_without_provenance(device: &Device, path: &str, data: &[u8]) -> Vec<u8> {
    let hash = sha256_bytes(data);
    device.store.put(data).unwrap();
    device
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: path.into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    hash
}

/// Bounds a hand-written fake responder task so a future regression (e.g.
/// the request it's waiting for never arriving) fails fast with a
/// descriptive panic instead of hanging the test indefinitely. Aborts the
/// task on timeout so it doesn't linger past the failing assertion.
async fn await_responder(responder: tokio::task::JoinHandle<()>) {
    let abort_handle = responder.abort_handle();
    match tokio::time::timeout(Duration::from_secs(5), responder).await {
        Ok(join_result) => join_result.expect("fake responder task panicked"),
        Err(_) => {
            abort_handle.abort();
            panic!("fake responder did not finish within 5s");
        }
    }
}

/// Sends a raw `BlockRequest` for `hash` at `file_path` over `channel`.
async fn send_block_request(channel: &PeerChannel, file_path: &str, hash: Vec<u8>) {
    channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: file_path.to_string(),
                    block_hash: hash,
                    request_id: 0,
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
}

/// Builds a `BlockServeEngine` with generous dispatch/credit budgets (not
/// what the tests using this helper exercise) but a device-wide
/// examination-admission pool drained down to exactly one free slot --
/// every other slot consumed directly via the engine's own public
/// `try_begin_examination` and held in the returned `Vec` for the whole
/// test. With one slot deliberately left free, a live session backed by
/// this engine can push exactly one `BlockRequest` through examination at a
/// time; a second request sent immediately afterward can only also get
/// examined (rather than denied at the recv loop's own `try_begin_
/// examination` gate -- a `Busy` reply with no handler ever spawned for it)
/// if the first request's `examination_permits` was already dropped. This
/// is the least-invasive way to make `examination_admission`'s internal
/// semaphore state observable from a test without a backdoor into
/// `BlockServeEngine` itself -- its live permit count is deliberately not
/// part of its public API (see `ExaminationPermit`'s own doc comment: "the
/// field is intentionally write-only from this crate's perspective").
fn engine_with_one_free_examination_slot() -> (
    Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
    Vec<yadorilink_peer_session::block_serve::ExaminationPermit>,
) {
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        4,
    );
    let mut held = Vec::new();
    while let Ok(permit) = engine.try_begin_examination() {
        held.push(permit);
    }
    assert!(!held.is_empty(), "sanity: examination capacity must be positive");
    held.pop();
    (engine, held)
}

/// Pins invariant 1 (`shares_group` rejection path) from the peer-handler
/// inventory doc's deep dive: `examination_permits` must be dropped (the
/// doc's line ~5710) strictly before the non-blocking `Rejected` reply that
/// path sends. Proven by leaving the device exactly one free examination
/// slot, sending an unauthorized request down this exact path, waiting for
/// its reply, then sending a second request that can only avoid a `Busy`
/// reply of its own if the first request's slot was already back.
#[tokio::test]
async fn examination_permit_is_released_before_reply_on_shares_group_rejection() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let (channel_a, requester_channel) = connect_pair(addr).await;
    // No shared groups at all -- every request fails `shares_group`,
    // regardless of file path or hash, before either is ever looked up.
    let session_a = spawn_session_with_groups(channel_a, &device_a, "device-b", vec![]);
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.set_block_serve_engine(engine);
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    let hash_1 = sha256_bytes(b"first unauthorized request");
    send_block_request(&requester_channel, "whatever-1.bin", hash_1.clone()).await;
    let reply_1 = recv_matching_block_reply(&requester_channel, &hash_1).await;
    assert!(
        matches!(reply_1.outcome, Some(proto::block_reply::Outcome::Rejected(_))),
        "sanity: this path must be the shares_group rejection, got {:?}",
        reply_1.outcome
    );

    let hash_2 = sha256_bytes(b"second unauthorized request, the probe");
    send_block_request(&requester_channel, "whatever-2.bin", hash_2.clone()).await;
    let reply_2 = recv_matching_block_reply(&requester_channel, &hash_2).await;
    assert!(
        !matches!(reply_2.outcome, Some(proto::block_reply::Outcome::Busy(_))),
        "the probe request must not be denied examination admission by the recv loop's own \
         try_begin_examination gate -- the only spare examination slot this device had must \
         already have been returned by the first request's own reply time, got {:?}",
        reply_2.outcome
    );
    assert!(
        matches!(reply_2.outcome, Some(proto::block_reply::Outcome::Rejected(_))),
        "sanity: the probe must take the identical shares_group rejection path, got {:?}",
        reply_2.outcome
    );
    drop(held_permits);
}

/// Pins invariant 1 (`block_request_is_referenced` rejection path): the
/// doc's line ~5732.
#[tokio::test]
async fn examination_permit_is_released_before_reply_when_block_is_not_referenced() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.set_block_serve_engine(engine);
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    // Neither hash is referenced by any file record, in the DAG, or as a
    // retained version -- `block_request_is_referenced` returns false for
    // both, with nothing seeded in device-a's state at all.
    let hash_1 = sha256_bytes(b"first unreferenced hash");
    send_block_request(&requester_channel, "unreferenced-1.bin", hash_1.clone()).await;
    let reply_1 = recv_matching_block_reply(&requester_channel, &hash_1).await;
    assert!(
        matches!(reply_1.outcome, Some(proto::block_reply::Outcome::DontHave(true))),
        "sanity: this path must be the not-referenced dont_have path, got {:?}",
        reply_1.outcome
    );

    let hash_2 = sha256_bytes(b"second unreferenced hash, the probe");
    send_block_request(&requester_channel, "unreferenced-2.bin", hash_2.clone()).await;
    let reply_2 = recv_matching_block_reply(&requester_channel, &hash_2).await;
    assert!(
        !matches!(reply_2.outcome, Some(proto::block_reply::Outcome::Busy(_))),
        "the probe request must not be denied examination admission -- the only spare \
         examination slot must already have been returned by the first request's own reply \
         time, got {:?}",
        reply_2.outcome
    );
    assert!(
        matches!(reply_2.outcome, Some(proto::block_reply::Outcome::DontHave(true))),
        "sanity: the probe must take the identical not-referenced path, got {:?}",
        reply_2.outcome
    );
    drop(held_permits);
}

/// Pins invariant 1 (`group_has_block_provenance` rejection path): the
/// doc's line ~5745.
#[tokio::test]
async fn examination_permit_is_released_before_reply_when_group_has_no_block_provenance() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let hash_1 = seed_referenced_block_without_provenance(
        &device_a,
        "no-provenance-1.bin",
        b"referenced but never obtained through this group",
    );
    let hash_2 = seed_referenced_block_without_provenance(
        &device_a,
        "no-provenance-2.bin",
        b"same story, the probe",
    );

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.set_block_serve_engine(engine);
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    send_block_request(&requester_channel, "no-provenance-1.bin", hash_1.clone()).await;
    let reply_1 = recv_matching_block_reply(&requester_channel, &hash_1).await;
    assert!(
        matches!(reply_1.outcome, Some(proto::block_reply::Outcome::Rejected(_))),
        "sanity: this path must be the no-provenance rejection, got {:?}",
        reply_1.outcome
    );

    send_block_request(&requester_channel, "no-provenance-2.bin", hash_2.clone()).await;
    let reply_2 = recv_matching_block_reply(&requester_channel, &hash_2).await;
    assert!(
        !matches!(reply_2.outcome, Some(proto::block_reply::Outcome::Busy(_))),
        "the probe request must not be denied examination admission -- the only spare \
         examination slot must already have been returned by the first request's own reply \
         time, got {:?}",
        reply_2.outcome
    );
    assert!(
        matches!(reply_2.outcome, Some(proto::block_reply::Outcome::Rejected(_))),
        "sanity: the probe must take the identical no-provenance rejection path, got {:?}",
        reply_2.outcome
    );
    drop(held_permits);
}

/// Pins invariant 1 (the pass-through/serve path): the doc's line ~5778,
/// where the drop is unconditional and happens BEFORE dispatch even
/// begins -- so it must already be back well before the first request's
/// own (much later) `Found` reply.
#[tokio::test]
async fn examination_permit_is_released_before_reply_on_the_pass_through_serve_path() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let data_1 = b"first fully servable block".to_vec();
    let hash_1 = seed_referenced_block(&device_a, "servable-1.bin", &data_1);
    let data_2 = b"second fully servable block, the probe".to_vec();
    let hash_2 = seed_referenced_block(&device_a, "servable-2.bin", &data_2);

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.set_block_serve_engine(engine);
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    send_block_request(&requester_channel, "servable-1.bin", hash_1.clone()).await;
    let reply_1 = recv_matching_block_reply(&requester_channel, &hash_1).await;
    let Some(proto::block_reply::Outcome::Found(found_1)) = reply_1.outcome else {
        panic!("sanity: this path must be the pass-through serve path, got {:?}", reply_1.outcome);
    };
    assert_eq!(found_1.data, data_1);

    send_block_request(&requester_channel, "servable-2.bin", hash_2.clone()).await;
    let reply_2 = recv_matching_block_reply(&requester_channel, &hash_2).await;
    assert!(
        !matches!(reply_2.outcome, Some(proto::block_reply::Outcome::Busy(_))),
        "the probe request must not be denied examination admission -- on this path \
         examination_permits is dropped unconditionally before dispatch even begins, so it \
         must already have been returned well before the first request's own reply, got {:?}",
        reply_2.outcome
    );
    let Some(proto::block_reply::Outcome::Found(found_2)) = reply_2.outcome else {
        panic!("sanity: the probe must also be served, got an unexpected outcome");
    };
    assert_eq!(found_2.data, data_2);
    drop(held_permits);
}

/// Pins invariant 2 from the peer-handler inventory doc's deep dive: a
/// `BlockRequest` that cannot get a fair dispatch turn within
/// `DISPATCH_WAIT_BUDGET` (~2s, `handle_block_request_with_credit`'s own
/// constant) must give up and answer `Busy` rather than hang past that
/// budget. A precise millisecond assertion would be fragile against
/// scheduler jitter; this instead asserts a bounded window loose enough to
/// tolerate ordinary jitter but tight enough that it would fail outright if
/// `DISPATCH_WAIT_BUDGET` were, say, 10x too large (20s instead of 2s).
///
/// Forces the wait deterministically the same way
/// `block_request_is_rejected_if_authorization_is_revoked_while_waiting_
/// for_a_dispatch_turn` above does: this test itself holds the one
/// dispatch slot for `("device-b", GROUP)` via the same public
/// `acquire_dispatch_turn` the real session calls -- but here, unlike that
/// test, the slot is never released, so the real request's own wait is
/// guaranteed to run out the clock instead of being granted a turn.
#[tokio::test]
async fn dispatch_wait_budget_timeout_returns_busy_within_a_bounded_window() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let hash = seed_referenced_block(
        &device_a,
        "dispatch-timeout.bin",
        b"content stuck behind a permanently busy dispatch slot",
    );

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1,
    );
    session_a.set_block_serve_engine(engine.clone());

    // Occupy the one dispatch slot for this exact key and never release it.
    let _never_released_dispatch_guard =
        engine.acquire_dispatch_turn("device-b", GROUP, 1).await.unwrap();
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    let started = Instant::now();
    send_block_request(&requester_channel, "dispatch-timeout.bin", hash.clone()).await;

    let reply = tokio::time::timeout(
        Duration::from_secs(6),
        recv_matching_block_reply(&requester_channel, &hash),
    )
    .await
    .expect("the request must resolve, not hang forever, once DISPATCH_WAIT_BUDGET elapses");
    let elapsed = started.elapsed();

    assert!(
        matches!(reply.outcome, Some(proto::block_reply::Outcome::Busy(_))),
        "a request that can never get a dispatch turn must answer Busy once its wait budget \
         elapses, got {:?}",
        reply.outcome
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the Busy reply took {elapsed:?} -- DISPATCH_WAIT_BUDGET is documented as 2s, so this \
         bound (2x that) would fail if a future change grew it by even a modest multiple (it \
         must stay well under FETCH_RESPONSE_TIMEOUT's own 5s deadline, per that constant's own \
         doc comment)"
    );
    assert!(
        elapsed >= Duration::from_millis(1_500),
        "the Busy reply arrived suspiciously fast ({elapsed:?}) for a wait that should run out \
         essentially the entire ~2s DISPATCH_WAIT_BUDGET -- this would fail if the timeout were \
         accidentally applied to the wrong wait, or bypassed entirely"
    );
}

/// Pins invariant 3 from the peer-handler inventory doc's deep dive, the
/// highest-value invariant in this family: `credit_guard` (`ServeCreditGuard`)
/// must be dropped only AFTER the `BlockReply` send actually completes, not
/// before -- see `handle_block_request_with_credit`'s own comment mirroring
/// the "72 concurrent requests" incident this exact ordering exists to
/// prevent a repeat of. A byte-budget window where credit looks free while
/// the bytes are still in flight on the wire would let a burst of new
/// requests over-admit against a budget that hasn't actually been vacated.
///
/// Forces the ordering deterministically by throttling the SERVING side's
/// own upload rate limiter (`PeerSyncSession::set_rate_limiters`, the same
/// public, production seam a daemon uses to enforce a configured transfer
/// cap) down to a rate that turns one block's `upload.acquire` call --
/// which runs strictly BEFORE the reply send and, transitively, strictly
/// before `credit_guard`'s drop -- into a multi-second, deterministic delay
/// window. A second, identically-sized block from the same peer/group is
/// requested mid-window, when the FIRST request's credit reservation
/// (sized to consume the entire per-peer/per-group/global budget on its
/// own) must still be held if the documented ordering holds -- and is
/// asserted `Busy` because of it. A third request, issued only after the
/// first's `Found` reply has actually been observed, is then asserted to
/// succeed, proving the credit was released once that reply completed, not
/// held forever (and not released any earlier either).
#[tokio::test]
async fn credit_guard_is_released_only_after_the_reply_finishes_sending() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    const BLOCK_LEN: usize = 6_000;
    let block_a = seed_referenced_block(&device_a, "credit-a.bin", &vec![0xAAu8; BLOCK_LEN]);
    let block_b = seed_referenced_block(&device_a, "credit-b.bin", &vec![0xBBu8; BLOCK_LEN]);
    let block_c = seed_referenced_block(&device_a, "credit-c.bin", &vec![0xCCu8; BLOCK_LEN]);

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    // Exactly enough budget for ONE of these blocks at a time, on every one
    // of the three CONV-6 budgets `try_admit` checks at once -- so a
    // second, concurrently-requested block of the same size can only be
    // admitted if the first's `ServeCreditGuard` has already released its
    // share. Dispatch/examination capacity is left generous (4): this test
    // is not exercising either of those.
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        BLOCK_LEN as u64,
        BLOCK_LEN as u64,
        BLOCK_LEN as u64,
        4,
    );
    session_a.set_block_serve_engine(engine);
    // Slow enough that acquiring BLOCK_LEN bytes of upload tokens --
    // starting from a fresh bucket, whose initial burst allowance equals
    // the configured rate itself (`TokenBucket::new`'s own doc comment) --
    // takes about (BLOCK_LEN - rate) / rate = (6000 - 2000) / 2000 = 2
    // seconds.
    session_a.set_rate_limiters(Arc::new(RateLimiters::new(2_000, 0)));
    complete_raw_peer_handshake(&requester_channel, &session_a).await;

    let started = Instant::now();
    send_block_request(&requester_channel, "credit-a.bin", block_a.clone()).await;

    // Well inside the ~2s throttled window above, and well after
    // `try_admit` for request A has certainly already run (a synchronous,
    // non-blocking, in-memory check) -- request B's own credit admission
    // must fail here if A's guard is still held, which is exactly what
    // forces this race deterministically rather than probabilistically.
    tokio::time::sleep(Duration::from_millis(500)).await;
    send_block_request(&requester_channel, "credit-b.bin", block_b.clone()).await;

    // The actual oracle below is the SEQUENCE of outcomes (Busy, then
    // Found, then Found once credit is released), not wall-clock deadlines
    // on each step -- an exact per-step timeout here previously raced a
    // real ~3.0s completion (request C's send has no initial burst credit
    // left, unlike A's) against a 3s bound with effectively zero margin.
    // This outer timeout is a watchdog against a genuine hang, not a
    // correctness check; it must stay generous relative to the ~2s
    // throttled-send window baked into the rate limiter above.
    tokio::time::timeout(Duration::from_secs(10), async {
        let reply_b = recv_matching_block_reply(&requester_channel, &block_b).await;
        assert!(
            matches!(reply_b.outcome, Some(proto::block_reply::Outcome::Busy(_))),
            "request B must be denied credit admission while request A's reply is still being \
             sent (within the throttled upload window) -- if this were Found instead, \
             credit_guard was released BEFORE the send it is supposed to guard, got {:?}",
            reply_b.outcome
        );
        assert!(
            started.elapsed() < Duration::from_millis(1_800),
            "request B's Busy reply must arrive well before request A's throttled send finishes \
             (~2s from `started`), proving the two were genuinely concurrent rather than \
             accidentally serialized"
        );

        let reply_a = recv_matching_block_reply(&requester_channel, &block_a).await;
        assert!(
            matches!(reply_a.outcome, Some(proto::block_reply::Outcome::Found(_))),
            "request A itself must still succeed, got {:?}",
            reply_a.outcome
        );

        // Now that A's reply has actually been observed, its credit must
        // already be released -- a fresh, same-sized request must succeed.
        send_block_request(&requester_channel, "credit-c.bin", block_c.clone()).await;
        let reply_c = recv_matching_block_reply(&requester_channel, &block_c).await;
        assert!(
            matches!(reply_c.outcome, Some(proto::block_reply::Outcome::Found(_))),
            "request C must succeed once request A's credit_guard has released its share \
             (observed via A's own reply having already arrived), got {:?}",
            reply_c.outcome
        );
    })
    .await
    .expect("credit-release scenario did not complete");
}

/// Pins invariant 4 from the peer-handler inventory doc's deep dive:
/// `shares_group` is re-checked in `handle_block_request_with_credit`
/// (~5889-5902), not just once in `handle_block_request` (~5708) --
/// already covered end to end by
/// `block_request_is_rejected_if_authorization_is_revoked_while_waiting_
/// for_a_dispatch_turn` above, which forces the exact revoked-while-
/// queued race deterministically via the same `acquire_dispatch_turn`
/// seam this file's other invariant tests use. No separate test added
/// here; this comment exists so the doc's four numbered invariants each
/// have an explicit pointer to their covering test.
///
/// Pins invariant 5: `handle_block_reply` -- the handler that runs on the
/// REQUESTING side when its own outstanding `BlockRequest` is answered --
/// acquires no examination, dispatch, or credit permit of any kind; it
/// only correlates the reply against `pending_block_requests_by_id` and
/// resolves the bytes. Demonstrated by fully saturating the REQUESTING
/// session's own `BlockServeEngine` (the one it would use only if IT were
/// serving inbound requests from someone else) -- its examination-
/// admission pool, its one dispatch slot, and its one byte of credit -- for
/// the whole test, and confirming `fetch_block` still resolves promptly:
/// if `handle_block_reply` touched any of that shared, per-device
/// admission state, this fully starved engine would make it hang or fail.
#[tokio::test]
async fn handle_block_reply_acquires_no_examination_dispatch_or_credit_permit() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let content = b"content fetched while the requester's own engine is fully starved".to_vec();
    let hash = seed_referenced_block(&device_a, "starved-requester.bin", &content);

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session_with_block_serve_engine(
        channel_a,
        &device_a,
        "device-b",
        yadorilink_peer_session::block_serve::BlockServeEngine::new(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            4,
        ),
    );

    // Device-b's OWN serve-side engine (used only if IT were answering
    // inbound requests from someone else), deliberately starved of every
    // permit kind for the whole test.
    let starved_engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(1, 1, 1, 1);
    let session_b = spawn_session_with_block_serve_engine(
        channel_b,
        &device_b,
        "device-a",
        starved_engine.clone(),
    );
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;
    let mut held_examination_permits = Vec::new();
    while let Ok(permit) = starved_engine.try_begin_examination() {
        held_examination_permits.push(permit);
    }
    assert!(!held_examination_permits.is_empty(), "sanity: examination capacity must be positive");
    let _held_dispatch_guard =
        starved_engine.acquire_dispatch_turn("device-a", GROUP, 1).await.unwrap();
    let _held_credit_guard = starved_engine.try_admit("device-a", GROUP, 1).unwrap();

    let fetched = tokio::time::timeout(
        Duration::from_secs(5),
        session_b.fetch_block(GROUP, "starved-requester.bin", &hash),
    )
    .await
    .expect(
        "handle_block_reply must resolve promptly regardless of this session's own (unrelated) \
         serve-side admission state",
    )
    .unwrap();

    assert_eq!(
        fetched.map(|b| b.to_vec()),
        Some(content),
        "the fetch must still succeed with the correct content"
    );
    drop(held_examination_permits);
}

/// a peer that receives one heads announce covering several
/// committed edits reconciles every file in the frontier correctly, end to
/// end (materializes each file with the right content on disk and in the
/// index).
#[tokio::test]
async fn peer_reconciles_every_file_in_an_announced_frontier() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let files = [
        ("one.txt", b"first file content".to_vec()),
        ("two.txt", b"second file, different content".to_vec()),
        ("three.txt", b"third".to_vec()),
    ];
    let mut records = Vec::new();
    for (name, content) in &files {
        let path = device_a.root_path().join(name);
        std::fs::write(&path, content).unwrap();
        records.push(expect_file_changed(
            device_a
                .processor()
                .process_event(
                    GROUP,
                    &device_a.root_path(),
                    &FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified },
                )
                .await
                .unwrap(),
        ));
    }

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;
    // The three edits are already committed to device-a's DAG by process_event
    // above; announcing the head carries the whole frontier to device-b at once.
    let _ = records;

    for (name, content) in &files {
        let replicated_path = device_b.root_path().join(name);
        announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20))
            .await;
        assert_eq!(&std::fs::read(&replicated_path).unwrap(), content);
        let record = device_b.state.file_index_repository().get_file(GROUP, name).unwrap().unwrap();
        assert_eq!(record.size, content.len() as u64);
    }
}

/// A regression guard against recording unfetched content as hydrated:
/// when a peer cannot supply a block for an eagerly-materialized record,
/// `materialize` must leave the path as a retriable `Placeholder` — never a
/// live-but-fileless `Hydrated` row. A `Hydrated` row here would fail
/// `reconstruct_file` on the missing block (orphaning its temp file) and then
/// be demoted by `repair_interrupted_materializations` to empty content,
/// permanently and silently losing the write — catastrophic for a losing
/// conflict copy, whose materialization is the only preservation of that
/// content. This mirrors `hydrate_file_with_timeout`'s existing `all_present`
/// handling on the eager path.
#[tokio::test]
async fn eager_materialize_leaves_placeholder_when_peer_cannot_supply_a_block() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // device-a advertises a record but never stores its block bytes, so a
    // block request for it is answered `not_found` (referenced-but-absent) —
    // exactly what a peer does mid directory-rename/move churn when it cannot
    // currently serve a losing conflict copy's content.
    let content = b"the losing conflict copy content that must not be silently lost".to_vec();
    let block_hash = sha256_bytes(&content);
    let record = yadorilink_replica_domain::file::FileRecord {
        path: "loser.bin".into(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![yadorilink_replica_domain::file::BlockInfo {
            hash: block_hash.clone(),
            offset: 0,
            size: content.len() as u32,
        }],
        deleted: false,
    };
    // Commit a signed Create referencing the block WITHOUT storing its bytes,
    // so device-b's later block request is answered not_found.
    // `upsert_file_emitting_change` writes the index row and commits the change
    // in one transaction — the same primitive the local-change producer uses.
    let absent_version = yadorilink_replica_domain::file::FileVersion::new(
        vec![yadorilink_replica_domain::file::VersionBlock {
            hash: yadorilink_replica_domain::ids::BlockHash(block_hash.clone()),
            size: content.len() as u32,
        }],
        content.len() as u64,
        yadorilink_replica_domain::file::FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: yadorilink_replica_domain::file::RecordKind::File,
        },
    );
    let create_op = yadorilink_replica_domain::change::Op::Put {
        path: yadorilink_replica_domain::ids::SyncPath("loser.bin".into()),
        version: absent_version.version_hash,
        origin: yadorilink_replica_domain::change::PutOrigin::Direct,
    };
    device_a
        .state
        .upsert_file_emitting_change(
            GROUP,
            &record,
            "device-a",
            yadorilink_replica_domain::session_state::ChangeContent {
                ops: vec![create_op],
                versions: std::slice::from_ref(&absent_version),
            },
            None,
            yadorilink_daemon::replica_coordinator::ReplicaChangeEmission {
                emitter: &device_a.emitter(),
                permit: &RootCommitPermit::for_tests(),
            },
        )
        .unwrap();
    // Intentionally NOT `device_a.store.put(&content)` — the block is absent,
    // so device-a answers device-b's block request `not_found`.

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // device-b eagerly materializes, cannot fetch the block, and (with the
    // fix) records a retriable placeholder instead of a Hydrated row.
    announce_until(
        &session_a,
        GROUP,
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "loser.bin")
                .unwrap()
                == Some(MaterializationState::Placeholder)
        },
        Duration::from_secs(25),
    )
    .await;

    // (a) Placeholder, never Hydrated.
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "loser.bin")
            .unwrap(),
        Some(MaterializationState::Placeholder),
        "an eager materialize whose block the peer can't supply must leave a retriable \
         placeholder, not a (fileless) Hydrated row",
    );

    // (b) No orphaned `.yadorilink-tmp.*` file left under the sync root.
    fn collect_temp_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    collect_temp_files(&p, out);
                } else if p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(".yadorilink-tmp."))
                {
                    out.push(p);
                }
            }
        }
    }
    let mut temp_files = Vec::new();
    collect_temp_files(&device_b.root_path(), &mut temp_files);
    assert!(
        temp_files.is_empty(),
        "an incomplete eager fetch must leave no orphaned temp file, found {temp_files:?}"
    );

    // (c) The self-healing sweep has nothing to repair — the row is a
    // Placeholder, not a fileless Hydrated row, so it is never demoted (which
    // is what would have destroyed the pending write).
    let report =
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            device_b.state.as_ref(),
            device_b.store.as_ref(),
            &device_b.root_path(),
            GROUP,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(
        report.demoted_to_placeholder.is_empty() && report.reconstructed.is_empty(),
        "self-healing sweep must have nothing to repair for a retriable placeholder, got \
         demoted={:?} reconstructed={:?}",
        report.demoted_to_placeholder,
        report.reconstructed,
    );

    // (d) Once the peer can serve the block, the real content materializes —
    // the write was preserved, not lost.
    device_a.store.put(content.as_slice()).unwrap();
    // See the identical comment in
    // `block_request_is_refused_after_mid_session_group_revocation` above.
    device_a
        .state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&block_hash))
        .unwrap();
    session_b.hydrate_file(GROUP, "loser.bin").await.unwrap();
    let out = device_b.root_path().join("loser.bin");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        content,
        "the real content must materialize once the peer can serve the block"
    );
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "loser.bin")
            .unwrap(),
        Some(MaterializationState::Hydrated),
    );
}

/// A pre-existing symlink at an intermediate path component inside the
/// sync root must not let a peer-advertised file's content land outside
/// the sync root. `is_safe_relative_path` only rejects `..`/absolute path
/// *strings* — it cannot see a symlink already planted on disk, which is
/// exactly the precondition for this TOCTOU to be exploitable at all (a
/// locally pre-planted symlink or a racing local actor, not something a
/// remote peer alone can create). `verify_write_target`'s
/// canonicalize-and-`starts_with` check is the defense-in-depth this test
/// confirms actually closes the gap.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_intermediate_component_does_not_let_a_write_escape_the_sync_root() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // A directory *outside* device_a's sync root that a symlink inside the
    // root points to — the locally pre-planted symlink this scenario requires.
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), device_a.root_path().join("evil_link")).unwrap();

    // device_b has an entirely ordinary file at "evil_link/pwned.txt" — on
    // device_b's own side "evil_link" is just a normal subdirectory;
    // nothing about creating and syncing it is malicious by itself. The
    // attack lives entirely in what "evil_link" already is on device_a's
    // side.
    let dir_b = device_b.root_path().join("evil_link");
    std::fs::create_dir_all(&dir_b).unwrap();
    let path_b = dir_b.join("pwned.txt");
    std::fs::write(&path_b, b"attacker-controlled content").unwrap();
    device_b
        .processor()
        .process_event(
            GROUP,
            &device_b.root_path(),
            &FsChangeEvent { path: path_b, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Announce device-b's evil_link/pwned.txt commit and wait until device-a
    // has ADMITTED it into its index — the point at which it tries to
    // materialize. Admission is a DAG/auth decision; the path-escape defense
    // lives in materialization, which must fail closed.
    announce_until(
        &session_b,
        GROUP,
        || {
            device_a
                .state
                .file_index_repository()
                .get_file(GROUP, "evil_link/pwned.txt")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
    )
    .await;
    // Give the fail-closed materialize attempt a moment to run its course.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !outside.path().join("pwned.txt").exists(),
        "the write must not have escaped the sync root through the symlink"
    );
    assert!(
        !device_a.root_path().join("evil_link/pwned.txt").exists(),
        "no file should be visible at the naive joined path from device_a's own perspective either"
    );

    // The session must have survived the failed materialize rather than
    // wedging or crashing: an ordinary, unrelated file syncs normally
    // right after, on the same connection.
    std::fs::write(device_b.root_path().join("ordinary.txt"), b"fine").unwrap();
    let _record = expect_file_changed(
        device_b
            .processor()
            .process_event(
                GROUP,
                &device_b.root_path(),
                &FsChangeEvent {
                    path: device_b.root_path().join("ordinary.txt"),
                    kind: FsChangeKind::CreatedOrModified,
                },
            )
            .await
            .unwrap(),
    );
    announce_until(
        &session_b,
        GROUP,
        || device_a.root_path().join("ordinary.txt").exists(),
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(std::fs::read(device_a.root_path().join("ordinary.txt")).unwrap(), b"fine");
}

/// A file device A already synced to device B becomes newly ignored on
/// device A (not the same as a deletion). The rescan must drop it from
/// A's own local index without producing a tombstone, leave A's on-disk
/// file untouched, and — the part this test actually exercises over a
/// real peer connection — device B's already-synced copy must be
/// completely unaffected: no tombstone ever reaches it, because the
/// rescan never produced one to begin with.
#[tokio::test]
async fn newly_ignored_file_drops_from_local_index_without_tombstoning_the_peers_copy() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("cache.tmp");
    std::fs::write(&file_path, b"scratch data").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join("cache.tmp");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;
    assert!(device_a.state.file_index_repository().get_file(GROUP, "cache.tmp").unwrap().is_some());

    // Device A alone decides to ignore "*.tmp" — device-local and unsynced
    // ; device B's own config is untouched.
    std::fs::write(device_a.root_path().join(".yadorilinkignore"), "*.tmp\n").unwrap();
    let ignore_set =
        yadorilink_root_authority::ignore_patterns::EffectiveIgnoreSet::load_for_link_root(
            device_a.root_path(),
        )
        .unwrap();
    let changed = device_a
        .processor()
        .scan_existing_files_with_ignore(GROUP, &device_a.root_path(), &ignore_set)
        .unwrap();

    // A's own index no longer carries the now-ignored file...
    assert!(device_a.state.file_index_repository().get_file(GROUP, "cache.tmp").unwrap().is_none());
    // ...but the on-disk file itself is left completely untouched — newly
    // ignored is not deleted.
    assert!(device_a.root_path().join("cache.tmp").exists());
    // ...and the rescan produced no record for it at all (no tombstone to
    // even broadcast), the crux of "drop, don't delete" behavior.
    assert!(!changed.iter().any(|r| r.path == "cache.tmp"));

    // The rescan returned nothing to broadcast (asserted above): dropping a
    // now-ignored path is a plain local index removal that emits no change into
    // the DAG, so nothing propagates. Confirm device B — which never touched its
    // own ignore config — keeps its copy untouched.
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        replicated_path.exists(),
        "peer's existing copy must be untouched by the other device choosing to ignore the path locally"
    );
    let record_b =
        device_b.state.file_index_repository().get_file(GROUP, "cache.tmp").unwrap().unwrap();
    assert!(
        !record_b.deleted,
        "no tombstone must reach the peer for a newly-ignored (not deleted) file"
    );
}

/// An incoming change for a path matching this device's own ignore patterns
/// must never be projected onto this device — neither materialized to disk nor
/// added to the index — see `peer_session.rs`'s `is_locally_ignored` and
/// `reconcile_group_paths`. Device A (the sender) does not ignore the path
/// itself — only device B does, via its own `.yadorilinkignore` (device-local,
/// unsynced) — so this exercises the filter purely from the receiving side.
///
/// Device B MUST get a change authenticator, and this test MUST assert the DAG
/// is negotiated. Both are load-bearing, not ceremony: without an
/// authenticator `handle_change_batch` drops every incoming change unverified
/// before it reaches the projection path, so the ignore assertions below would
/// pass vacuously — every file would be dropped for the wrong reason. This test
/// passed against a build that materialized `secret.log` on the change-DAG path
/// with no ignore check whatsoever. Any future edit that drops the
/// authenticator or stops the pair negotiating the DAG must fail
/// `wait_dag_negotiated` loudly rather than go on claiming coverage it does not
/// have.
///
/// On relaying — a deliberate, load-bearing inversion. This test used to also
/// assert the ignored record was never *forwarded* onward, by draining a
/// `new_with_forwarding` channel. That property belonged to the legacy record
/// wire, whose engine drove `forward_tx` from incoming peer records; the change
/// DAG never fed that channel from the receive path at all. It is not re-asserted
/// here because on the DAG the opposite is required: `reconcile_group_paths`
/// skips an ignored path as a *success*, so the change still marks applied and
/// this device's heads still advance past it. That is the design, not an
/// oversight — the ignore set is device-local, so a third device that does NOT
/// ignore the path must still be able to receive the change *through* this one
/// (store-and-forward). A device that dropped an ignored path's change from its
/// DAG would censor the mesh with its own local config and strand that third
/// device; one that recorded the skip as a *failure* would hold the change at
/// `applied = 0` forever and re-drive it every reprojection cycle. So the
/// assertions below pin both halves: the bytes never land here, and the change
/// still retires as applied so it relays onward.
#[tokio::test]
async fn incoming_change_for_a_locally_ignored_path_is_not_projected_but_still_relayed() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Device B ignores "secret.log"; device A has no such pattern at all.
    std::fs::write(device_b.root_path().join(".yadorilinkignore"), "secret.log\n").unwrap();

    // Device A has both a path that's ignored-on-B and an ordinary file
    // that should sync normally, committed into the same DAG.
    let mut secret_change = None;
    let mut notes_change = None;
    for (name, content) in
        [("secret.log", b"do not sync me".to_vec()), ("notes.txt", b"keep me".to_vec())]
    {
        let file_path = device_a.root_path().join(name);
        std::fs::write(&file_path, &content).unwrap();
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
        // The single head device A's group now sits at is exactly the change
        // this commit just emitted (the emitter auto-parents from the current
        // heads, so each commit descends from the last and is the sole head).
        // Captured per-commit because naming the ignored path's *change* is the
        // only way to assert, below, that device B stored it rather than
        // dropping it.
        let heads = device_a.state.sqlite().dag_group_heads(GROUP).unwrap();
        assert_eq!(heads.len(), 1, "a local commit leaves device A's group on a single head");
        match name {
            "secret.log" => secret_change = Some(heads[0]),
            _ => notes_change = Some(heads[0]),
        }
    }
    let secret_change = secret_change.expect("secret.log's change hash");
    let notes_change = notes_change.expect("notes.txt's change hash");

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    // `EffectiveIgnoreSet` is loaded from `device_b`'s root at construction
    // time (mirroring `canonical_sync_roots`), so the `.yadorilinkignore`
    // written above must exist before this call. `spawn_session` wires the
    // change authenticator that makes device B admit device A's signed changes.
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Assert the pair really is on the change DAG, so this test cannot quietly
    // degrade into proving nothing again.
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // The ordinary (non-ignored) file replicating is the signal that device
    // A's announced frontier — one batch covering both changes — has already
    // been fully reconciled, so by this point the ignored change has also
    // already been decided one way or the other.
    let ordinary_path = device_b.root_path().join("notes.txt");
    announce_until(&session_a, GROUP, || ordinary_path.exists(), Duration::from_secs(20)).await;

    assert!(
        !device_b.root_path().join("secret.log").exists(),
        "an incoming change for a locally-ignored path must never be materialized to disk"
    );
    assert!(
        device_b.state.file_index_repository().get_file(GROUP, "secret.log").unwrap().is_none(),
        "an incoming change for a locally-ignored path must never be added to the local index"
    );

    // The relay half: ignoring a path locally must not remove its change from
    // this device's DAG, or a third device that does not ignore `secret.log`
    // could never receive it through device B.
    assert!(
        device_b.state.change_history_repository().dag_has_change(&secret_change).unwrap(),
        "the ignored path's change must still be admitted to this device's DAG so it can \
         still relay onward to a device that does not ignore the path"
    );
    // ... and the skip must retire the change as applied, not park it as a
    // retryable failure. Heads advancing past it is what tells the peer "we
    // already hold this", so it is never re-sent.
    assert!(
        device_b
            .state
            .change_history_repository()
            .dag_list_unapplied_changes(GROUP)
            .unwrap()
            .is_empty(),
        "an ignored path's change must retire as applied — recording the skip as a failure \
         would hold it unapplied forever and re-drive it every reprojection cycle"
    );
    assert_eq!(
        device_b.state.sqlite().dag_group_heads(GROUP).unwrap(),
        vec![notes_change],
        "device B's frontier must advance to device A's head across both changes, ignored \
         path included"
    );
}

/// A conflict on a locally-ignored path must not materialize a conflict copy.
///
/// This is the case the ignore filter cannot catch by name. A conflict copy
/// carries the losing content to a *derived* path that embeds a timestamp,
/// device id and version hash — `secret.log` becomes
/// `secret (conflicted copy, …, device-a, ….log)` — which the literal rule
/// `secret.log` does not match. So a per-path ignore check at the point of
/// materialization is not sufficient on its own: by then the copy path exists
/// and reads as an ordinary, un-ignored path, and the excluded content lands on
/// disk under a name the user never wrote a rule for. The check has to happen
/// where conflict-copy paths are *derived* (`reconcile_group_paths`'s fixpoint),
/// so an ignored path yields no copies at all.
///
/// The scenario is the realistic one, not a contrived one: B synced the file,
/// then the user added it to B's `.yadorilinkignore`, and A goes on editing it.
/// B's pre-existing change is already in the DAG, so B's head and A's head are
/// genuinely concurrent and a conflict is resolved on both sides.
#[tokio::test]
async fn conflict_on_a_locally_ignored_path_materializes_no_conflict_copy() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Concurrent creates of the same path on both devices, committed while the
    // path is still ordinary on B — this is B's pre-existing change, the live
    // head that A's edit later conflicts against. The rule is added afterwards
    // (below), which is both the realistic order and the required one:
    // `process_event` loads `.yadorilinkignore` from the root itself, so a rule
    // written first would suppress B's local change and leave nothing to
    // conflict with.
    for (device, content) in
        [(&device_a, b"edited on A".to_vec()), (&device_b, b"edited on B, longer".to_vec())]
    {
        let file_path = device.root_path().join("secret.log");
        std::fs::write(&file_path, &content).unwrap();
        device
            .processor()
            .process_event(
                GROUP,
                &device.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
    }

    // Sanity check: a genuine conflict, not a sequential edit — otherwise no
    // conflict copy would be derived on either side and this test would prove
    // nothing.
    // Causality is DAG ancestry now: the two edits are concurrent exactly when
    // each device authored its own change for the path and neither has yet
    // admitted the other's, so neither can be the other's ancestor.
    let author_a = device_a
        .state
        .file_index_repository()
        .get_authoring_change_hash(GROUP, "secret.log")
        .unwrap()
        .expect("A authored");
    let author_b = device_b
        .state
        .file_index_repository()
        .get_authoring_change_hash(GROUP, "secret.log")
        .unwrap()
        .expect("B authored");
    assert_ne!(author_a, author_b, "the two devices must have authored distinct changes");
    assert!(
        device_a.state.sqlite().dag_get_change(&author_b).unwrap().is_none(),
        "A must not yet know B's change"
    );
    assert!(
        device_b.state.sqlite().dag_get_change(&author_a).unwrap().is_none(),
        "B must not yet know A's change"
    );

    // A's change for the path, captured before connecting (it is A's only
    // change, so A's frontier is exactly it). Waiting for *this hash* to land in
    // B's DAG is the only sound way to know B has actually seen A's edit — see
    // the settle loop below.
    let a_heads = device_a.state.sqlite().dag_group_heads(GROUP).unwrap();
    assert_eq!(a_heads.len(), 1, "device A should have exactly one change to propagate");
    let a_change = a_heads[0];

    // Now the user adds the rule on B only — device-local and unsynced, so A
    // neither knows nor cares. Written before B's session is constructed because
    // the session snapshots its ignore set there.
    std::fs::write(device_b.root_path().join(".yadorilinkignore"), "secret.log\n").unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Settle on two positive signals, never a sleep — an absence assertion is
    // only worth anything once the thing that would have caused the presence has
    // provably happened.
    //
    // 1. B's DAG holds A's change. This is the load-bearing one, and it must be
    //    asserted on B: A materializing its own copy proves only that A received
    //    B's change, which says nothing about the reverse direction (the two
    //    exchanges are independent flows). An earlier draft of this test settled
    //    on A's copy alone and passed against a build with the fixpoint check
    //    removed, purely by winning a race.
    // 2. A (which does not ignore the path) has materialized a conflict copy.
    //    This is the vacuity guard: it proves the scenario really does drive
    //    conflict-copy derivation, so B's clean root below means the filter
    //    worked rather than that no copy was ever on offer.
    let a_has_copy = || {
        std::fs::read_dir(device_a.root_path())
            .unwrap()
            .any(|e| is_final_conflict_copy(&e.unwrap().file_name().to_string_lossy()))
    };
    let b_has_a_change =
        || device_b.state.change_history_repository().dag_has_change(&a_change).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while !(a_has_copy() && b_has_a_change()) && tokio::time::Instant::now() < deadline {
        let _ = session_a.announce_local_commit(GROUP).await;
        let _ = session_b.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(a_has_copy(), "sanity check: the non-ignoring device must resolve the conflict");
    assert!(b_has_a_change(), "device B never received A's change; nothing was actually tested");

    // The ignored path's change must still RETIRE. Skipping a projection is a
    // decision, not a failure, so the change is marked applied and B's heads
    // advance past it — that is what stops the peer re-announcing it forever and
    // the reprojection backstop re-driving it every cycle. A change parked at
    // `applied = 0` here would mean the fix traded a privacy defect for an
    // endless churn loop.
    assert!(
        device_b
            .state
            .change_history_repository()
            .dag_list_unapplied_changes(GROUP)
            .unwrap()
            .is_empty(),
        "an ignored path's change must still be marked applied, or the DAG never settles"
    );

    let names_b: Vec<String> = std::fs::read_dir(device_b.root_path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        !names_b.iter().any(|n| is_final_conflict_copy(n)),
        "a conflict copy of a locally-ignored path must never be materialized — its derived \
         name escapes the very pattern that excluded it, got {names_b:?}"
    );
    // The index must agree with the disk: no row for a copy that was never written.
    let indexed_copy = device_b
        .state
        .file_index_repository()
        .list_files(GROUP)
        .unwrap()
        .into_iter()
        .any(|r| is_final_conflict_copy(&r.path));
    assert!(!indexed_copy, "a conflict copy of a locally-ignored path must never be indexed");

    // The ignored path's own bytes are B's alone: the peer's winning content
    // must not overwrite them, and B's pre-existing copy must not be evicted
    // just because a rule now excludes it.
    assert_eq!(
        std::fs::read(device_b.root_path().join("secret.log")).unwrap(),
        b"edited on B, longer",
        "a peer must not overwrite the contents of a path this device ignores"
    );
}

/// Tombstoning a symlink record must
/// remove the on-disk symlink itself, and must never touch — let alone
/// delete — whatever real file the link happens to point at. Verified
/// against an actual target file living entirely outside device_b's sync
/// root (a separate tempdir, never itself part of what's being
/// tombstoned), so a regression here (e.g. accidentally resolving/
/// following the link before removing it) would show up as real data
/// loss in the assertions below, not just a passing-by-accident check.
///
/// `device_b`'s pre-tombstone state (an already-materialized symlink,
/// `record_kind = Symlink`, a recorded target) is set up directly against
/// `ReplicaCoordinator` rather than produced by a live scan/watch or a genuine
/// wire-transmitted symlink record — see `peer_session.rs`'s
/// `materialize_symlink_at` doc comment for why: today's wire schema
/// (`proto::FileInfo`, section 5 of this change, not yet implemented)
/// carries no `record_kind`/`symlink_target` field, so a peer cannot yet
/// actually advertise "this is a symlink" over the wire. The tombstone
/// itself, by contrast, is entirely real and wire-driven: `deleted` is an
/// ordinary, already-supported `FileRecord` field, sent via a real
/// `PeerSyncSession` full-index exchange like any other record.
#[cfg(unix)]
#[tokio::test]
async fn symlink_tombstone_removes_link_but_never_its_target() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // A real, valuable file living entirely outside device_b's sync root.
    let target_dir = tempfile::tempdir().unwrap();
    let target_path = target_dir.path().join("precious.txt");
    std::fs::write(&target_path, b"do not delete me").unwrap();

    let symlink_record = yadorilink_replica_domain::file::FileRecord {
        path: "link.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    device_b
        .state
        .file_index_repository()
        .upsert_file(GROUP, &symlink_record, &RootCommitPermit::for_tests())
        .unwrap();
    device_b
        .state
        .file_index_repository()
        .set_record_kind(
            GROUP,
            "link.txt",
            yadorilink_replica_domain::file::RecordKind::Symlink,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .file_index_repository()
        .set_symlink_target(GROUP, "link.txt", Some(target_path.as_os_str().as_encoded_bytes()))
        .unwrap();
    std::os::unix::fs::symlink(&target_path, device_b.root_path().join("link.txt")).unwrap();
    assert!(
        std::fs::symlink_metadata(device_b.root_path().join("link.txt"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "sanity check: the pre-tombstone state really is a symlink on disk"
    );

    // device_a commits a tombstone for the same path into the change DAG;
    // device_b, which holds link.txt, adopts it over the wire and removes the
    // link. (deleted is an ordinary FileRecord field the DAG's Delete op
    // carries, unlike the symlink kind/target set up device-locally above.)
    device_a
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "link.txt",
            "device-a",
            0,
            &device_a.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    announce_until(
        &session_a,
        GROUP,
        || !device_b.root_path().join("link.txt").exists(),
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(
        std::fs::read(&target_path).unwrap(),
        b"do not delete me",
        "the tombstone must never touch the symlink's target, only the link itself"
    );
    let record =
        device_b.state.file_index_repository().get_file(GROUP, "link.txt").unwrap().unwrap();
    assert!(record.deleted, "the index must agree the record is now a tombstone");
}

/// A tombstone whose `record.path` names a file behind an INTERMEDIATE
/// directory symlink must not delete whatever the symlink actually points
/// at, even though `record.path` itself is lexically safe (no `..`, not
/// absolute). `remove_file` on `sync_root/external/victim.txt` follows the
/// `external` symlink exactly as `create`/`rename` would; the ordinary
/// write path already guards against this via `verify_write_target`
/// (see `peer_session.rs`'s doc comment on it), but the tombstone branch
/// used to call `remove_file` directly with no such check. `external`
/// points at a directory living entirely outside device_b's sync root, and
/// the assertion is against the REAL file living there, so a regression
/// (the guard silently not applying to deletes) would show up as real data
/// loss, not just a passing-by-accident check.
#[cfg(unix)]
#[tokio::test]
async fn tombstone_must_not_delete_through_an_intermediate_directory_symlink() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // A real, valuable file living entirely outside device_b's sync root --
    // e.g. what an attacker-controlled tombstone for "external/victim.txt"
    // would try to reach.
    let outside_dir = tempfile::tempdir().unwrap();
    let victim_path = outside_dir.path().join("victim.txt");
    std::fs::write(&victim_path, b"do not delete me").unwrap();

    // An intermediate directory symlink inside device_b's sync root,
    // redirecting "external/*" to the outside directory.
    std::os::unix::fs::symlink(outside_dir.path(), device_b.root_path().join("external")).unwrap();

    let record = yadorilink_replica_domain::file::FileRecord {
        path: "external/victim.txt".into(),
        size: 17,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    device_b
        .state
        .file_index_repository()
        .upsert_file(GROUP, &record, &RootCommitPermit::for_tests())
        .unwrap();

    // device_a commits a tombstone for the same logical path; device_b
    // adopts it over the wire.
    device_a
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "external/victim.txt",
            "device-a",
            0,
            &device_a.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // The fixed behavior refuses the delete (verify_delete_target detects
    // the escape), so the record never settles as `deleted` in the index --
    // unlike the ordinary tombstone test above, this can't wait on that
    // becoming true. Give plenty of time (and a second announce) for the
    // change to arrive and, if the guard were missing, be applied.
    let _ = session_a.announce_local_commit(GROUP).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = session_a.announce_local_commit(GROUP).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        std::fs::read(&victim_path).unwrap(),
        b"do not delete me",
        "a tombstone must never delete through an intermediate directory symlink out of the \
         sync root"
    );
}

/// A held file's held state must clear
/// once its record is tombstoned, rather than leaving an orphaned
/// `held_reason`/`held_since_unix_nanos` entry with no corresponding live
/// index record. Driven by a real, wire-transmitted tombstone (`deleted`
/// is an ordinary already-supported `FileRecord` field) through an actual
/// two-peer `PeerSyncSession` exchange — the held-file setup itself is
/// device-local index state (`ReplicaCoordinator::set_held`), the same as it would
/// be from a real case-fold-collision/invalid-name detection (section 4,
/// not yet implemented).
#[tokio::test]
async fn held_file_tombstone_clears_held_state() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let held_record = yadorilink_replica_domain::file::FileRecord {
        path: "A.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    device_b
        .state
        .file_index_repository()
        .upsert_file(GROUP, &held_record, &RootCommitPermit::for_tests())
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_held(GROUP, "A.txt", "case_collision", 1_000)
        .unwrap();
    assert!(
        device_b
            .state
            .materialization_state_repository()
            .get_held_state(GROUP, "A.txt")
            .unwrap()
            .is_some(),
        "sanity check: the file really is held before the tombstone arrives"
    );

    // device_a commits a tombstone for A.txt into the change DAG; device_b
    // adopts it over the wire. (deleted is an ordinary FileRecord field the
    // Delete op carries; the held state was set up device-locally above.)
    device_a
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "A.txt",
            "device-a",
            0,
            &device_a.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    announce_until(
        &session_a,
        GROUP,
        || matches!(device_b.state.file_index_repository().get_file(GROUP, "A.txt"), Ok(Some(r)) if r.deleted),
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(
        device_b.state.materialization_state_repository().get_held_state(GROUP, "A.txt").unwrap(),
        None,
        "a tombstoned file must not leave an orphaned held entry"
    );
}

/// A real, wire-driven two-peer
/// scenario — device A's "Photo.jpg" fully materializes on device B
/// first; only afterward does A send a second, real-content record,
/// "photo.jpg", differing only in case. Device B's sync root (an ordinary
/// tempdir, case-insensitive on this suite's actual dev/CI platforms) has
/// a genuine case-fold collision: the *second*-arriving record
/// must be held (short-circuit ahead of the atomic write) —
/// never written to disk under its own name or any other — while the
/// first, already-materialized file is left completely
/// untouched.
#[tokio::test]
async fn case_fold_collision_holds_the_second_arriving_file_without_touching_the_first() {
    let device_b = Device::new("device-b");
    // The whole scenario only applies on a case-insensitive sync root
    // (see hazard_reason_for_policy, which only even checks for a
    // case-fold collision when hazard::is_case_insensitive_filesystem
    // says so) -- skip outright on a genuinely case-sensitive filesystem
    // (e.g. Linux ext4) rather than waiting out this test's own timeout
    // for a hazard that correctly cannot occur there.
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&device_b.root_path()) {
        eprintln!("skipping: {} is case-sensitive here", device_b.root_path().display());
        return;
    }

    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    // First file, via real local scanning on device A, so it carries a
    // genuine, block-store-backed content chain end to end.
    let first_path = device_a.root_path().join("Photo.jpg");
    std::fs::write(&first_path, b"original photo bytes").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: first_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let first_replicated = device_b.root_path().join("Photo.jpg");
    announce_until(&session_a, GROUP, || first_replicated.exists(), Duration::from_secs(20)).await;
    assert_eq!(std::fs::read(&first_replicated).unwrap(), b"original photo bytes");

    // Second file, differing only in case — committed as a signed DAG Create
    // (block stored so device B can fetch it) so this exercises exactly "a
    // second record for a case-fold-colliding path arrives", regardless of
    // device A's own OS.
    let second_bytes = b"a completely different photo";
    device_a.producer().commit_create(GROUP, "photo.jpg", second_bytes, 0);

    announce_until(
        &session_a,
        GROUP,
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
    )
    .await;

    let held = device_b
        .state
        .materialization_state_repository()
        .get_held_state(GROUP, "photo.jpg")
        .unwrap()
        .unwrap();
    assert!(held.reason.starts_with("case_collision"), "unexpected reason: {}", held.reason);

    // A held record still keeps its own index row.
    let stored =
        device_b.state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().unwrap();
    assert!(!stored.deleted);
    assert_eq!(stored.size, second_bytes.len() as u64);

    // (the design): the actual regression assertion — device B's
    // sync root must contain *exactly* the one, original, non-hazardous
    // file. No `photo.jpg`, no numbered/suffixed variant of either name
    // (`Photo (1).jpg`, `photo_2.jpg`,...) — nothing beyond what a
    // completely ordinary, uncontested sync would have produced.
    let mut entries: Vec<String> = std::fs::read_dir(device_b.root_path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME)
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["Photo.jpg".to_string()],
        "a name hazard must never produce a written file under any name other than the \
         original — this crate implements no automatic rename/escape path"
    );
    assert_eq!(
        std::fs::read(&first_replicated).unwrap(),
        b"original photo bytes",
        "the first, already-materialized file must be completely untouched by the second \
         record's collision"
    );
}

/// A pair differing in BOTH case AND Unicode normalization form at once
/// (`"Café.txt"`, composed é, vs `"café.txt"`, decomposed é) escapes
/// `case_fold_collision` and `normalization_collision` independently (each
/// checks only one axis), but collides to one physical file on a volume
/// that is simultaneously case-insensitive AND normalization-insensitive
/// — the macOS default (both HFS+ and APFS). See
/// `hazard::case_and_normalization_collision`'s doc comment for the
/// reasoning; this is the same scenario as the single-axis test above,
/// through the real wire-driven `materialize` path, for the combined axis.
#[tokio::test]
async fn combined_case_and_normalization_collision_holds_the_second_arriving_file() {
    let device_b = Device::new("device-b");
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&device_b.root_path())
        || !yadorilink_peer_session::hazard::is_normalization_insensitive_filesystem(
            &device_b.root_path(),
        )
    {
        eprintln!(
            "skipping: {} is not both case- and normalization-insensitive here",
            device_b.root_path().display()
        );
        return;
    }

    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    // First file: "Café.txt" (capital C, composed é), via real local
    // scanning on device A.
    let first_path = device_a.root_path().join("Caf\u{e9}.txt");
    std::fs::write(&first_path, b"original cafe bytes").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: first_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let first_replicated = device_b.root_path().join("Caf\u{e9}.txt");
    announce_until(&session_a, GROUP, || first_replicated.exists(), Duration::from_secs(20)).await;
    assert_eq!(std::fs::read(&first_replicated).unwrap(), b"original cafe bytes");

    // Second file: "cafe\u{301}.txt" -- lowercase c, DECOMPOSED é. Differs
    // from the first in both case and normalization form at once.
    let second_path = "cafe\u{301}.txt";
    let second_bytes = b"a completely different cafe";
    device_a.producer().commit_create(GROUP, second_path, second_bytes, 0);

    announce_until(
        &session_a,
        GROUP,
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_held_state(GROUP, second_path)
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
    )
    .await;

    let held = device_b
        .state
        .materialization_state_repository()
        .get_held_state(GROUP, second_path)
        .unwrap()
        .unwrap();
    assert!(
        held.reason.starts_with("case_and_normalization_collision"),
        "unexpected reason: {}",
        held.reason
    );

    let mut entries: Vec<String> = std::fs::read_dir(device_b.root_path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME)
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["Caf\u{e9}.txt".to_string()],
        "a combined-axis hazard must never produce a written file under any name other than the \
         original"
    );
    assert_eq!(
        std::fs::read(&first_replicated).unwrap(),
        b"original cafe bytes",
        "the first, already-materialized file must be completely untouched by the second \
         record's collision"
    );
}

/// A TOMBSTONE for a case-fold-colliding path must be held, exactly like a
/// non-delete record with the same collision — not dispatched straight to
/// `remove_file`, which on a case-insensitive filesystem physically deletes
/// whatever sibling the index/disk actually has. "Photo.jpg" is
/// materialized first; a tombstone arrives for "photo.jpg" (different
/// case, same physical file on this filesystem). The correct outcome is
/// the same as the create-collision case above: the tombstone is held, and
/// "Photo.jpg" is left completely untouched on disk.
#[tokio::test]
async fn tombstone_of_a_case_fold_colliding_path_holds_rather_than_deletes_the_sibling() {
    let device_b = Device::new("device-b");
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&device_b.root_path()) {
        eprintln!("skipping: {} is case-sensitive here", device_b.root_path().display());
        return;
    }

    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    // "Photo.jpg" already materialized on device_b -- both indexed and
    // physically present, as an ordinary prior sync would leave it.
    let first_path = device_b.root_path().join("Photo.jpg");
    std::fs::write(&first_path, b"original photo bytes").unwrap();
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "Photo.jpg".into(),
                size: b"original photo bytes".len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // device_b also already tracks "photo.jpg" itself (e.g. from a prior,
    // now-tombstoned sync from a third device) -- reconcile only dispatches
    // a record to `materialize` when the local index already has some
    // entry for that exact path, so a genuinely first-ever-seen path with
    // no local history at all isn't the shape that reaches the hazard
    // check being tested here.
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "photo.jpg".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // device_a commits a tombstone for the colliding-but-not-identical
    // "photo.jpg" into the change DAG; device_b adopts it over the wire.
    device_a
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "photo.jpg",
            "device-a",
            0,
            &device_a.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    announce_until(
        &session_a,
        GROUP,
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
    )
    .await;

    let held = device_b
        .state
        .materialization_state_repository()
        .get_held_state(GROUP, "photo.jpg")
        .unwrap()
        .unwrap();
    assert!(held.reason.starts_with("case_collision"), "unexpected reason: {}", held.reason);

    assert_eq!(
        std::fs::read(&first_path).unwrap(),
        b"original photo bytes",
        "a colliding tombstone must never physically delete the sibling it collides with"
    );
}

/// A hazardous tombstone targeting the path that is ITSELF the live,
/// materialized file must not corrupt that path's own index row. Unlike
/// the sibling-targeted case above (where the tombstoned path has no file
/// on disk to begin with), holding a tombstone for "Photo.jpg" -- which
/// really is live on disk -- must not adopt the incoming record's
/// `deleted=true` over "Photo.jpg"'s own row: that would leave the index
/// saying "Photo.jpg" is deleted while the file is still physically
/// present, exactly the divergence a later local scan reads as a
/// brand-new local edit and resurrects/re-propagates.
#[tokio::test]
async fn tombstone_of_the_live_file_itself_does_not_corrupt_its_own_index_row_when_held() {
    let device_b = Device::new("device-b");
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&device_b.root_path()) {
        eprintln!("skipping: {} is case-sensitive here", device_b.root_path().display());
        return;
    }

    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    // "Photo.jpg" is the live, materialized file.
    let live_path = device_b.root_path().join("Photo.jpg");
    std::fs::write(&live_path, b"original photo bytes").unwrap();
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "Photo.jpg".into(),
                size: b"original photo bytes".len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // "photo.jpg" is a colliding sibling already known (held) from a prior
    // create-collision -- present in the index, never materialized.
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "photo.jpg".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // device_a commits a tombstone for "Photo.jpg" -- the live file's OWN
    // path, not the sibling's.
    device_a
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "Photo.jpg",
            "device-a",
            0,
            &device_a.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    announce_until(
        &session_a,
        GROUP,
        || {
            device_b
                .state
                .materialization_state_repository()
                .get_held_state(GROUP, "Photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
    )
    .await;

    let record =
        device_b.state.file_index_repository().get_file(GROUP, "Photo.jpg").unwrap().unwrap();
    assert!(
        !record.deleted,
        "Photo.jpg's own index row must not become deleted=true while its bytes are still on \
         disk -- that is exactly the divergence a later scan reads as a resurrection-worthy \
         local edit"
    );
    assert_eq!(
        std::fs::read(&live_path).unwrap(),
        b"original photo bytes",
        "a held tombstone must never physically delete the file it targets"
    );
}

/// A held file's record and content
/// blocks must keep flowing to peers exactly like any other record — held
/// state is a *local* materialization gate (this device won't write the
/// bytes to disk under this hazardous name), not an exclusion from index
/// exchange or block serving (the design: "the index continues tracking
/// it... so it still syncs correctly to any peer/platform where the name
/// is valid"). Held state is set up directly against device B's own
/// `ReplicaCoordinator`/`BlockStore` here (the same device-local setup
/// `held_file_tombstone_clears_held_state` above uses) rather than driven
/// through an actual case-fold collision, so this test isolates exactly
/// the property calls for — B, despite holding this record,
/// still answers device C's real block requests for it over an actual
/// two-peer wire connection.
#[tokio::test]
async fn held_files_blocks_are_still_served_to_a_requesting_peer() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");
    let device_c = Device::new("device-c");

    let content = b"content this device holds but never wrote to disk";
    // Committed through the DAG, not straight into the index: the heads
    // announce is what carries this record to C, and it can only announce a
    // path the change history actually contains. `commit_create` stores the
    // content block on B exactly as the direct `store.put` here used to, so
    // B still has the bytes to serve without ever writing them to disk.
    device_b.producer().commit_create(GROUP, "photo.jpg", content, 0);
    device_b
        .state
        .materialization_state_repository()
        .set_held(GROUP, "photo.jpg", "case_collision: collides with existing 'Photo.jpg'", 1_000)
        .unwrap();
    assert!(
        !device_b.root_path().join("photo.jpg").exists(),
        "sanity check: nothing is on disk under the held name before B ever connects to anyone"
    );

    let (channel_b, channel_c) = connect_pair(addr).await;
    let session_b = spawn_session(channel_b, &device_b, "device-c");
    let _session_c = spawn_session(channel_c, &device_c, "device-b");

    let path_on_c = device_c.root_path().join("photo.jpg");
    announce_until(&session_b, GROUP, || path_on_c.exists(), Duration::from_secs(20)).await;
    assert_eq!(
        std::fs::read(&path_on_c).unwrap(),
        content,
        "C must receive the real content — B served its held-but-locally-present blocks"
    );

    // B's own held state and lack of an on-disk artifact are unaffected
    // by having served the block onward to C.
    assert!(device_b
        .state
        .materialization_state_repository()
        .get_held_state(GROUP, "photo.jpg")
        .unwrap()
        .is_some());
    assert!(!device_b.root_path().join("photo.jpg").exists());
}

/// Closes a wire-serialization gap: `FileRecord` (and therefore
/// `proto::FileInfo`'s pre-fix `From` conversions) never carried
/// `record_kind`/`symlink_target`, so the real symlink
/// scan/materialization logic only ever worked within *one* device's own
/// local state; a symlink genuinely could not cross the wire from a peer.
///
/// This is the real, end-to-end case that gap blocked: device A creates a
/// genuine symlink on disk, `LocalChangeProcessor::process_event` (section
/// 2's actual scan/watch classification — not a hand-built `FileRecord`)
/// records it as `RecordKind::Symlink` with its target text, and only
/// *then* do the two devices connect over an actual `PeerChannel`
/// and run real `PeerSyncSession`s. If `send_full_index`
/// (`PeerSyncSession::file_info_for_record`) didn't populate the new wire
/// fields, or `reconcile_one_file`/`apply_incoming_wire_metadata` didn't
/// persist them into device B's own index ahead of `materialize`, device B
/// would materialize an ordinary (and, since a symlink record carries no
/// blocks, empty/zero-byte) regular file here instead of a real symlink —
/// exactly the "local-only tests don't catch it" distinction this test is
/// written to rule out. The assertion that matters is on B's *actual
/// on-disk filesystem entry* (`symlink_metadata`/`read_link`), not just
/// its index row.
#[cfg(unix)]
#[tokio::test]
async fn symlink_created_on_one_device_materializes_as_a_real_symlink_on_its_peer() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // An ordinary sibling file the link points at, entirely within device
    // A's linked folder — an intra-folder-root symlink is the common,
    // legitimate case that must actually sync as a link.
    std::fs::write(device_a.root_path().join("original.txt"), b"vacation photos live here")
        .unwrap();
    let link_path = device_a.root_path().join("shortcut");
    std::os::unix::fs::symlink("original.txt", &link_path).unwrap();
    assert!(
        std::fs::symlink_metadata(&link_path).unwrap().file_type().is_symlink(),
        "sanity check: this really is a symlink on device A's own disk before anything syncs"
    );

    // Real scan-side classification (section 2), not a hand-built record —
    // this is what actually populates `RecordKind::Symlink`/the target
    // text in device A's own `ReplicaCoordinator` in the first place.
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: link_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    assert!(record.blocks.is_empty(), "sanity check: a symlink record carries no content blocks");
    assert_eq!(
        device_a.state.file_index_repository().get_record_kind(GROUP, "shortcut").unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink),
        "sanity check: device A's own index really does classify this as a symlink"
    );

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("shortcut");
    // `.exists` follows symlinks and would report `false` for a symlink
    // whose target isn't resolvable from B's perspective — use the
    // lstat-equivalent check so this doesn't depend on B being able to
    // resolve the target at all.
    wait_until(|| std::fs::symlink_metadata(&replicated_path).is_ok(), Duration::from_secs(10))
        .await;

    let metadata = std::fs::symlink_metadata(&replicated_path).unwrap();
    assert!(
        metadata.file_type().is_symlink(),
        "device B must materialize a real symlink, not a regular (and, since a symlink record \
         carries no blocks, empty) file — this is exactly the round-trip the wire gap \
         used to break"
    );
    assert_eq!(
        std::fs::read_link(&replicated_path).unwrap(),
        std::path::PathBuf::from("original.txt"),
        "the symlink's target text must survive the wire round trip unchanged"
    );

    // The index-level view should agree with the on-disk reality — both
    // matter, but the on-disk assertions above are the ones that actually
    // distinguish "the gap is closed" from "only the local index looks
    // right."
    assert_eq!(
        device_b.state.file_index_repository().get_record_kind(GROUP, "shortcut").unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink)
    );
    assert_eq!(
        device_b.state.file_index_repository().get_symlink_target(GROUP, "shortcut").unwrap(),
        Some(b"original.txt".to_vec())
    );
}

/// Closes the same wire gap as the symlink
/// test above, for the other field the gap silently dropped in both
/// directions — the owner-executable bit. Device A's index records a file
/// as executable (`ReplicaCoordinator::set_exec_bit`, standing in for section 2/3's
/// still-separately-open local-capture wiring — see
/// `yadorilink_local_storage::chunker::owner_exec_bit_from_metadata`'s doc
/// comment for that distinct, still-undone gap; this test is scoped to
/// whether an *already-recorded* bit
/// crosses the wire and gets applied for real, not to how it got recorded
/// in the first place), and a real two-peer sync must leave device B's
/// **actual on-disk file** — not just its index row — with the owner-exec
/// permission bit set.
#[cfg(unix)]
#[tokio::test]
async fn exec_bit_set_on_one_device_is_applied_to_the_real_file_on_its_peer() {
    use std::os::unix::fs::PermissionsExt;

    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("run.sh");
    std::fs::write(&file_path, b"#!/bin/sh\necho hi\n").unwrap();
    // Make it executable on disk BEFORE capturing, so process_event records the
    // exec bit into the emitted DAG change's FileVersion. The raw set_exec_bit
    // index setter does not emit a change, so the exec bit would never cross the
    // DAG wire — only the deleted legacy index wire carried an index column.
    let mut perms = std::fs::metadata(&file_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&file_path, perms).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("run.sh");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;

    assert_eq!(std::fs::read(&replicated_path).unwrap(), b"#!/bin/sh\necho hi\n");
    let mode = std::fs::metadata(&replicated_path).unwrap().permissions().mode();
    assert_ne!(
        mode & 0o100,
        0,
        "device B's real, on-disk file must carry the owner-exec bit device A advertised — \
         before the fix this field never crossed the wire at all"
    );
}

/// Closes a specific, honestly-documented limitation: an exec-bit-only
/// change that skips the block fetch was previously not exercised as a
/// genuine over-the-wire two-peer test, because before this fix
/// `proto::FileInfo` had nowhere to carry an exec-bit change at all.
/// Device A first syncs a file normally (full
/// content, not executable), then changes *only* the exec bit (content
/// byte-identical) and pushes an incremental `IndexUpdate`. Device B must
/// end up with the owner-exec bit applied to its already-materialized
/// file via `try_apply_metadata_only_update`'s fast path — this doesn't
/// instrument the network to prove zero bytes were re-fetched, but it does
/// prove the file's content survives completely unchanged (not silently
/// corrupted/truncated by a spurious rewrite) while the permission bit
/// updates, which is the fast path's whole externally-observable contract.
#[cfg(unix)]
#[tokio::test]
async fn exec_bit_only_change_propagates_over_the_wire_without_disturbing_content() {
    use std::os::unix::fs::PermissionsExt;

    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("build.sh");
    let content = b"#!/bin/sh\nmake all\n";
    std::fs::write(&file_path, content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join("build.sh");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;
    assert_eq!(std::fs::read(&replicated_path).unwrap(), content);
    assert_eq!(
        std::fs::metadata(&replicated_path).unwrap().permissions().mode() & 0o100,
        0,
        "sanity check: not executable yet"
    );

    // Content is unchanged; only the exec bit flips. Flipping it on disk and
    // re-capturing emits an exec-bit-only Update into the DAG (size and mtime
    // unchanged, so process_event takes the metadata-only path and carries the
    // new exec bit in the FileVersion), which the peer applies via
    // `try_apply_metadata_only_update`'s block-list fast path.
    let build_sh = device_a.root_path().join("build.sh");
    let mut perms = std::fs::metadata(&build_sh).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&build_sh, perms).unwrap();
    let _ = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: build_sh, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );

    announce_until(
        &session_a,
        GROUP,
        || {
            std::fs::metadata(&replicated_path)
                .map(|m| m.permissions().mode() & 0o100 != 0)
                .unwrap_or(false)
        },
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(
        std::fs::read(&replicated_path).unwrap(),
        content,
        "the metadata-only fast path must never disturb already-correct file content"
    );
}

// --- Rate-limiting integration tests ---

/// The default (unlimited, `RateLimiters::unlimited`) session
/// configuration imposes no measurable delay on a real block transfer —
/// end-to-end confirmation alongside `rate_limiter::tests`'s unit-level one.
#[tokio::test]
async fn unlimited_rate_limiters_impose_no_measurable_delay_on_a_real_transfer() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("unthrottled.bin");
    std::fs::write(&file_path, vec![0x22u8; 50_000]).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    // Explicit (matches the real, un-configured default), confirming the
    // session-level plumbing itself adds no overhead either.
    session_a.set_rate_limiters(Arc::new(RateLimiters::unlimited()));
    session_b.set_rate_limiters(Arc::new(RateLimiters::unlimited()));

    let replicated_path = device_b.root_path().join("unthrottled.bin");
    let start = std::time::Instant::now();
    wait_until(|| replicated_path.exists(), Duration::from_secs(5)).await;
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "an unlimited-rate transfer should complete quickly, took {:?}",
        start.elapsed()
    );
}

/// A configured non-zero download rate measurably caps real
/// block-transfer throughput — the file is small enough to be a single
/// `DEFAULT_BLOCK_SIZE` block, so the configured rate directly bounds the
/// one `fetch_block` call's `acquire` wait.
#[tokio::test]
async fn configured_download_rate_caps_real_block_transfer_throughput() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let size = 20_000usize;
    let file_path = device_a.root_path().join("throttled.bin");
    std::fs::write(&file_path, vec![0x33u8; size]).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let rate_bytes_per_sec = 4_000u64;
    session_b.set_rate_limiters(Arc::new(RateLimiters::new(0, rate_bytes_per_sec)));

    let replicated_path = device_b.root_path().join("throttled.bin");
    let start = std::time::Instant::now();
    wait_until(|| replicated_path.exists(), Duration::from_secs(30)).await;
    let elapsed = start.elapsed();

    // The bucket starts with one second's worth of tokens (burst
    // allowance), so only `size - rate_bytes_per_sec` bytes are actually
    // rate-limited; generous margin for scheduling overhead.
    let expected_min_secs =
        (size as f64 - rate_bytes_per_sec as f64).max(0.0) / rate_bytes_per_sec as f64;
    let expected_min =
        Duration::from_secs_f64(expected_min_secs).saturating_sub(Duration::from_millis(750));
    assert!(
        elapsed >= expected_min,
        "expected a throttled transfer to take at least {expected_min:?}, took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------
// Transfer compression: real, wire-driven proof that compression is
// actually negotiated and used end-to-end — not just that
// `compress_block`/`decompress_block` work in isolation
// (`peer_session::compression_codec_tests` already covers that). These
// tests either drive a real two-`PeerSyncSession` pair (proving
// negotiation + content correctness through the real send/receive path)
// or pair one real session with a raw, manually-driven `PeerChannel`
// acting as the peer (the same pattern `block_request_for_unreferenced_
// hash_is_refused`/`hydration_rejects_block_response_with_wrong_hash_or_
// size` already use above), so the exact bytes a real session puts on the
// wire can be inspected directly.
// ---------------------------------------------------------------------

/// Two real sessions, both advertising compression support (this
/// build always does — ), must negotiate it and still deliver
/// byte-for-byte correct content through the real compress-on-send /
/// decompress-on-receive path — not merely "sync still works," but sync
/// still works *with compression actually engaged*, verified via the
/// public `compression_negotiated` getter.
#[tokio::test]
async fn compression_is_negotiated_between_two_real_sessions_and_content_round_trips() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Highly repetitive text content (the kind of shape source trees,
    // documents, and logs typically have) spanning multiple blocks, so both
    // a full-index exchange and multiple block fetches are exercised.
    let content = "line of repeated log-like content\n".repeat(20_000).into_bytes();
    let file_path = device_a.root_path().join("app.log");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Negotiation happens from the handshake `ClusterConfig` each side
    // Sends first in `run` — both sessions should observe
    // the other as compression-capable shortly after connecting.
    wait_until(
        || session_a.compression_negotiated() && session_b.compression_negotiated(),
        Duration::from_secs(5),
    )
    .await;

    let replicated_path = device_b.root_path().join("app.log");
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;

    let replicated = std::fs::read(&replicated_path).unwrap();
    assert_eq!(
        replicated, content,
        "content must round-trip byte-for-byte through the real compress/decompress send path"
    );
}

/// A raw, manually-driven peer that advertises compression
/// support must actually receive a `Compression::Zstd`-tagged, genuinely
/// smaller `BlockResponse` for compressible content — inspecting the real
/// wire bytes a live `PeerSyncSession::handle_block_request` produces,
/// not just asserting the codec functions work standalone.
#[tokio::test]
async fn block_response_is_actually_compressed_on_the_wire_when_negotiated() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    // Repetitive text, sized to stay within one 128 KiB default block so
    // there's exactly one block/hash to reason about.
    let content = "the quick brown fox jumps over the lazy dog\n".repeat(2_000).into_bytes();
    assert!(content.len() < 128 * 1024, "test content must fit in a single default-size block");
    let file_path = device_a.root_path().join("big.txt");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    let block = record.blocks.first().cloned().expect("content must chunk to at least one block");

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");

    // Complete the exact-generation handshake as a raw peer (not a full
    // `PeerSyncSession`) so this test can inspect exactly what
    // `handle_block_request` puts on the wire in response.
    // `complete_raw_peer_handshake`'s own inner-layer ClusterConfig
    // deliberately omits zstd (most callers want literal, uncompressed
    // reply bytes) -- this test is the one that specifically wants
    // compression negotiated, so it sends its own additional
    // zstd-advertising ClusterConfig, which the inner recv loop's
    // `record_peer_compression_support` picks up (sticky-true-only, so this
    // only ever turns compression ON, never off).
    complete_raw_peer_handshake(&requester_channel, &session_a).await;
    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                    protocol_version: PeerSyncSession::PROTOCOL_VERSION,
                    supports_reliable_delivery: true,
                    supports_change_dag: true,
                    supports_version_present: true,
                    supports_version_hash_exact: true,
                    supported_compression: vec![proto::Compression::Zstd as i32],
                    max_inflight_requests: 64,
                    max_inflight_bytes: 64 * 1024 * 1024,
                    ..Default::default()
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "big.txt".to_string(),
                    block_hash: block.hash.clone(),
                    request_id: 0,
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let reply = recv_matching_block_reply(&requester_channel, &block.hash).await;
    let Some(proto::block_reply::Outcome::Found(found)) = reply.outcome else {
        panic!("expected a Found reply, got {:?}", reply.outcome);
    };

    assert_eq!(
        found.compression,
        proto::Compression::Zstd as i32,
        "a negotiated-compression peer must receive a Zstd-tagged reply for compressible content"
    );
    assert!(
        found.data.len() < (block.size as usize) / 2,
        "compressed payload ({} bytes) should be well under half the raw block size ({} bytes) \
         for highly repetitive text",
        found.data.len(),
        block.size
    );
    let decompressed = zstd::stream::decode_all(found.data.as_slice()).unwrap();
    assert_eq!(decompressed.len(), block.size as usize);
    assert_eq!(
        sha256_bytes(&decompressed),
        block.hash,
        "decompressed wire bytes must match the block's content hash (D4)"
    );
}

/// A peer whose `ClusterConfig` does not advertise `zstd` support (an old,
/// pre-this-change peer) must never receive a `Compression::Zstd`-tagged
/// response — block fetch behaves identically to pre-change behavior,
/// byte-for-byte. Note this peer still completes the mandatory
/// exact-generation handshake (`complete_raw_peer_handshake`) -- a peer
/// that skips the handshake entirely is no longer a reachable state at
/// all now that `PeerSyncSession::run()`'s preflight requires it
/// unconditionally; what this test actually characterizes is compression
/// specifically staying unnegotiated, not the handshake itself being
/// absent. `complete_raw_peer_handshake`'s own inner-layer `ClusterConfig`
/// already omits zstd by default (see its doc comment), so no extra setup
/// is needed here beyond calling it.
#[tokio::test]
async fn block_reply_is_uncompressed_without_inner_compression_negotiation() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    let content = "the quick brown fox jumps over the lazy dog\n".repeat(2_000).into_bytes();
    let file_path = device_a.root_path().join("big.txt");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    let block = record.blocks.first().cloned().expect("content must chunk to at least one block");

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    complete_raw_peer_handshake(&requester_channel, &session_a).await;
    assert!(
        !session_a.compression_negotiated(),
        "sanity: complete_raw_peer_handshake's inner ClusterConfig must not advertise zstd"
    );

    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "big.txt".to_string(),
                    block_hash: block.hash.clone(),
                    request_id: 0,
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let reply = recv_matching_block_reply(&requester_channel, &block.hash).await;
    let Some(proto::block_reply::Outcome::Found(found)) = reply.outcome else {
        panic!("expected a Found reply, got {:?}", reply.outcome);
    };

    assert_eq!(
        found.compression,
        proto::Compression::None as i32,
        "a peer that never advertised compression support must never receive a compressed block"
    );
    assert_eq!(
        found.data, content,
        "an unnegotiated block reply must carry the exact raw bytes, unchanged"
    );
}

/// A decompression-bomb bound: a `BlockReply` declaring
/// `Compression::Zstd` whose true decompressed size vastly exceeds the
/// sync engine's `MAX_BLOCK_SIZE` (16 MiB) must be rejected without ever
/// materializing that size in memory, hydration must fail cleanly (not
/// hang or crash), and nothing must be persisted to the block store —
/// mirroring `hydration_rejects_block_response_with_wrong_hash_or_size`'s
/// structure exactly, since both are the same reject-and-reassign path
/// (see `PeerSyncSession::handle_block_response`'s doc comment).
#[tokio::test]
async fn hydration_rejects_a_decompression_bomb_block_response() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x42u8; 4096];
    let expected_hash = sha256_bytes(&expected);

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "bomb.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "bomb.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    yadorilink_local_storage::write_placeholder(
        &device_b.root_path().join("bomb.bin"),
        expected.len() as u64,
        0,
    )
    .unwrap();

    // A classic zstd-bomb shape: a large, trivially-compressible buffer
    // (all zeros) compresses down to a tiny payload but claims to expand
    // to far more than `MAX_BLOCK_SIZE` (16 MiB) on decompression. Level 3
    // (not a high level) is enough — all-zero input compresses to a tiny
    // fraction of its size at any level — and keeps this light under
    // parallel test execution.
    let bomb_source = vec![0u8; 64 * 1024 * 1024];
    let bomb = zstd::stream::encode_all(bomb_source.as_slice(), 3).unwrap();
    drop(bomb_source);

    let (responder_channel, channel_b) = connect_pair(addr).await;
    // Not `spawn_session`: this test's subject is hydration's own bounded
    // decompression, driven by one hand-written fake responder answering
    // exactly one `BlockRequest`. The test-only convergence driver would
    // independently discover "bomb.bin" as a materialization repair
    // candidate and issue its own concurrent `BlockRequest` for the same
    // hash, racing this test's explicit `hydrate_file_with_timeout` call for
    // the single canned reply below.
    // `_with_root_authority`: see the identical note in
    // `hydration_rejects_block_response_with_wrong_hash_or_size` --
    // `hydrate_file_with_timeout` below needs a live root-commit authority
    // to actually send the `BlockRequest` this fake responder is waiting
    // to answer.
    let session_b = spawn_session_without_convergence_driver_with_root_authority(
        channel_b, &device_b, "device-a",
    );
    let handshake_session_b = session_b.clone();
    let responder = tokio::spawn(async move {
        let mut buffered: std::collections::VecDeque<Vec<u8>> =
            complete_raw_peer_handshake(&responder_channel, &handshake_session_b).await.into();
        loop {
            let bytes = match buffered.pop_front() {
                Some(bytes) => bytes,
                None => responder_channel.recv().await.unwrap(),
            };
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockReply(
                            proto::BlockReply {
                                block_hash: req.block_hash,
                                outcome: Some(proto::block_reply::Outcome::Found(
                                    proto::BlockReplyFound {
                                        data: bomb,
                                        compression: proto::Compression::Zstd as i32,
                                    },
                                )),
                                request_id: req.request_id,
                            },
                        )),
                    }
                    .encode_to_vec(),
                )
                .await
                .unwrap();
            break;
        }
    });

    let start = std::time::Instant::now();
    let result =
        session_b.hydrate_file_with_timeout(GROUP, "bomb.bin", Duration::from_secs(5)).await;
    let elapsed = start.elapsed();
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "a decompression-bomb block response must fail hydration, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "bounded decompression must reject the bomb promptly rather than spending time \
         materializing tens of megabytes it will discard; took {elapsed:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "a decompression-bomb payload must never be persisted under the expected block hash"
    );
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "bomb.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder)
    );
}

/// (second half): a `BlockResponse` declaring `Compression::Zstd`
/// whose bytes aren't a valid zstd stream at all (corrupted or tampered in
/// transit) must be rejected the same way — cleanly, no panic, no
/// persisted block, hydration reported as failed.
#[tokio::test]
async fn hydration_rejects_a_corrupt_compressed_block_response() {
    let addr = bind_unused_addr().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x55u8; 4096];
    let expected_hash = sha256_bytes(&expected);

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "corrupt.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "corrupt.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    yadorilink_local_storage::write_placeholder(
        &device_b.root_path().join("corrupt.bin"),
        expected.len() as u64,
        0,
    )
    .unwrap();

    let (responder_channel, channel_b) = connect_pair(addr).await;
    // Not `spawn_session`: see the identical note in
    // `hydration_rejects_a_decompression_bomb_block_response` -- this test's
    // one hand-written fake responder answers exactly one `BlockRequest`,
    // which the test-only convergence driver's own concurrent repair fetch
    // for this same placeholder could otherwise race and consume.
    // `_with_root_authority`: see the identical note in
    // `hydration_rejects_block_response_with_wrong_hash_or_size` --
    // `hydrate_file_with_timeout` below needs a live root-commit authority
    // to actually send the `BlockRequest` this fake responder is waiting
    // to answer.
    let session_b = spawn_session_without_convergence_driver_with_root_authority(
        channel_b, &device_b, "device-a",
    );
    let handshake_session_b = session_b.clone();
    let responder = tokio::spawn(async move {
        let mut buffered: std::collections::VecDeque<Vec<u8>> =
            complete_raw_peer_handshake(&responder_channel, &handshake_session_b).await.into();
        loop {
            let bytes = match buffered.pop_front() {
                Some(bytes) => bytes,
                None => responder_channel.recv().await.unwrap(),
            };
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockReply(
                            proto::BlockReply {
                                block_hash: req.block_hash,
                                outcome: Some(proto::block_reply::Outcome::Found(
                                    proto::BlockReplyFound {
                                        data: vec![0xFFu8; 256], // not a valid zstd frame
                                        compression: proto::Compression::Zstd as i32,
                                    },
                                )),
                                request_id: req.request_id,
                            },
                        )),
                    }
                    .encode_to_vec(),
                )
                .await
                .unwrap();
            break;
        }
    });

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "corrupt.bin", Duration::from_secs(3)).await;
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "an undecompressable block reply must fail hydration, got {result:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "a corrupt compressed payload must never be persisted under the expected block hash"
    );
}

/// The adaptive in-flight window: a real, end-to-end proof (not just the
/// standalone `AdaptiveWindow` unit tests) that
/// `PeerSyncSession::fetch_window` moves in response to real `fetch_block`
/// traffic over a real transport, through the actual public API
/// `yadorilink-daemon`'s multi-peer dispatcher consults
/// (`fetch_window`/`record_fetch_timeout`) — grows under many real, fast,
/// successful round trips, then shrinks once timeouts are reported the
/// way a real caller-imposed bound would report them, then grows back
/// once good conditions resume.
#[tokio::test]
async fn fetch_window_grows_under_real_traffic_and_shrinks_after_timeouts_then_recovers() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // OnDemand on device_b so the initial index sync adopts a placeholder
    // without eagerly fetching — `hydrate_file` below then drives every
    // block fetch explicitly, giving a clean, countable burst of real
    // `fetch_block` round trips over the live direct connection.
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // Large enough (well past `chunker::DEFAULT_BLOCK_SIZE` = 128 KiB) to
    // split into many blocks, so `hydrate_file` issues many real
    // `fetch_block` round trips — one sample alone can't demonstrate
    // "grows under repeated good conditions."
    let content: Vec<u8> = (0..1_000_000).map(|index| (index % 251) as u8).collect();
    let file_path = device_a.root_path().join("big-archive.tar");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let placeholder_path = device_b.root_path().join("big-archive.tar");
    announce_until(&session_a, GROUP, || placeholder_path.exists(), Duration::from_secs(20)).await;

    let initial_window = session_b.fetch_window();

    session_b.hydrate_file(GROUP, "big-archive.tar").await.unwrap();
    assert_eq!(std::fs::read(&placeholder_path).unwrap(), content);

    let grown_window = session_b.fetch_window();
    assert!(
        grown_window > initial_window,
        "fetch_window should grow after many real, fast, successful block \
         fetches: {initial_window} -> {grown_window}"
    );

    // Simulate what a real caller-imposed timeout observes and reports —
    // exactly the signal `yadorilink-daemon::hydration`'s
    // `PER_BLOCK_FETCH_TIMEOUT` arm feeds via `record_fetch_timeout` when a
    // `fetch_block` future is dropped without ever answering. Real network
    // conditions bad enough to reliably reproduce this in a test are
    // impractical, so this drives the same public API a real timeout
    // caller drives.
    for _ in 0..10 {
        session_b.record_fetch_timeout();
    }
    let shrunk_window = session_b.fetch_window();
    assert!(
        shrunk_window < grown_window,
        "fetch_window should shrink after sustained timeouts: {grown_window} -> {shrunk_window}"
    );

    // Recovery: another real hydration (a second, different file) over the
    // same still-healthy connection should grow the window again from the
    // shrunk point — grow/shrink is not a one-way ratchet.
    let content2 = vec![0x5Bu8; 1_000_000];
    let file_path2 = device_a.root_path().join("second-archive.tar");
    std::fs::write(&file_path2, &content2).unwrap();
    let _record2 = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path2, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    announce_until(
        &session_a,
        GROUP,
        || device_b.root_path().join("second-archive.tar").exists(),
        Duration::from_secs(20),
    )
    .await;
    session_b.hydrate_file(GROUP, "second-archive.tar").await.unwrap();

    let recovered_window = session_b.fetch_window();
    assert!(
        recovered_window > shrunk_window,
        "fetch_window should grow back once good conditions resume: \
         {shrunk_window} -> {recovered_window}"
    );
}

/// a real, end-to-end proof that
/// `reconcile_files`'s batched prefetch (`ReplicaCoordinator::get_files_by_paths` +
/// `reconcile_needed`, see both doc comments) correctly handles the
/// scenario it targets — a large incoming index where almost every record
/// is already in sync (the old per-record `get_file` point-query pattern's
/// worst case, and exactly what a peer resending its full index on
/// reconnect looks like) mixed with a handful of records that genuinely
/// changed. The fast-path skip must never swallow a real change, and every
/// unchanged record must still converge correctly.
#[tokio::test]
async fn large_mostly_unchanged_index_resync_still_correctly_reconciles_the_few_real_changes() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    const FILE_COUNT: usize = 150;
    for i in 0..FILE_COUNT {
        let path = device_a.root_path().join(format!("file_{i:04}.txt"));
        std::fs::write(&path, format!("content {i}")).unwrap();
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
    }

    let (channel_a, channel_b) = connect_pair(addr).await;
    let auth = dag_authenticator(&[&device_a, &device_b]);
    let session_a =
        spawn_session_with_authenticator(channel_a, &device_a, "device-b", auth.clone());
    let session_b =
        spawn_session_with_authenticator(channel_b, &device_b, "device-a", auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Initial full sync over the DAG — every file materializes on device_b.
    // 150 sequential local commits form a 150-deep linear chain; this relies
    // on `handle_change_request`'s ancestor-closure walk to serve that whole
    // chain in one round trip instead of one request/response per
    // generation (see its doc comment) and on `promote_orphans` being
    // seeded/dependency-driven rather than doing a full-buffer rescan per
    // promotion (see its doc comment) — without both, this used to take
    // well over a minute and get slower, not faster, as more headroom was
    // given it.
    announce_until(
        &session_a,
        GROUP,
        || (0..FILE_COUNT).all(|i| device_b.root_path().join(format!("file_{i:04}.txt")).exists()),
        Duration::from_secs(30),
    )
    .await;
    for i in 0..FILE_COUNT {
        assert_eq!(
            std::fs::read_to_string(device_b.root_path().join(format!("file_{i:04}.txt"))).unwrap(),
            format!("content {i}")
        );
    }

    // Modify only a small number of files on device_a.
    const CHANGED: [usize; 3] = [7, 80, 149];
    for i in CHANGED {
        let path = device_a.root_path().join(format!("file_{i:04}.txt"));
        std::fs::write(&path, format!("UPDATED content {i}")).unwrap();
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
    }

    // Resend every record device_a currently has for this group — most of
    // it (147 of 150) is identical to what device_b already converged on
    // above, simulating a full-index resend (e.g. after a reconnect)
    // rather than an ordinary incremental update of just the changed
    // files. This is exactly the batch shape `reconcile_needed`'s
    // prefetch-based skip is meant for.
    // On the DAG path only the three genuinely changed files produced new
    // commits above; announcing device_a's head carries exactly those Updates
    // to device_b, which must converge them while leaving the 147 unchanged
    // files correct.
    let all_records = device_a.state.file_index_repository().list_files(GROUP).unwrap();
    assert_eq!(all_records.len(), FILE_COUNT);
    let started = std::time::Instant::now();
    announce_until(
        &session_a,
        GROUP,
        || {
            CHANGED.iter().all(|&i| {
                std::fs::read_to_string(device_b.root_path().join(format!("file_{i:04}.txt")))
                    .ok()
                    .as_deref()
                    == Some(format!("UPDATED content {i}").as_str())
            })
        },
        Duration::from_secs(20),
    )
    .await;
    let elapsed = started.elapsed();

    // The genuinely changed files converged...
    for i in CHANGED {
        assert_eq!(
            std::fs::read_to_string(device_b.root_path().join(format!("file_{i:04}.txt"))).unwrap(),
            format!("UPDATED content {i}")
        );
    }
    // ...and every one of the other 147 unchanged files is still correct
    // (the skip fast-path must never be mistaken for "delete/ignore this
    // record" — it must leave already-correct content exactly alone).
    for i in 0..FILE_COUNT {
        if CHANGED.contains(&i) {
            continue;
        }
        assert_eq!(
            std::fs::read_to_string(device_b.root_path().join(format!("file_{i:04}.txt"))).unwrap(),
            format!("content {i}"),
            "unchanged file_{i:04}.txt must be untouched by a mostly-unchanged batch resync"
        );
    }

    // Loose sanity bound — the real, decisive O(records)-vs-batched proof
    // is `ReplicaCoordinator::get_files_by_paths`'s own comparative timing test in
    // index.rs; this just confirms the wired-up end-to-end path isn't
    // pathologically slow for a 150-record mixed batch.
    assert!(
        elapsed < Duration::from_secs(15),
        "reconciling a 150-record mostly-unchanged index update took {elapsed:?}, expected well \
         under 15s"
    );
}

/// A tombstone *adopted from a
/// peer* (not just a local delete — `mark_deleted`'s own case is covered
/// directly in `index.rs`'s unit tests) enters the same recoverable
/// trashed state as a local deletion would (spec "A tombstone adopted from
/// a peer also enters trash"). Device A holds real content for
/// "shared.txt"; device B's tombstone strictly dominates A's version
/// vector (an ordinary "peer is ahead" adoption, not a conflict), so A
/// adopts it outright via `reconcile_one_file`'s `ChangeOrdering::Before`
/// branch — exercising `materialize`'s tombstone-apply path over the real
/// wire, not a direct `ReplicaCoordinator` call.
#[tokio::test]
async fn tombstone_adopted_from_a_peer_enters_recoverable_trash() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // device_a creates shared.txt with real content, committed to the DAG.
    let content_a: &[u8] = b"real content that must be recoverable from trash";
    std::fs::write(device_a.root_path().join("shared.txt"), content_a).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent {
                path: device_a.root_path().join("shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // device_b first receives shared.txt over the DAG...
    announce_until(
        &session_a,
        GROUP,
        || device_b.root_path().join("shared.txt").exists(),
        Duration::from_secs(20),
    )
    .await;

    // ...then tombstones it. The tombstone descends device_a's Create (an
    // ordinary "peer is ahead" adoption, not a concurrent-edit conflict), so
    // device_a adopts it and moves its own last live content to trash.
    device_b
        .state
        .mark_deleted_emitting_change(
            GROUP,
            "shared.txt",
            "device-b",
            2000,
            &device_b.emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    announce_until(
        &session_b,
        GROUP,
        || !device_a.root_path().join("shared.txt").exists(),
        Duration::from_secs(20),
    )
    .await;

    // The tombstone is now device A's current record for this path...
    let current =
        device_a.state.file_index_repository().get_file(GROUP, "shared.txt").unwrap().unwrap();
    assert!(current.deleted, "device A must have adopted the peer's tombstone");

    // ...but its own prior real content is recoverable from trash, not
    // discarded — this is the property this test exists to prove.
    let trashed = device_a.state.file_index_repository().list_trashed(GROUP).unwrap();
    assert_eq!(trashed.len(), 1, "the file's last live content must be listed under trash");
    assert_eq!(trashed[0].path, "shared.txt");
    assert_eq!(trashed[0].last_known_size, content_a.len() as u64);

    let versions = device_a.state.sqlite().dag_list_versions(GROUP, "shared.txt").unwrap();
    let trashed_version = versions
        .iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Trashed);
    let trashed_version = trashed_version.expect("expected exactly one trashed version");
    assert!(
        !trashed_version.blocks.is_empty(),
        "the trashed version's block references must survive"
    );
    assert_eq!(
        trashed_version.origin_device_id.as_deref(),
        Some("device-a"),
        "the trashed version still records who originally wrote it"
    );
}

/// A catch-up batch larger than `MAX_IN_FLIGHT_MESSAGES_PER_PEER` (64)
/// distinct eager-fetch-triggering messages must not permanently deadlock
/// the recv loop. Sends `N` (> 64) separate single-change `ChangeBatch`es
/// (one per wire message, so each spawns its own `handle_message`
/// task/permit rather than sharing one permit across a single batched
/// message — see `DagProducer::last_commit_as_wire_batch`), followed by an
/// interleaved control message — a trailing `ChangeBatch` for a zero-block
/// file, which needs no `BlockRequest` of its own — all *before* answering a
/// single `BlockRequest` for the `N` real files: reproducing exactly the
/// ordering that used to deadlock: every permit held by a task stuck awaiting
/// a `BlockResponse` this test hasn't sent yet, with other messages (including
/// the trailing control update) queued behind them.
///
/// Each change is authored by its own producer device, so the `N` changes are
/// independent DAG *roots* rather than one causal chain. That is required for
/// the stimulus to mean what it says: the recv loop hands each message to its
/// own task and those tasks run concurrently, so a chain would let a child be
/// dequeued before its parent was admitted, get held as an orphan, and return
/// its permit immediately instead of blocking on a `BlockResponse` — quietly
/// dismantling the very permit exhaustion this test exists to create. It also
/// mirrors what a real catch-up carries: one peer relaying many devices'
/// independent edits (store-and-forward).
///
/// Before this change's fix, the recv loop would block on
/// `acquire_owned` trying to admit the 65th message and never call
/// `self.channel.recv` again — so it could never even read, let alone
/// process, the incoming `BlockResponse`s this test's responder task
/// sends once it observes the resulting `BlockRequest`s, nor the
/// trailing control update. Forward progress would then depend entirely
/// on each stuck fetch's own `DEFAULT_HYDRATION_TIMEOUT` (30s, times
/// `RECONCILE_RETRY_ATTEMPTS`) elapsing — far outside this test's
/// generous-but-bounded timeouts, so the old structure fails this test
/// with a timeout rather than a clean assertion failure.
#[tokio::test]
async fn recv_loop_survives_a_catchup_batch_larger_than_the_permit_budget() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");

    // Comfortably more than `MAX_IN_FLIGHT_MESSAGES_PER_PEER` (64) so the
    // semaphore is genuinely, fully exhausted by real concurrently-running
    // tasks, not just close to it.
    const N: usize = 80;

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    complete_raw_peer_handshake(&channel_b, &session_a).await;

    struct StressFile {
        path: String,
        content: Vec<u8>,
        hash: Vec<u8>,
        batch: proto::ChangeBatch,
    }
    // Each producer device is dropped at the end of its iteration: the wire
    // batch and the block bytes are owned copies by then, and device A fetches
    // every block from this test's own responder rather than from the
    // producer's store, so nothing reads the producer back after this.
    let files: Vec<StressFile> = (0..N)
        .map(|i| {
            let path = format!("stress-{i:03}.bin");
            let content = format!("stress-content-{i}").into_bytes();
            let producer_device = Device::new(&format!("stress-dev-{i:03}"));
            let producer = producer_device.producer();
            let (record, version) =
                producer.commit_create_returning_version(GROUP, &path, &content, 0);
            let batch = producer.last_commit_as_wire_batch(GROUP, &version);
            StressFile { path, hash: record.blocks[0].hash.clone(), content, batch }
        })
        .collect();

    // One `ChangeBatch` per change, not one batched message covering all of
    // them — batching would process every change sequentially inside a
    // single `handle_message` call (one permit total), which could never
    // exhaust `message_slots` regardless of change count.
    for f in &files {
        channel_b
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::ChangeBatch(f.batch.clone())),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    }

    // The interleaved control message: sent after every eager-fetch
    // trigger and before any `BlockResponse` -- the exact ordering that
    // used to wedge the recv loop behind its own exhausted permit pool.
    // A zero-block file needs no `BlockRequest` of its own, so — once
    // dequeued — it's handled and indexed immediately rather than joining
    // the same stuck-awaiting-`BlockResponse` state as the `N` real files.
    let control_device = Device::new("stress-control");
    let control_producer = control_device.producer();
    let (_control_record, control_version) =
        control_producer.commit_create_empty(GROUP, "stress-control-signal", 0);
    let control_batch = control_producer.last_commit_as_wire_batch(GROUP, &control_version);
    channel_b
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ChangeBatch(control_batch)),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    // Answers every `BlockRequest` as it's observed, concurrently with
    // the assertions below -- this is what proves permits actually
    // *recover* (not just that one lucky message got through): the full
    // batch, not merely the first 64, must eventually converge.
    let responder_files: Vec<(Vec<u8>, Vec<u8>)> =
        files.iter().map(|f| (f.hash.clone(), f.content.clone())).collect();
    let channel_b_responder = channel_b.clone();
    let responder = tokio::spawn(async move {
        let mut answered = std::collections::HashSet::new();
        while answered.len() < N {
            let Some(bytes) = channel_b_responder.recv().await else { break };
            let Ok(msg) = proto::SyncMessage::decode(bytes.as_slice()) else { continue };
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            let Some((hash, content)) =
                responder_files.iter().find(|(hash, _)| *hash == req.block_hash)
            else {
                continue;
            };
            answered.insert(hash.clone());
            let _ = channel_b_responder
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockReply(
                            proto::BlockReply {
                                block_hash: hash.clone(),
                                outcome: Some(proto::block_reply::Outcome::Found(
                                    proto::BlockReplyFound {
                                        data: content.clone(),
                                        compression: proto::Compression::None as i32,
                                    },
                                )),
                                request_id: req.request_id,
                            },
                        )),
                    }
                    .encode_to_vec(),
                )
                .await;
        }
    });

    // The actual deadlock-vs-not assertion: the recv loop must still
    // deliver this control message even though, at the moment it was
    // sent, every one of `MAX_IN_FLIGHT_MESSAGES_PER_PEER` permits was
    // held by a task awaiting a `BlockReply` nobody had sent yet.
    wait_until(
        || {
            device_a
                .state
                .file_index_repository()
                .get_file(GROUP, "stress-control-signal")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(15),
    )
    .await;

    tokio::time::timeout(Duration::from_secs(15), responder)
        .await
        .expect("expected every BlockRequest to be observed and answered promptly")
        .unwrap();

    for f in &files {
        let replicated_path = device_a.root_path().join(&f.path);
        wait_until(|| replicated_path.exists(), Duration::from_secs(15)).await;
        assert_eq!(&std::fs::read(&replicated_path).unwrap(), &f.content);
    }
}

#[cfg(test)]
mod promoted_orphan_projection_tests {
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session_impl::{
        ChangeAuthenticator, PeerSyncSession, PeerSyncSessionOneTimeDeps,
    };
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::file::{FileMeta, FileVersion};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
    use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

    const GROUP: &str = "shared-group";

    /// A permissive authenticator that pins one author's verifying key and
    /// treats it as a writer — the trust material the daemon would normally
    /// inject from the coordination plane's netmap.
    struct TestAuthenticator {
        author_device_id: String,
        author_verifying_key: [u8; 32],
    }

    impl ChangeAuthenticator for TestAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == self.author_device_id).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    fn empty_version() -> FileVersion {
        // Zero-block content, so materialization writes an empty file with no
        // block fetch — the projection under test does not depend on content
        // transfer, only on which paths get projected.
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }
    }

    /// Builds the two signed changes an author would emit — a root editing
    /// `a.txt`, then a child editing `b.txt` that descends from it — by
    /// running the real local-emission path against a throwaway store.
    fn build_parent_then_child(signing_key: &SigningKey) -> (Change, Change, FileVersion) {
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let version = empty_version();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let parent = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("a.txt", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();
        let child = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("b.txt", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();
        (parent, child, version)
    }

    /// Constructs a live channel that has no reachable peer. `handle_change_
    /// batch` may enqueue an outbound change-request for a still-missing
    /// parent; sending on this channel simply queues the datagram (the send
    /// half stays open), so the call under test completes without a peer.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    /// The regression this targets: two changes touching DIFFERENT paths,
    /// delivered child-first within one batch, must BOTH project together in
    /// one Convergence Engine audit pass. The child editing `b.txt` arrives
    /// before its parent, so it is orphaned; the parent editing `a.txt`
    /// arrives next in the same batch, applies, and promotes the child.
    /// Before the fix this regression targets, only the parent's path
    /// (`a.txt`) was folded into the batch's projection, so `b.txt` would not
    /// have materialized until a later reprojection audit ran. This asserts
    /// both paths have file records and both changes are marked applied after
    /// one call to `reconcile_local_materialization_audit` (the same
    /// projection step `handle_change_batch` used to run inline, and that the
    /// Convergence Engine now drives on its own schedule instead).
    #[tokio::test]
    async fn unauthenticated_batch_cannot_persist_file_versions() {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
        );
        let version = empty_version();
        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![],
                compressed_changes: vec![],
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();
        assert!(!state.sqlite().dag_has_file_version(GROUP, &version.version_hash).unwrap());
    }

    #[tokio::test]
    async fn rejected_lamport_change_cannot_persist_or_authorize_its_file_version() {
        use yadorilink_replica_domain::file::VersionBlock;
        use yadorilink_replica_domain::ids::BlockHash;

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, _, parent_version) = build_parent_then_child(&signing_key);
        let block_hash = vec![0x5a; 32];
        let poisoned_version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        // `parent.lamport` is the only valid predecessor maximum. Supplying a
        // much larger value creates a correctly signed change that fails DAG
        // admission only after signature and writer authorization succeed.
        let rejected = Change::create_signed(
            vec![parent.compute_hash()],
            parent.lamport + 99,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".into()),
            FolderGroupId(GROUP.into()),
            vec![create_op("poison.bin", &poisoned_version)],
            &signing_key,
        );

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![parent.to_wire_bytes(), rejected.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![
                    parent_version.canonical_encoding(),
                    poisoned_version.canonical_encoding(),
                ],
            })
            .await
            .unwrap();

        assert!(state.change_history_repository().dag_has_change(&parent.compute_hash()).unwrap());
        assert!(!state
            .change_history_repository()
            .dag_has_change(&rejected.compute_hash())
            .unwrap());
        assert!(!state
            .sqlite()
            .dag_has_file_version(GROUP, &poisoned_version.version_hash)
            .unwrap());
        assert!(!state
            .change_history_repository()
            .dag_group_file_version_references_block(GROUP, &block_hash)
            .unwrap());
    }

    #[tokio::test]
    async fn reverse_ordered_batch_projects_both_paths_immediately() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_parent_then_child(&signing_key);

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        // Reverse order: the child (b.txt) precedes its parent (a.txt) in the
        // batch, so the child is processed first and orphaned, then the parent
        // lands and promotes it — all in this one call.
        let batch = yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: vec![child.to_wire_bytes(), parent.to_wire_bytes()],
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        };
        session.handle_change_batch(batch).await.unwrap();

        // Both changes are durable immediately (DAG admission is still
        // synchronous within `handle_change_batch` — only materialization is
        // now deferred)...
        assert!(state.change_history_repository().dag_has_change(&parent.compute_hash()).unwrap());
        assert!(state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap());

        // ...`handle_change_batch` itself only admits the DAG changes and
        // enqueues materialization jobs now (CONV-1); drive the same
        // projection step the Convergence Engine would, exactly as it would
        // call it, in one pass covering both the parent's path and the
        // promoted orphan's path together.
        session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        assert!(
            state.file_index_repository().get_file(GROUP, "a.txt").unwrap().is_some(),
            "the parent's path must be materialized"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "b.txt").unwrap().is_some(),
            "the promoted orphan's path must be materialized in the same audit pass"
        );
        // ...and both changes are marked applied, so the backstop has nothing
        // left to re-drive.
        assert!(
            state.change_history_repository().dag_list_unapplied_changes(GROUP).unwrap().is_empty(),
            "both the parent and the promoted orphan must be marked applied after one audit pass"
        );
    }

    /// The real peer-apply entry point (`handle_change_batch`) must wait on the
    /// group's startup barrier before admitting any change, so an incoming peer
    /// change cannot race the startup scan's un-path-locked commit. A closed
    /// barrier blocks the call; `mark_group_ready` releases it.
    #[tokio::test]
    async fn handle_change_batch_waits_for_group_startup_barrier() {
        let store_dir = tempfile::tempdir().unwrap();
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // A live link, but deliberately no `mark_group_ready` yet -- this test
        // owns the barrier's lifecycle below. The link row itself is required:
        // the apply path refuses a group with no live link before it ever
        // reaches the barrier, so without it there would be no parking to
        // observe.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);

        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );

        // Close the barrier, as `start_link_watch` does before the peer
        // orchestrator can run.
        let generation = state.startup_readiness().begin_group_startup(GROUP);

        let empty_batch = || yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: vec![],
            compressed_changes: Vec::new(),
            file_versions: vec![],
        };

        // Closed: the admission call must not complete.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                session.handle_change_batch(empty_batch()),
            )
            .await
            .is_err(),
            "handle_change_batch must park on the group's startup barrier"
        );

        // Startup done: it proceeds.
        state.startup_readiness().mark_group_ready(GROUP, generation);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session.handle_change_batch(empty_batch()),
        )
        .await
        .expect("handle_change_batch must proceed once the group is ready")
        .unwrap();
    }

    /// CONV-1 regression: `handle_change_batch` must never await a block
    /// fetch or disk materialization for the content a change references —
    /// admission and enqueuing a `materialization_jobs` row must be
    /// everything it does before returning. Before this change,
    /// `handle_change_batch` called `reconcile_group_paths` inline, which
    /// would have tried (and, over `unreachable_channel`, never succeeded in)
    /// fetching this change's one block, blocking for up to
    /// `PER_BLOCK_FETCH_TIMEOUT`/`HYDRATION_TIMEOUT` (5s/30s in
    /// `yadorilink-daemon::hydration`) while holding this call's
    /// `message_slots` permit — the traced mechanism behind the row-14
    /// stall this whole change fixes. A tight bound well under either
    /// timeout (100ms, matching the specified p99 success criterion) is
    /// therefore a meaningful, not arbitrary, assertion: passing only
    /// because admission is fast is the whole point, not an implementation
    /// detail.
    #[tokio::test]
    async fn handle_change_batch_never_blocks_on_an_unfetchable_block() {
        use yadorilink_replica_domain::file::VersionBlock;
        use yadorilink_replica_domain::ids::BlockHash;

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();

        // One block whose hash exists in no store anywhere. Over
        // `unreachable_channel` (no peer ever answers), a fetch attempt for
        // it would never resolve — exactly modeling "no reachable peer
        // holds this content" without needing a real, slow-to-time-out
        // second peer.
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![0xAB; 32]), size: 4096 }],
            4096,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let change = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("unfetchable.bin", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        let batch = yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: vec![change.to_wire_bytes()],
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        };

        let started = std::time::Instant::now();
        session.handle_change_batch(batch).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "handle_change_batch took {elapsed:?} for an unfetchable block; it must never await \
             a block fetch (CONV-1) — only admit the change and enqueue a materialization job"
        );

        // The change itself is durable immediately (DAG admission is still
        // synchronous)...
        assert!(state.change_history_repository().dag_has_change(&change.compute_hash()).unwrap());
        // ...but nothing was materialized (no engine ran in this test), and
        // the change stays unapplied — a durable, not silently-dropped,
        // signal that this path still needs the Convergence Engine to make
        // progress on it once a reachable source exists.
        assert!(state
            .file_index_repository()
            .get_file(GROUP, "unfetchable.bin")
            .unwrap()
            .is_none());
        assert!(!state
            .change_history_repository()
            .dag_list_unapplied_changes(GROUP)
            .unwrap()
            .is_empty());
    }

    // --- Characterization tests for `docs/design/phase7-peer-handler-
    // inventory.md`'s reading of the DAG-admission/projection path inside
    // `handle_change_batch`, written to pin the CURRENT observable behavior
    // ahead of a future `PeerReplicaEngine` extraction. See that doc's
    // "Headline findings" section, which flags this handler as one of only
    // two NOT cleanly splittable.

    /// Pins invariant 2 (buffered orphan reprocessed once its ancestor
    /// arrives): a change admitted while its parent is still missing is
    /// buffered as an orphan and is promoted -- not silently dropped --
    /// once its parent arrives, even when the parent arrives in a
    /// SEPARATE, later `handle_change_batch` call rather than the same
    /// batch. `reverse_ordered_batch_projects_both_paths_immediately`
    /// above already proves the same-batch case (child and parent
    /// reordered within one `ChangeBatch`); this proves the cross-batch
    /// case, which exercises `dag_store::promote_orphans` from a genuinely
    /// separate admission call rather than the same per-batch loop
    /// iteration. Invariant 1 (unknown parent lands in the missing-
    /// ancestor frontier) is asserted here too, but is not otherwise
    /// duplicated as its own test: it is already proven directly and
    /// extensively by `dag_store::mod`'s own unit tests --
    /// `missing_ancestor_frontier_walks_through_a_stuck_buffered_orphan`,
    /// `missing_ancestor_frontier_dedups_a_missing_ancestor_shared_by_two_
    /// roots`, and `missing_ancestor_frontier_reports_only_the_genuinely_
    /// missing_branch` -- against the exact function `handle_change_batch`
    /// itself calls (`dag_missing_ancestor_frontier`, peer_session.rs
    /// ~4395/4605), with no additional logic of its own to test
    /// independently.
    #[tokio::test]
    async fn orphan_admitted_in_one_batch_is_promoted_when_its_parent_arrives_in_a_later_batch() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_parent_then_child(&signing_key);

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        // First batch: only the child (b.txt), whose parent (a.txt's
        // change) this session has never seen -- it must buffer as an
        // orphan, not be admitted outright.
        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![child.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();
        assert!(
            !state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap(),
            "an orphaned change must not appear as admitted"
        );
        assert!(
            state
                .change_history_repository()
                .dag_has_change_or_buffered_orphan(&child.compute_hash())
                .unwrap(),
            "the child must still be tracked, buffered as an orphan"
        );
        let missing =
            state.sqlite().dag_missing_ancestor_frontier(vec![child.compute_hash()]).unwrap();
        assert_eq!(
            missing,
            vec![parent.compute_hash()],
            "the child's missing ancestor frontier must name exactly its own missing parent"
        );

        // Second, later batch: the parent arrives alone. It must both admit
        // itself AND promote the already-buffered child -- reprocessing it,
        // not leaving it stuck.
        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![parent.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();
        assert!(state.change_history_repository().dag_has_change(&parent.compute_hash()).unwrap());
        assert!(
            state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap(),
            "the previously-buffered orphan must be promoted into the DAG once its parent arrives \
             in a later, separate batch"
        );
    }

    /// Pins invariant 3: sending the identical `ChangeBatch` twice must not
    /// duplicate the observable effects of admission -- neither a second,
    /// competing DAG head nor a re-armed/duplicated materialization job.
    /// `dag_store::append_is_idempotent_under_duplicate_delivery` already
    /// proves DAG-level idempotency (`changes`/`group_heads` row counts) for
    /// `dag_store::append_change` directly; this instead exercises the real
    /// `handle_change_batch` entry point end to end and additionally pins
    /// the materialization-job side, whose own idempotency rule
    /// (`materialization_jobs::enqueue_pending`'s doc comment: "same
    /// version, non-terminal: ... must not be reset") is a separate
    /// mechanism from DAG admission's own.
    #[tokio::test]
    async fn duplicate_change_batch_does_not_duplicate_the_dag_head_or_the_materialization_job() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, _child, version) = build_parent_then_child(&signing_key);

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );
        let batch = || yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: vec![parent.to_wire_bytes()],
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        };

        session.handle_change_batch(batch()).await.unwrap();
        assert!(state.change_history_repository().dag_has_change(&parent.compute_hash()).unwrap());
        let heads_after_first = state.sqlite().dag_group_heads(GROUP).unwrap();
        let job_after_first = state
            .materialization_job_repository()
            .materialization_get_job(GROUP, "a.txt")
            .unwrap()
            .expect("a materialization job must be enqueued after the first admission");

        // A little real elapsed time so that, if the second delivery DID
        // touch the job row (re-arming it), `updated_at`/`last_progress_at`
        // would visibly differ -- making this a genuine idempotency check,
        // not one that only passes because both calls happened to land in
        // the same clock tick.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Resend the identical batch.
        session.handle_change_batch(batch()).await.unwrap();
        let heads_after_second = state.sqlite().dag_group_heads(GROUP).unwrap();
        let job_after_second = state
            .materialization_job_repository()
            .materialization_get_job(GROUP, "a.txt")
            .unwrap()
            .expect("the job row must still exist after a duplicate delivery");

        assert_eq!(
            heads_after_first, heads_after_second,
            "a duplicate change must not create a second, competing DAG head"
        );
        assert_eq!(
            job_after_first, job_after_second,
            "a duplicate change must not re-arm or otherwise mutate the materialization job row"
        );
    }

    /// Pins invariant 4: `handle_change_batch`'s `shares_group` gate must
    /// reject a change for a group this session was never authorized for
    /// BEFORE any DAG mutation -- not just before a reply is sent (this
    /// handler sends no reply either way). The change here is otherwise
    /// fully valid (correctly signed, by a device the authenticator pins,
    /// causally sound) specifically so a false pass here would actually
    /// admit it if the authorization gate were bypassed or ordered after
    /// admission.
    #[tokio::test]
    async fn handle_change_batch_never_admits_a_change_for_an_unauthorized_group() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let version = empty_version();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let change = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("secret.txt", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();

        let store_dir = tempfile::tempdir().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // Deliberately no `add_link`/`VerifiedRoot`/startup barrier for
        // GROUP -- `shares_group` must reject before any of that is ever
        // reached.
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![], // no authorized groups at all
            HashMap::new(),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![change.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();

        assert!(
            !state.change_history_repository().dag_has_change(&change.compute_hash()).unwrap(),
            "a change for an unauthorized group must never reach DAG admission"
        );
        assert!(
            !state.sqlite().dag_has_file_version(GROUP, &version.version_hash).unwrap(),
            "its file version must not be persisted either"
        );
    }

    /// Pins invariant 5: a change whose signature does not verify against
    /// the authenticator's pinned key for its claimed device must never be
    /// written to the DAG store, even transiently. Constructs a change that
    /// CLAIMS `device_id = "device-a"` (a device the authenticator pins a
    /// key for) but is actually signed with a different key -- exactly the
    /// forged-identity shape `verify_change`'s signature check exists to
    /// catch, as distinct from `rejected_lamport_change_cannot_persist_or_
    /// authorize_its_file_version` above (which covers a validly-signed but
    /// causally-invalid change).
    #[tokio::test]
    async fn handle_change_batch_never_admits_a_change_with_an_invalid_signature() {
        let real_signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = real_signing_key.verifying_key().to_bytes();
        let forger_signing_key = SigningKey::from_bytes(&[99u8; 32]);

        let version = empty_version();
        let forged = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".into()),
            FolderGroupId(GROUP.into()),
            vec![create_op("forged.bin", &version)],
            &forger_signing_key,
        );

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![forged.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();

        assert!(
            !state.change_history_repository().dag_has_change(&forged.compute_hash()).unwrap(),
            "a change with an invalid signature must never be admitted, even transiently"
        );
        assert!(!state.sqlite().dag_group_heads(GROUP).unwrap().contains(&forged.compute_hash()));

        // The rejection must not wedge this session or group: a genuinely
        // valid change from the real, pinned device afterward is still
        // admitted normally.
        let (honest_parent, _child, honest_version) = build_parent_then_child(&real_signing_key);
        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![honest_parent.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![honest_version.canonical_encoding()],
            })
            .await
            .unwrap();
        assert!(
            state
                .change_history_repository()
                .dag_has_change(&honest_parent.compute_hash())
                .unwrap(),
            "a subsequent genuinely valid change from the real device must still admit normally"
        );
    }

    /// Pins invariant 7: `dag_mark_applied` is only ever called from
    /// `reproject_unapplied_changes`, and only for a change whose
    /// projection this audit attempt actually proved successful
    /// (`change_projection_succeeded`) -- never unconditionally just
    /// because an audit ran. `reverse_ordered_batch_projects_both_paths_
    /// immediately` above proves the SUCCESS half (an audit that can
    /// complete DOES mark applied); this proves the complementary FAILURE
    /// half, reusing `handle_change_batch_never_blocks_on_an_unfetchable_
    /// block`'s own unfetchable-block construction (a projection
    /// precondition -- the block's content -- that can never be satisfied
    /// over this test's unreachable channel) to show that running the
    /// audit explicitly does NOT mark the change applied when its
    /// projection still cannot succeed. Together these two tests pin
    /// invariant 6 as well: an admitted-but-unprojectable change is neither
    /// lost nor falsely marked done, so it stays exactly the kind of
    /// "admitted but unapplied" state `reproject_unapplied_changes` is
    /// built to keep retrying.
    #[tokio::test]
    async fn reproject_unapplied_changes_does_not_mark_applied_when_projection_still_fails() {
        use yadorilink_replica_domain::file::VersionBlock;
        use yadorilink_replica_domain::ids::BlockHash;

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();

        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![0xCD; 32]), size: 4096 }],
            4096,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let change = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("still-unfetchable.bin", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        // Force `Eager` materialization: an `OnDemand` group would
        // materialize a correctly-sized placeholder without ever needing
        // the block's actual bytes, which would make this change project
        // successfully regardless of block availability -- defeating the
        // whole point of this test, which needs projection to genuinely be
        // unable to complete.
        state
            .link_repository()
            .set_materialization_policy(
                &sync_root.to_string_lossy(),
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
            )
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        session
            .handle_change_batch(yadorilink_sync_wire::ChangeBatchFrame {
                folder_group_id: GROUP.to_string(),
                changes: vec![change.to_wire_bytes()],
                compressed_changes: Vec::new(),
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();
        assert!(state.change_history_repository().dag_has_change(&change.compute_hash()).unwrap());
        assert!(!state
            .change_history_repository()
            .dag_list_unapplied_changes(GROUP)
            .unwrap()
            .is_empty());

        // Explicitly drive the same re-projection audit
        // `reconcile_local_materialization_audit` calls internally. The
        // block is still unfetchable (no reachable peer, same as above), so
        // projection still cannot succeed.
        session.reproject_unapplied_changes(GROUP, 1).await.unwrap();

        // The index record and a `Pending` materialization job exist (the
        // eager-fetch attempt was armed) but the block was never actually
        // obtained -- the file stays a `Placeholder`, never `Hydrated`.
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "still-unfetchable.bin")
                .unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder),
            "the file must still be a placeholder, not hydrated -- content was never obtained"
        );
        let still_unapplied =
            state.change_history_repository().dag_list_unapplied_changes(GROUP).unwrap();
        assert!(
            still_unapplied.iter().any(|c| c.compute_hash() == change.compute_hash()),
            "a change whose projection still cannot succeed must remain unapplied after an audit \
             attempt -- dag_mark_applied must only be called once projection actually succeeds, \
             not just because an audit ran"
        );
    }
}

#[cfg(test)]
mod reconcile_group_paths_flush_tests {
    use ed25519_dalek::SigningKey;
    use std::collections::{BTreeSet, HashMap};
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
    use yadorilink_local_capture::LocalChangeProcessor;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session_impl::{
        ChangeAuthenticator, PeerSyncSession, PeerSyncSessionOneTimeDeps, PendingLocalChangeFlush,
    };
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::file::{FileMeta, FileVersion};
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

    const GROUP: &str = "flush-guard-group";
    const REMOTE: &str = "device-remote";
    const LOCAL: &str = "device-local";
    const P: &str = "p.txt";
    const Q: &str = "q.txt";
    const LOCAL_EDIT: &[u8] = b"device-local's genuine concurrent edit";

    fn remote_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn local_key() -> SigningKey {
        SigningKey::from_bytes(&[8u8; 32])
    }

    struct TestAuthenticator {
        author_verifying_key: [u8; 32],
    }
    impl ChangeAuthenticator for TestAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == REMOTE).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    /// Zero-block content: materialization writes an empty file with no block
    /// fetch, so a remote change carrying only this version's metadata (never
    /// its blocks, exactly like the real wire) always materializes.
    fn empty_version() -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    /// A live channel with no reachable peer: `handle_change_batch` may enqueue
    /// an outbound change-request for a missing parent; the send simply queues.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        Arc::new(
            yadorilink_transport::PeerChannel::connect(
                local_secret,
                peer_public,
                0,
                Vec::new(),
                hub,
            )
            .await
            .unwrap(),
        )
    }

    fn batch_of(
        changes: &[&Change],
        versions: &[&FileVersion],
    ) -> yadorilink_sync_wire::ChangeBatchFrame {
        yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: changes.iter().map(|c| c.to_wire_bytes()).collect(),
            compressed_changes: Vec::new(),
            file_versions: versions.iter().map(|v| v.canonical_encoding()).collect(),
        }
    }

    /// The remote author's real, signed emission chain, built on a throwaway
    /// sender store so each change carries the correct parents/lamports.
    /// `ops_chain` is emitted oldest-first; each entry descends from the prior.
    fn emit_remote_chain(version: &FileVersion, ops_chain: Vec<Vec<Op>>) -> Vec<Change> {
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        dag_store::put_file_version(&sender, GROUP, version).unwrap();
        let emitter = ChangeEmitter::new(REMOTE, remote_key());
        ops_chain
            .into_iter()
            .map(|ops| {
                dag_store::emit_local_change(&sender, GROUP, ops, ChangeAuth::PLACEHOLDER, &emitter)
                    .unwrap()
            })
            .collect()
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }
    }
    fn update_op(path: &str, version: &FileVersion) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }
    }
    fn delete_op(path: &str) -> Op {
        Op::Delete { path: SyncPath(path.into()) }
    }

    /// Stands in for the daemon's `LinkFlushHandle`: when asked to flush a path
    /// that is marked pending, it dispatches the on-disk edit through the real
    /// `LocalChangeProcessor` emission path (index + DAG), exactly as a real
    /// debounce flush would. `pending` models what is sitting undispatched in
    /// the accumulator; `calls` records every path the session asked to flush,
    /// so a test can witness that the reconcile-site guard actually fired.
    struct RecordingFlush {
        processor: Arc<LocalChangeProcessor>,
        root: PathBuf,
        pending: Mutex<BTreeSet<String>>,
        calls: Mutex<Vec<String>>,
    }
    impl RecordingFlush {
        fn new(processor: Arc<LocalChangeProcessor>, root: PathBuf) -> Self {
            Self {
                processor,
                root,
                pending: Mutex::new(BTreeSet::new()),
                calls: Mutex::new(vec![]),
            }
        }
        fn mark_pending(&self, rel: &str) {
            self.pending.lock().unwrap().insert(rel.to_string());
        }
        fn take_calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }
    impl PendingLocalChangeFlush for RecordingFlush {
        fn flush_pending_local_change<'a>(
            &'a self,
            group_id: &'a str,
            rel_path: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(rel_path.to_string());
                // Drop the guard before the await below.
                let is_pending = self.pending.lock().unwrap().remove(rel_path);
                if is_pending {
                    let event = FsChangeEvent {
                        path: self.root.join(rel_path),
                        kind: FsChangeKind::CreatedOrModified,
                    };
                    let _ = self.processor.process_event(group_id, &self.root, &event).await;
                }
            })
        }
        fn flush_case_fold_sibling<'a>(
            &'a self,
            _group_id: &'a str,
            rel_path: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            // On a case-insensitive filesystem (e.g. the macOS test host) the
            // session also probes for a colliding sibling; this scenario stages
            // no case-fold sibling, so it is a recorded no-op.
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("casefold:{rel_path}"));
            })
        }
    }

    struct Harness {
        session: Arc<PeerSyncSession>,
        state: Arc<ReplicaCoordinator>,
        sync_root: PathBuf,
        /// Always wired in (see `setup`'s own doc comment): a test that never
        /// calls `flush.mark_pending` sees the exact same no-op behavior an
        /// absent handle used to produce, since `RecordingFlush` only ever
        /// dispatches a path it was told is pending.
        flush: Arc<RecordingFlush>,
        _root_dir: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
    }

    /// Builds a session with `TestAuthenticator` wired as its change
    /// authenticator (every test in this module needs to admit REMOTE's
    /// signed changes) and a `RecordingFlush` wired as its pending-local-
    /// change-flush handle, keyed to the harness's own `local_processor`/
    /// `sync_root`. The flush handle is installed unconditionally rather
    /// than only for the handful of tests that call `flush.mark_pending` --
    /// with nothing marked pending it never dispatches anything, so this is
    /// behaviorally identical to the deny-by-default no-op every other
    /// caller of `PeerSyncSessionOneTimeDeps::test_permissive` gets, and
    /// lets a test install a genuinely pending edit mid-test just by calling
    /// `h.flush.mark_pending(path)` without needing the session constructed
    /// any differently.
    async fn setup() -> Harness {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Kept as a concrete `Arc<FsBlockStore>` alongside its
        // `Arc<dyn BlockContentStore>` coercion: both `LocalChangeProcessor`
        // below and `PeerSyncSession` now take the same port trait, and a
        // concrete, still-Sized `BlockStore` implementor unsize-coerces
        // straight to it (see `yadorilink_local_storage::content_ports`'s module doc).
        let fs_store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> = fs_store.clone();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        // A live link always reaches Ready in a real daemon: app::run starts a
        // watcher for every link at boot, and add_link starts one immediately.
        // Peer apply for a live link that never registered a gate defers, so a
        // test that skipped this would be exercising a state the daemon does
        // not produce.
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        // The local-edit emitter shares the session's state AND block store, so
        // a flushed local edit is a live DAG head the reconcile reads and its
        // content is fetchable when materialized. Built before the session
        // (which used to be unnecessary when the flush handle was wired in
        // after the fact) since the session now needs it at construction.
        let local_processor = Arc::new(
            LocalChangeProcessor::new(
                state.clone(),
                fs_store.clone(),
                LOCAL.to_string(),
                std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
            )
            .with_change_emitter(Arc::new(ChangeEmitter::new(LOCAL, local_key()))),
        );
        let flush = Arc::new(RecordingFlush::new(local_processor.clone(), sync_root.clone()));

        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            LOCAL.to_string(),
            REMOTE.to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_verifying_key: remote_key().verifying_key().to_bytes(),
                }),
                pending_local_change_flush: flush.clone(),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        Harness { session, state, sync_root, flush, _root_dir: root_dir, _store_dir: store_dir }
    }

    fn conflict_copy_files(root: &Path) -> Vec<PathBuf> {
        let mut out = vec![];
        if let Ok(entries) = std::fs::read_dir(root) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().contains("(conflicted copy") {
                    out.push(e.path());
                }
            }
        }
        out
    }

    /// The local edit survives if it is present either as live `p.txt` or as a
    /// conflict-copy sibling — the two legitimate no-data-loss outcomes.
    fn local_edit_present(root: &Path, expected: &[u8]) -> bool {
        if std::fs::read(root.join(P)).map(|c| c == expected).unwrap_or(false) {
            return true;
        }
        conflict_copy_files(root)
            .iter()
            .any(|p| std::fs::read(p).map(|c| c == expected).unwrap_or(false))
    }

    /// Scenario (a): a genuinely concurrent local edit to P is captured by the
    /// admission-loop flush (P is the incoming change's own path) and preserved
    /// as a conflict copy rather than silently overwritten.
    #[tokio::test]
    async fn concurrent_edit_via_change_batch_preserves_local_edit_as_conflict_copy() {
        let h = setup().await;
        let version = empty_version();
        // C0 creates P (baseline), R updates P concurrently with the local edit.
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![update_op(P, &version)]],
        );
        let (c0, r) = (&chain[0], &chain[1]);

        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        // `handle_change_batch` now only admits the change and enqueues a
        // materialization job (CONV-1); drive the same projection step the
        // Convergence Engine would.
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        assert!(h.sync_root.join(P).exists(), "baseline P must materialize");

        let flush = h.flush.clone();

        // A real, still-pending local edit to P: bytes on disk, marked pending.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();
        flush.mark_pending(P);

        // R (remote update to P) is admitted. Its own path is P, so the
        // admission loop flushes P first, turning the pending edit into a
        // genuinely concurrent change.
        h.session.handle_change_batch(batch_of(&[r], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        let copies = conflict_copy_files(&h.sync_root);
        assert_eq!(copies.len(), 1, "exactly one conflict copy expected; found {copies:?}");
        assert!(
            local_edit_present(&h.sync_root, LOCAL_EDIT),
            "the local edit must survive as live content or a conflict copy"
        );
    }

    /// Scenario (a), no-flush variant: without the flush wired, the pending
    /// edit is invisible; the remote content wins with no conflict copy and the
    /// index no longer tracks the local edit. Pins that the flush is
    /// load-bearing for the admission path.
    #[tokio::test]
    async fn concurrent_edit_via_change_batch_without_flush_loses_local_edit() {
        let h = setup().await;
        let version = empty_version();
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![update_op(P, &version)]],
        );
        let (c0, r) = (&chain[0], &chain[1]);

        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        // Local edit on disk, but no flush handle wired: nothing dispatches it.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();

        h.session.handle_change_batch(batch_of(&[r], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        assert!(
            conflict_copy_files(&h.sync_root).is_empty(),
            "no flush => no concurrent change => no conflict copy"
        );
        let rec = h.state.file_index_repository().get_file(GROUP, P).unwrap().unwrap();
        assert!(
            !rec.deleted && rec.blocks.is_empty(),
            "the index adopted the remote (empty) content; the local edit is untracked/lost"
        );
    }

    /// Scenario (b) — the GAP-1 regression: an orphaned tombstone of P is
    /// promoted by a parent touching a DIFFERENT path Q, so the admission-loop
    /// flush never covers P. Only the flush hoisted ahead of the Absent
    /// (tombstone) resolution in `reconcile_group_paths` captures P's pending
    /// edit before the delete. Without that fix this test fails: P is deleted
    /// and the reconcile-site flush is never asked for P.
    #[tokio::test]
    async fn promoted_orphan_tombstone_flushes_pending_local_edit_before_delete() {
        let h = setup().await;
        let version = empty_version();
        // Chain: C0 create P -> Par create Q -> O delete P. O descends from Par.
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![create_op(Q, &version)], vec![delete_op(P)]],
        );
        let (c0, par, o) = (&chain[0], &chain[1], &chain[2]);

        // Baseline: adopt C0 so P is live on disk and in the index.
        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        assert!(h.sync_root.join(P).exists(), "baseline P must materialize");

        let flush = h.flush.clone();

        // O (delete P) arrives BEFORE its parent Par -> orphaned/held. Nothing
        // is pending yet, so the admission-loop flush of O's own path (P) is a
        // no-op: the local edit only lands afterwards. O is orphaned, so no
        // materialization job is enqueued for it yet — nothing to audit.
        h.session.handle_change_batch(batch_of(&[o], &[])).await.unwrap();
        assert!(h.sync_root.join(P).exists(), "O is orphaned; P must not be deleted yet");

        // NOW the genuine local edit to P lands in the accumulator.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();
        flush.mark_pending(P);
        // Drop the pre-edit admission-loop flush calls so the assertion below is
        // strictly about the reconcile-site flush.
        flush.take_calls();

        // Par (touches Q) arrives, admits, and promotes O. The admission loop
        // flushes only Q, never P — so the reconcile Absent-branch flush
        // (invoked, as it always was, inside the Convergence Engine's audit
        // pass rather than inline here) is the sole line of defense for P's
        // pending edit.
        h.session.handle_change_batch(batch_of(&[par], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        let calls = flush.take_calls();
        assert!(
            calls.iter().any(|c| c == P),
            "reconcile_group_paths must flush P before acting on its Absent (tombstone) \
             resolution; recorded calls: {calls:?}"
        );
        assert!(
            h.sync_root.join(P).exists(),
            "the concurrent local edit must survive the promoted-orphan tombstone, not be deleted"
        );
        assert_eq!(
            std::fs::read(h.sync_root.join(P)).unwrap(),
            LOCAL_EDIT,
            "P must still hold the local edit's content"
        );
        let rec = h.state.file_index_repository().get_file(GROUP, P).unwrap().unwrap();
        assert!(!rec.deleted, "P must remain live in the index, not tombstoned");
    }

    /// Scenario (b), no-flush variant: with no handle wired, the reconcile-site
    /// flush is a no-op, so the promoted tombstone deletes P — the exact
    /// pre-fix data loss. Confirms the flush call is what saves the edit.
    #[tokio::test]
    async fn promoted_orphan_tombstone_without_flush_deletes_pending_local_edit() {
        let h = setup().await;
        let version = empty_version();
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![create_op(Q, &version)], vec![delete_op(P)]],
        );
        let (c0, par, o) = (&chain[0], &chain[1], &chain[2]);

        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        h.session.handle_change_batch(batch_of(&[o], &[])).await.unwrap();
        // Local edit on disk, but no flush handle wired.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();
        h.session.handle_change_batch(batch_of(&[par], &[&version])).await.unwrap();
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        // No flush => the tombstone wins and P is deleted from the index.
        let rec = h.state.file_index_repository().get_file(GROUP, P).unwrap().unwrap();
        assert!(rec.deleted, "without the flush the promoted tombstone deletes P");
    }

    /// `change_emitter()` defaults to `None` -- the same safe, defined "no
    /// signing capability yet" state a session with no real change
    /// authenticator has for `change_authenticator()` -- for a session
    /// constructed with no emitter, and is `Some`, keyed to this device's
    /// own id and key, for one constructed with one wired in via
    /// `PeerSyncSessionOneTimeDeps::change_emitter`. This is the capability
    /// `captured_authoring::author_captured_change` will need at
    /// materialize time; this session does not call it yet.
    #[tokio::test]
    async fn change_emitter_defaults_to_none_and_is_wired_in_at_construction() {
        let h = setup().await;
        assert!(
            h.session.change_emitter().is_none(),
            "a session constructed with no emitter must have no signing capability wired"
        );

        let emitter = Arc::new(ChangeEmitter::new(LOCAL, local_key()));
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let with_emitter = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            LOCAL.to_string(),
            REMOTE.to_string(),
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
            store,
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            None,
            PeerSyncSessionOneTimeDeps {
                change_emitter: Some(emitter.clone()),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        let installed = with_emitter
            .change_emitter()
            .expect("must be Some for a session constructed with an emitter");
        assert_eq!(installed.device_id(), LOCAL, "the installed emitter must be this device's own");
    }
}

#[cfg(test)]
mod version_hash_exact_capability_tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session_impl::{
        durable_version_query_from_wire, PeerSyncSession,
    };
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

    const GROUP: &str = "handoff-group";

    /// A live channel to nowhere, sufficient to construct a `PeerSyncSession`
    /// for a purely local, no-network test — mirrors `promoted_orphan_
    /// projection_tests::unreachable_channel`.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    /// Claims a sync root for the group, as linking the folder does. Tests that
    /// index a file and then run a scan or repair need this: an unmarked root
    /// whose indexed files are all absent is indistinguishable from an unmounted
    /// volume, and is refused.
    fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
        yadorilink_root_authority::root_identity::VerifiedRoot::open(root, group, state).unwrap();
    }

    async fn new_session(
        state: Arc<ReplicaCoordinator>,
        store: Arc<dyn yadorilink_local_storage::BlockContentStore>,
    ) -> Arc<PeerSyncSession> {
        PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state,
            store,
            vec![GROUP.to_string()],
            HashMap::new(),
        )
    }

    /// A session holding no sync root for a group must refuse to resolve a
    /// local path for it, not fall back to a relative one.
    ///
    /// `new_session` above builds exactly that shape: shared groups, empty
    /// `sync_roots`. With the old empty-path default, `local_file_path` returned
    /// a bare relative `"file.txt"`, so every write for the group landed under
    /// the process's working directory instead of the user's folder — and
    /// `verify_write_target` could not catch it, because its fast path asks
    /// whether the target's parent IS the root, and `""` is trivially the parent
    /// of `"file.txt"`. Both the path and its guard failed open together.
    #[tokio::test]
    async fn missing_sync_root_refuses_to_resolve_a_local_path() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        let resolved = session.local_file_path(GROUP, "file.txt");
        assert!(
            resolved.is_err(),
            "a group with no sync root must not resolve to a path at all; got {resolved:?}"
        );

        // The write guard must refuse too, rather than waving through a
        // working-directory-relative target.
        let verified = session.verify_write_target(GROUP, std::path::Path::new("file.txt"));
        assert!(
            verified.is_err(),
            "the write-target guard must reject a target it cannot prove is under a known root"
        );
    }

    /// A freshly constructed session — never having run a `ClusterConfig`
    /// handshake at all, the same starting state as a session that DID run
    /// one against a peer predating this field (which always leaves it
    /// `false`) — must report the capability as not negotiated. Recording an
    /// advertisement of `true` then flips it, mirroring `record_peer_
    /// version_present_support`'s pattern this field's negotiation copies.
    #[tokio::test]
    async fn defaults_unsupported_and_flips_once_advertised() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        assert!(
            !session.version_hash_exact_negotiated(),
            "a session that never completed the handshake must default to unsupported, exactly \
             like a peer that predates the field"
        );

        session.record_peer_version_hash_exact_support(true);
        assert!(
            session.version_hash_exact_negotiated(),
            "recording a peer's advertised support must flip the negotiated flag"
        );

        // A `false` advertisement (or none at all) must never clear an
        // already-recorded `true` — the field only ever latches on, exactly
        // like every other one-shot capability flag in this file.
        session.record_peer_version_hash_exact_support(false);
        assert!(
            session.version_hash_exact_negotiated(),
            "a later false/absent advertisement must not un-negotiate an already-confirmed \
             capability"
        );
    }

    /// This build's own outgoing handshake always advertises the capability
    /// — it always enforces the exact-hash check on the answering side, so
    /// advertising anything else would be a lie a peer could rely on.
    #[tokio::test]
    async fn this_build_always_advertises_the_capability() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        let frame = session.cluster_config_message();
        let yadorilink_sync_wire::OutboundFrame::ClusterConfig(config) = frame else {
            panic!("cluster_config_message must produce a ClusterConfig frame");
        };
        assert!(
            config.supports_version_hash_exact,
            "this build's responder always enforces the exact-version-hash check, so it must \
             always advertise that capability"
        );
    }

    /// Regression lock on `holds_version_durably`'s pre-existing behavior:
    /// this capability-bit follow-up changes nothing about how the
    /// RESPONDER itself verifies a query. A retained version whose block
    /// list happens to coincide with the query's (here, because only the
    /// mtime differs) must still be rejected when the queried `version_hash`
    /// does not equal that retained version's actual identity; the exact
    /// matching hash is still accepted; and an absent `version_hash` (a
    /// querier built before that field existed) still fails closed rather
    /// than falling back to a block-hash-only match.
    #[tokio::test]
    async fn holds_version_durably_requires_exact_hash_and_group_provenance() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // `holds_version_durably`'s first condition requires this device be
        // a full replica (Eager materialization policy, the default) of the
        // group.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        let content = b"same bytes, different metadata";
        let hash_hex = store.put(content).unwrap();
        let hash_bytes = hex::decode(hash_hex.as_str()).unwrap();

        let record = FileRecord {
            path: "a.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo {
                hash: hash_bytes.clone(),
                offset: 0,
                size: content.len() as u32,
            }],
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let retained = state.sqlite().dag_list_versions(GROUP, "a.bin").unwrap();
        assert_eq!(retained.len(), 1, "the single upsert retains exactly one version");
        let actual_version_hash = retained[0].version_hash.0.to_vec();

        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );

        let base_query = proto::VersionPresentQuery {
            request_id: 1,
            folder_group_id: GROUP.to_string(),
            file_path: "a.bin".to_string(),
            block_hashes: vec![hash_bytes],
            for_handoff: true,
            version_hash: Vec::new(),
            block_sizes: vec![content.len() as u32],
        };

        // durable_version_query_from_wire now takes the peer_wire frame,
        // not the raw wire type -- convert at each call site (infallible,
        // same as the production conversion) rather than changing what
        // this test constructs, since proto::VersionPresentQuery is still
        // the realistic wire-level starting point.
        let frame = |q: &proto::VersionPresentQuery| {
            yadorilink_sync_wire::VersionPresentQueryFrame::try_from(q.clone()).unwrap()
        };

        let mismatched =
            proto::VersionPresentQuery { version_hash: vec![0xEEu8; 32], ..base_query.clone() };
        assert!(
            !session
                .replica_engine
                .holds_version_durably(&durable_version_query_from_wire(&frame(&mismatched)))
                .present,
            "block_hashes matching alone must not satisfy a for_handoff query whose \
             version_hash does not equal the retained version's actual identity"
        );

        let matching =
            proto::VersionPresentQuery { version_hash: actual_version_hash, ..base_query.clone() };
        assert!(
            !session
                .replica_engine
                .holds_version_durably(&durable_version_query_from_wire(&frame(&matching)))
                .present,
            "global block presence without this group's provenance must not prove custody"
        );

        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&matching.block_hashes[0]))
            .unwrap();
        assert!(
            session
                .replica_engine
                .holds_version_durably(&durable_version_query_from_wire(&frame(&matching)))
                .present,
            "the retained version's own exact version_hash alongside matching block_hashes/\
             block_sizes and group provenance must be confirmed present"
        );

        assert!(
            !session
                .replica_engine
                .holds_version_durably(&durable_version_query_from_wire(&frame(&base_query)))
                .present,
            "an absent version_hash (a querier that predates the field) must still fail closed, \
             not fall back to a block-hash-only match"
        );
    }

    /// Regression (data-loss): the LIVE peer-receive materialize path must
    /// itself journal a durable materialization intent, so a crash *after* it
    /// commits a brand-new `Hydrated` row but *before* the temp-write-then-rename
    /// lands is recovered by reconstructing the file — never misclassified as an
    /// offline delete and tombstoned group-wide.
    ///
    /// This drives the REAL `PeerSyncSession::materialize` eager path for a
    /// brand-new received file and simulates the crash by forcing the
    /// post-upsert disk-headroom preflight to fail: an error injected AFTER the
    /// durable row commit but BEFORE any file write, which leaves exactly the
    /// on-disk/index state a real crash-before-rename leaves — a `Hydrated` row,
    /// its blocks present locally, and no file on disk. Crucially it writes NO
    /// intent by hand; the whole point is that `materialize` must have written
    /// it. On the pre-fix code the live path wrote no intent, so this same state
    /// was read as an offline delete and the fresh file was tombstoned — the
    /// test is RED there and GREEN once the live path journals the intent.
    #[tokio::test]
    async fn live_materialize_crash_before_rename_is_reconstructed_not_deleted() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Claim the root while the index is still empty, the way linking a
        // folder does. Without it the repair below sees indexed files with no
        // bytes in an unmarked root -- byte-for-byte an unmounted volume -- and
        // correctly refuses to touch it.
        adopt_root(&state, GROUP, &sync_root);

        // The received content is already in this device's block store (the
        // eager fetch completed before the simulated crash), so
        // `ensure_blocks_present` short-circuits with no peer round trip and the
        // reconstruct during repair needs no network.
        let content = b"a freshly received file the crash must not destroy".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        // `ensure_blocks_present` only short-circuits a block already in the
        // CAS store when this group also has recorded provenance for it (a
        // physical hit alone might belong to another group) -- production's
        // real fetch path always records this alongside the store write, so
        // seed it here too, or the eager materialize below goes looking for
        // this "missing" block over the (deliberately unreachable) peer
        // channel and blocks for the full 30s hydration timeout instead of
        // exercising the crash-before-rename path this test is about.
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
            .unwrap();

        let record = FileRecord {
            path: "doc.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        // A live, started-up link is the only state a real daemon presents to a
        // peer session: `materialize` resolves its write target from the link
        // table on every call, and `wait_group_ready` defers a live link whose
        // startup never registered a gate.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // Force the post-upsert headroom preflight (which runs AFTER the durable
        // `Hydrated` row commit and BEFORE the reconstruct-to-disk write) to
        // fail, standing in for a process kill in that exact window. An
        // impossible headroom reserve guarantees `check_disk_headroom` rejects.
        session.set_headroom_enforced(true);
        session.set_headroom_override_bytes(Some(u64::MAX));

        // Drive the REAL eager materialize path. It must return the injected
        // disk-pressure error, having already committed the row.
        let out_path = sync_root.join("doc.txt");
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(result.is_err(), "the injected preflight failure must surface as an error");

        // The crash-before-rename state, produced entirely by the live path:
        // Hydrated row, blocks present, no file on disk — and, with the fix in
        // place, a materialization intent the live path wrote itself.
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "the durable row must have committed as Hydrated before the crash window"
        );
        assert!(!out_path.exists(), "no file was written before the simulated crash");
        assert!(
            state
                .materialization_job_repository()
                .has_materialization_intent(GROUP, "doc.txt")
                .unwrap(),
            "the LIVE materialize path must journal a durable intent before committing the \
             brand-new Hydrated row, so a crash in this window is recoverable"
        );

        // Repair (the production plain, no-emitter variant the daemon's startup/
        // periodic sweep runs) must RECONSTRUCT from the present blocks — never
        // classify this as an offline delete.
        let report = yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            state.as_ref(),
            store.as_ref(),
            &sync_root,
            GROUP,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        assert_eq!(
            report.reconstructed,
            vec!["doc.txt".to_string()],
            "a live-materialize crash-before-rename must be reconstructed"
        );
        assert!(
            report.offline_deleted.is_empty(),
            "the fresh file must NOT be misclassified as an offline deletion"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            content,
            "the reconstructed file must have exactly the received bytes"
        );
        assert!(
            state
                .file_index_repository()
                .get_file(GROUP, "doc.txt")
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "the index row must remain a live (not-deleted) record — no tombstone"
        );
    }

    /// A post-fetch failure inside `hydrate_file_with_timeout` (here: the
    /// pre-existing intermediate-directory-symlink escape guard,
    /// `verify_write_target`, refusing a root-escaping path) must not
    /// leave the row stuck at `Hydrating` forever -- every `?` between
    /// marking `Hydrating` and either `commit`ing or one of the two
    /// already-handled non-error exits used to have no rollback at all.
    /// Uses an already-locally-present block (seeded directly into the
    /// store with recorded provenance) so this test needs no live peer:
    /// `ensure_blocks_present` dedups on local presence + provenance
    /// before ever attempting a fetch.
    #[tokio::test]
    async fn hydrate_file_reverts_hydrating_state_on_a_post_fetch_failure() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "evil_link" inside the sync root points OUTSIDE it -- this
        // device's own local state, not anything peer-controlled.
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside_dir.path(), sync_root.join("evil_link")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside_dir.path(), sync_root.join("evil_link")).unwrap();

        let content = b"attacker-controlled content";
        let hash = hex::decode(store.put(content).unwrap()).unwrap();
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
            .unwrap();

        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "evil_link/pwned.txt".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "evil_link/pwned.txt",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let result = session
            .hydrate_file_with_timeout(
                GROUP,
                "evil_link/pwned.txt",
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(result.is_err(), "the symlink-escape write must be refused, not silently written");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "evil_link/pwned.txt")
                .unwrap(),
            Some(MaterializationState::Placeholder),
            "a post-fetch failure must revert the row, not leave it stuck at Hydrating"
        );
        assert!(
            !outside_dir.path().join("pwned.txt").exists(),
            "the write must not have escaped the sync root through the symlink"
        );
    }

    /// `hydrate_file`/`hydrate_file_with_timeout` must serialize on
    /// `ReplicaCoordinator::path_lock` for the whole attempt -- the root fix for
    /// the class of races the authoring-bound identity checks above only
    /// mitigate (they stop the INDEX from lying about a superseded row,
    /// but `reconstruct_file`'s temp-then-rename write itself could still
    /// interleave with a concurrent, legitimate materialize's own rename
    /// for the same path without this). Proven here by holding the lock
    /// externally (as any other writer for this path would) and
    /// confirming a concurrent `hydrate_file` call genuinely blocks
    /// rather than proceeding.
    #[tokio::test]
    async fn hydrate_file_serializes_on_the_same_path_lock_every_other_writer_uses() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        let content = b"hydrated content";
        let hash = hex::decode(store.put(content).unwrap()).unwrap();
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
            .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "doc.txt".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "doc.txt",
                MaterializationState::Placeholder,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // Held externally, exactly as `rematerialize_one_record`/
        // `reconcile_group_paths` would while materializing this same
        // path.
        let path_lock = state.path_lock_registry().path_lock(GROUP, "doc.txt");
        let external_guard = path_lock.lock().await;

        let session_clone = session.clone();
        let hydrate_task =
            tokio::spawn(async move { session_clone.hydrate_file(GROUP, "doc.txt").await });

        // Bounded wait, not a race: while the external lock is held,
        // hydration must not have even reached `Hydrating` yet.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Placeholder),
            "hydrate_file must block on the held path_lock, not proceed concurrently with it"
        );

        drop(external_guard);
        let result = hydrate_task.await.unwrap();

        assert!(matches!(
            result,
            Ok(yadorilink_peer_session::peer_session_impl::HydrationOutcome::Hydrated)
        ));
        assert_eq!(std::fs::read(sync_root.join("doc.txt")).unwrap(), content);
    }

    /// `HydratingStateGuard`'s revert-on-drop must not clobber a
    /// concurrent hydration attempt for the SAME path that already
    /// completed successfully. Even with `hydrate_file_with_timeout` now
    /// serializing on `path_lock` (see the test above), a losing internal
    /// race within one lock-holding attempt's own retry/backoff logic is
    /// still worth guarding directly at this layer too: if this guard's
    /// own attempt fails AFTER a different, concurrent
    /// attempt already committed a genuine `Hydrated`, an unconditional
    /// revert would silently downgrade that successful result back to
    /// `Placeholder` even though the file really is on disk -- a real
    /// regression an independent Codex review caught in this guard's
    /// first version, which used a blind `set_materialization_state`
    /// instead of a conditional transition.
    #[tokio::test]
    async fn hydrating_state_guard_does_not_clobber_a_concurrently_completed_hydration() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "doc.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "doc.txt",
                MaterializationState::Hydrating,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // This attempt's own guard, not yet committed -- as if this
        // attempt is still in flight (e.g. about to fail).
        let guard = yadorilink_peer_session::peer_session_impl::HydratingStateGuard {
            state: state.as_ref(),
            group_id: GROUP,
            path: "doc.txt",
            authoring_change_hash: None,
            committed: false,
        };

        // A DIFFERENT, concurrent attempt for the same path finishes
        // first and genuinely completes.
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "doc.txt",
                MaterializationState::Hydrated,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // This attempt's own guard now drops (uncommitted, simulating its
        // own late failure) -- it must NOT downgrade the row the
        // concurrent attempt already finished.
        drop(guard);

        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "a losing guard's revert-on-drop must not clobber a concurrently-completed \
             hydration's Hydrated state"
        );
    }

    /// A state-only CAS (the previous fix) is not enough on its own: it
    /// cannot distinguish "this row is still the SAME version this
    /// attempt started hydrating, just still `Hydrating`" from "a NEWER
    /// version of this same path became `current` mid-hydration (a
    /// peer's concurrent update superseding the row) and its own,
    /// unrelated hydration attempt happens to also be `Hydrating`". Only
    /// binding the CAS to the authoring identity captured before this
    /// attempt started closes that gap -- an independent review's own
    /// deeper counter-scenario to the state-only fix above.
    #[tokio::test]
    async fn hydrating_state_guard_does_not_clobber_a_superseding_newer_version() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "doc.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let old_hash = yadorilink_replica_domain::ids::ChangeHash([1u8; 32]);
        state
            .file_index_repository()
            .set_authoring_change_hash(GROUP, "doc.txt", &old_hash)
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "doc.txt",
                MaterializationState::Hydrating,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // This attempt's own guard, capturing the OLD version's authoring
        // identity, as `hydrate_file_with_timeout` does before it marks
        // the row `Hydrating`.
        let guard = yadorilink_peer_session::peer_session_impl::HydratingStateGuard {
            state: state.as_ref(),
            group_id: GROUP,
            path: "doc.txt",
            authoring_change_hash: Some(old_hash),
            committed: false,
        };

        // A peer's concurrent update supersedes the row with a genuinely
        // NEWER version, which independently starts its OWN hydration --
        // landing back at `Hydrating`, but for a different identity.
        let new_hash = yadorilink_replica_domain::ids::ChangeHash([2u8; 32]);
        state
            .file_index_repository()
            .set_authoring_change_hash(GROUP, "doc.txt", &new_hash)
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "doc.txt",
                MaterializationState::Hydrating,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // The OLD attempt's guard now drops (uncommitted) -- state alone
        // matches (`Hydrating`), but the authoring identity does not, so
        // this must be a no-op.
        drop(guard);

        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrating),
            "an old attempt's guard must not touch a newer version's own in-flight hydration \
             just because the state value happens to match"
        );
        assert_eq!(
            state.file_index_repository().get_authoring_change_hash(GROUP, "doc.txt").unwrap(),
            Some(new_hash),
            "the newer version's identity must be untouched"
        );
    }

    /// `verify_write_target` must refuse a write when the sync root's
    /// identity marker no longer matches what this device adopted, even
    /// though nothing about lexical path containment changed -- the
    /// scenario a bare `canonicalize`/containment check cannot see: an
    /// external volume unmounted and replaced by something else at the
    /// same mountpoint path during a long block fetch, between
    /// `materialize`'s own one-time `VerifiedRoot::verify` at its start
    /// and the physical write at the end. Simulated here by removing the
    /// marker file after adoption -- from `verify_write_target`'s
    /// perspective this is indistinguishable from "the mountpoint now
    /// names something else": both leave a directory that canonicalizes
    /// and lexically contains `out_path` just fine, with no valid marker.
    #[tokio::test]
    async fn verify_write_target_refuses_a_root_whose_marker_no_longer_matches() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // Sanity: an ordinary top-level path passes while the marker is
        // still intact.
        let out_path = sync_root.join("doc.txt");
        session.verify_write_target(GROUP, &out_path).unwrap();

        // Simulate the mountpoint being unmounted and replaced: the
        // directory itself still canonicalizes and still lexically
        // contains `out_path`, but it no longer carries this group's
        // identity marker.
        std::fs::remove_file(
            sync_root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let result = session.verify_write_target(GROUP, &out_path);
        assert!(
            result.is_err(),
            "a write target under a root whose marker no longer matches must be refused, not \
             just checked for lexical containment"
        );
    }

    /// `apply_locked_record`'s never-before-seen-path branch always calls
    /// `apply_incoming_wire_metadata` (which bootstraps a `version_seq = 0`
    /// scaffold row via `ensure_bootstrap_row_for_metadata`) BEFORE calling
    /// `materialize` — for every first-ever record for a path, tombstone
    /// included. So by the time `materialize`'s hazard-hold branch runs, a
    /// row for the tombstone's OWN path already exists even though this
    /// device never genuinely indexed anything there. `get_file(...)
    /// .is_some()` alone cannot tell the two apart; this drives `materialize`
    /// directly (bypassing the full wire/DAG-negotiation path, which turned
    /// out not to reliably deliver a delete-only change for a path with no
    /// prior history anywhere in the DAG in a plain integration-test setup)
    /// to reproduce exactly the caller-ordering `apply_locked_record` uses.
    #[tokio::test]
    async fn hazardous_tombstone_for_a_bootstrap_only_scaffold_is_not_held() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        // Adopt the (still-empty) root first, matching every other test in
        // this module -- `VerifiedRoot::open` refuses a folder that already
        // has un-adopted content on disk with no root marker.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "Photo.jpg" is live and materialized -- the sibling the tombstone
        // will collide with.
        std::fs::write(sync_root.join("Photo.jpg"), b"original photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"original photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().is_none(),
            "precondition: no prior row at all for the tombstone's own path"
        );

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        // Exactly what `apply_locked_record`'s never-seen branch does before
        // calling `materialize`, for every first-ever record for a path.
        yadorilink_peer_session::peer_session_impl::apply_incoming_wire_metadata(
            state.as_ref(),
            GROUP,
            &tombstone,
            &yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
                record_kind: yadorilink_replica_domain::file::RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                exec_bit: false,
                authoring_change_hash: None,
                origin_device_id: None,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().is_some(),
            "the bootstrap must have created a scaffold row -- this is the shape of the gap, \
             not the fix"
        );

        let result = session
            .materialize(GROUP, &tombstone, MaterializationPolicy::Eager, "device-a", None)
            .await
            .unwrap();

        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_none(),
            "a hazardous tombstone must not be held on a bootstrap-only scaffold -- there was \
             never any genuine content here to protect"
        );
        assert!(
            matches!(
                result,
                yadorilink_peer_session::peer_session_impl::MaterializeResult::RetryRequired
            ),
            "nothing was actually recorded (no hold, no delete) -- a caller must not treat this \
             path as resolved for this attempt, or a sending peer that later disappears leaves \
             this deletion permanently unconverged"
        );
        assert_eq!(
            std::fs::read(sync_root.join("Photo.jpg")).unwrap(),
            b"original photo bytes",
            "the sibling must remain untouched"
        );
    }

    /// Holding a hazardous tombstone against a GENUINE live row must report
    /// `RetryRequired`, not `Settled`: `set_held` only stamps `held_reason`
    /// onto the still-live row -- it records neither the pending
    /// tombstone's authoring identity nor that a deletion is pending at
    /// all -- so nothing downstream can tell "durably resolved" from "live
    /// file that happens to carry a hold reason". `Settled` here used to
    /// feed straight into `reproject_unapplied_changes` marking this
    /// tombstone's own DAG change permanently `applied`, which stops this
    /// crate's only periodic convergence sweep from ever re-examining it
    /// again even though nothing was deleted.
    #[tokio::test]
    async fn hazardous_tombstone_of_a_genuine_live_row_reports_retry_required() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "Photo.jpg" is live and materialized -- the sibling the tombstone
        // will collide with. On a case-insensitive filesystem "Photo.jpg"
        // and "photo.jpg" are the SAME on-disk entry, so "photo.jpg"'s own
        // genuine index row (below) is index-only, matching every other
        // test in this file that constructs this scenario.
        std::fs::write(sync_root.join("Photo.jpg"), b"original photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"original photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // "photo.jpg" itself already has a GENUINE (version_seq > 0), live
        // (not deleted) row -- unlike the bootstrap-scaffold test above.
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let result = session
            .materialize(GROUP, &tombstone, MaterializationPolicy::Eager, "device-a", None)
            .await
            .unwrap();

        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_some(),
            "the genuine live row must still be marked held"
        );
        assert!(
            matches!(
                result,
                yadorilink_peer_session::peer_session_impl::MaterializeResult::RetryRequired
            ),
            "holding a genuine live row is not durable convergence -- the pending tombstone's \
             identity is nowhere recorded, so this must not be reported as settled"
        );

        let first_held_since = state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .unwrap()
            .since_unix_nanos;
        // `RetryRequired` means the periodic materialization audit
        // re-drives this exact path every tick while the collision
        // persists -- re-materializing the identical tombstone must not
        // reset `held_since_unix_nanos` to "now" each time, or a path
        // held for hours would always read as held for a moment.
        std::thread::sleep(std::time::Duration::from_millis(5));
        session
            .materialize(GROUP, &tombstone, MaterializationPolicy::Eager, "device-a", None)
            .await
            .unwrap();
        let second_held_since = state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .unwrap()
            .since_unix_nanos;
        assert_eq!(
            first_held_since, second_held_since,
            "held_since_unix_nanos must not advance on a re-drive with the same hold reason"
        );
    }

    /// A tombstone that already landed cleanly (row `deleted = true`,
    /// `clear_held` already ran) must not become held again just because a
    /// peer's periodic full-index resend redelivers it after a fresh
    /// collision appears. Holding it would leave a `held_reason` on an
    /// already-tombstoned row -- the "orphaned held entry" state
    /// `clear_held`'s own doc comment says this crate deliberately avoids.
    #[tokio::test]
    async fn hazardous_redelivery_of_an_already_landed_tombstone_is_not_held() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "photo.jpg" already landed as a clean tombstone -- no collision
        // existed when it was applied, so nothing is held.
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .is_none());

        // "Photo.jpg" now becomes live -- a fresh collision the original
        // tombstone application never saw.
        std::fs::write(sync_root.join("Photo.jpg"), b"fresh photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // The same tombstone, redelivered (a peer's periodic full-index
        // resend) after the fresh collision now exists.
        let redelivered_tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let result = session
            .materialize(
                GROUP,
                &redelivered_tombstone,
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();

        assert!(
            matches!(
                result,
                yadorilink_peer_session::peer_session_impl::MaterializeResult::Settled
            ),
            "this deletion already converged (the row is already a genuine tombstone, not a \
             scaffold) -- reporting RetryRequired here would churn forever on a redundant resend"
        );
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_none(),
            "redelivering an already-landed tombstone must not mark its own (already deleted) \
             row held"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().unwrap().deleted,
            "the row must remain a clean tombstone"
        );
    }

    /// Direct-unit-test half of the authoring-advance fix: `materialize`'s
    /// already-a-genuine-tombstone fast path must actually write a
    /// differing supplied `authoring_change_hash` to the column, not
    /// silently keep whatever was there before. This drives `materialize`
    /// directly (bypassing `apply_locked_record`'s causal-ordering gate),
    /// so it does NOT by itself prove the column is only ever advanced to
    /// a genuinely NEWER identity -- `materialize` trusts its caller for
    /// that; see `redelivery_of_a_real_dag_descendant_tombstone_
    /// advances_authoring_identity_through_the_ordering_gate` (in
    /// `dag_convergence_authority_tests`) for the version that goes
    /// through real admitted DAG changes and `apply_locked_record`'s
    /// `ChangeOrdering::Before` gate.
    #[tokio::test]
    async fn hazardous_tombstone_materialize_advances_a_differing_authoring_hash() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert_eq!(
            state.file_index_repository().get_authoring_change_hash(GROUP, "photo.jpg").unwrap(),
            None,
            "precondition: no authoring identity recorded yet"
        );

        std::fs::write(sync_root.join("Photo.jpg"), b"fresh photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let newer_tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let newer_hash = yadorilink_replica_domain::ids::ChangeHash([7u8; 32]);
        let result = session
            .materialize(
                GROUP,
                &newer_tombstone,
                MaterializationPolicy::Eager,
                "device-a",
                Some(&newer_hash),
            )
            .await
            .unwrap();

        assert!(matches!(
            result,
            yadorilink_peer_session::peer_session_impl::MaterializeResult::Settled
        ));
        assert_eq!(
            state.file_index_repository().get_authoring_change_hash(GROUP, "photo.jpg").unwrap(),
            Some(newer_hash),
            "the row's authoring identity must advance to the newer descendant tombstone, not \
             stay stuck at whatever it was stamped with before"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().unwrap().deleted,
            "still a clean tombstone, not adopted content"
        );
    }

    /// `materialize` must refuse a peer-advertised path naming a versioned
    /// reserved-namespace artefact, regardless of how the record got here
    /// (see the comment at the check site in `materialize` for why this is
    /// defense-in-depth rather than the only guard).
    #[tokio::test]
    async fn materialize_rejects_a_versioned_artefact_path() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
            "deadbeef",
        )
        .unwrap();
        let record = FileRecord {
            path: artefact_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
            "expected a ReservedNamespaceCollision naming the artefact path, got {result:?}"
        );
        assert!(!sync_root.join(&artefact_path).exists());
    }

    /// THE remote-materialization hole this pins closed: a peer-driven
    /// `materialize` call naming this device's own sync-root lock file must
    /// be refused, driven through the real `materialize` entry point (not a
    /// bare predicate call). Without this, a change that skipped or
    /// predated admission's own `validate_no_reserved_paths` check would
    /// still reach disk here, replacing the on-disk lock file out from
    /// under this device's live OS lock — the exact "two processes both
    /// believe they own this root" state `sync_root_lock` exists to
    /// prevent.
    #[tokio::test]
    async fn materialize_rejects_the_sync_root_lock_path() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let lock_path =
            yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME.to_string();
        let record = FileRecord {
            path: lock_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &lock_path),
            "expected a ReservedNamespaceCollision naming the sync-root lock path, got {result:?}"
        );
        assert!(!sync_root.join(&lock_path).exists());
    }

    /// Windows drops trailing `.`/` ` in most Win32 path APIs, so a peer
    /// that spells the reserved name with a trailing dot or space types a
    /// path that is not literally the reserved name, but would land on
    /// disk — on a Windows device — as exactly the reserved name. Landing
    /// in the fail-closed direction is still a real defect: it lets any
    /// peer name (and thereby permanently block, via
    /// `ReservedNamespaceCollision`) an arbitrary path on someone else's
    /// device without ever spelling the exact reserved name on the wire.
    /// `materialize` must reject both forms regardless of which platform
    /// is running the check.
    #[tokio::test]
    async fn materialize_rejects_a_versioned_artefact_path_with_windows_trailing_normalization() {
        for suffix in [" ", "."] {
            let store_dir = tempfile::tempdir().unwrap();
            let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
                Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
            let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
            let root_dir = tempfile::tempdir().unwrap();
            let sync_root = root_dir.path().canonicalize().unwrap();
            state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
            adopt_root(&state, GROUP, &sync_root);
            let generation = state.startup_readiness().begin_group_startup(GROUP);
            state.startup_readiness().mark_group_ready(GROUP, generation);
            let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
            let session = PeerSyncSession::new(
                unreachable_channel().await,
                "device-b".to_string(),
                "device-a".to_string(),
                state.clone(),
                store.clone(),
                vec![GROUP.to_string()],
                sync_roots,
            );

            let artefact_path = format!(
                "{}{suffix}",
                yadorilink_root_authority::reserved_namespace::artefact_component_name(
                    yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
                    "deadbeef",
                )
                .unwrap()
            );
            let record = FileRecord {
                path: artefact_path.clone(),
                size: 0,
                mtime_unix_nanos: 1,
                blocks: Vec::new(),
                deleted: false,
            };
            let result = session
                .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
                .await;
            assert!(
                matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
                "suffix {suffix:?}: expected a ReservedNamespaceCollision, got {result:?}"
            );
        }
    }

    /// The converse of the artefact-rejection test above, and the fix for a
    /// real defect: a path merely containing the LEGACY `.yadorilink-tmp.`
    /// substring (e.g. a genuine user file named
    /// `report.yadorilink-tmp.old`) must still materialize normally.
    /// `materialize` keys its rejection on `path_has_artefact_component`,
    /// not the broader exclusion predicate `path_has_reserved_component` —
    /// the legacy marker is a substring match precisely because arbitrary
    /// user content can precede it, and
    /// `materialization::cleanup_stale_temp_files` already refuses to
    /// delete exactly such a look-alike. Pointing `materialize`'s check
    /// back at the exclusion predicate makes this test fail.
    #[tokio::test]
    async fn materialize_still_writes_a_legacy_marker_look_alike_user_file() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let content = b"my actual notes, not a temp file".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
            .unwrap();
        let path = "report.yadorilink-tmp.old".to_string();
        let record = FileRecord {
            path: path.clone(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            result.is_ok(),
            "a legacy-marker look-alike user file must still materialize: {result:?}"
        );
        assert_eq!(std::fs::read(sync_root.join(&path)).unwrap(), content);
    }

    /// A trailing space makes this path non-portable (Windows silently
    /// drops it), independently of whether the path also happens to look
    /// like a legacy marker — the non-portability check must reject it
    /// before materialize ever reaches the legacy-marker/artefact
    /// classification at all. See
    /// `materialize_still_writes_a_legacy_marker_look_alike_user_file` for
    /// the sibling case (same look-alike name, no trailing space) that
    /// confirms the legacy-marker substring match alone must not block an
    /// ordinary user file, and
    /// `reserved_namespace::tests::wire_predicate_still_excludes_the_legacy_marker_with_a_trailing_space`
    /// for where the narrower "trailing-space stripping must not widen the
    /// artefact predicate" property this test used to pin now lives — it
    /// can no longer be exercised through this full materialize pipeline,
    /// since the non-portability check refuses the path before the
    /// artefact-vs-legacy classification is ever reached.
    #[tokio::test]
    async fn materialize_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker()
    {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let content = b"my actual notes, not a temp file".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
            .unwrap();
        let path = "report.yadorilink-tmp.old ".to_string();
        let record = FileRecord {
            path: path.clone(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::NonPortablePath(ref p)) if p == &path),
            "a path with a trailing space must be rejected as non-portable, not materialized: \
             {result:?}"
        );
        assert!(!sync_root.join(&path).exists());
    }

    /// The actual data-loss shape this whole check exists to prevent,
    /// proven through the real `materialize` entry point rather than only
    /// against the predicate: two distinct logical paths that a Windows
    /// device's own path normalization would resolve onto ONE on-disk name
    /// (`"a"` and `"a "`, differing only in a trailing space) must never
    /// both be allowed to reach disk. This host cannot reproduce the
    /// actual on-disk aliasing (only a real Windows filesystem silently
    /// drops the trailing space), but it can — and must — prove the
    /// mechanism that prevents it on every host: the first, ordinary path
    /// materializes normally, and the second, would-be-colliding path is
    /// refused outright, leaving the first file's bytes on disk exactly as
    /// they were.
    ///
    /// Without the refusal, a Windows device receiving both changes would
    /// silently let the second overwrite the first with no conflict ever
    /// detected (they are different index paths, so no DAG conflict
    /// machinery ever compares them), while its own index kept believing
    /// both were independently, correctly `Hydrated` — permanent,
    /// undetectable data loss. The sibling
    /// `materialize_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker`
    /// test only pins the predicate for a single path considered in
    /// isolation; this one pins the actual collision it exists to prevent.
    #[tokio::test]
    async fn materialize_refuses_a_colliding_trailing_space_variant_of_an_already_materialized_path(
    ) {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let original_content = b"the original file, must survive untouched".to_vec();
        let original_hash = hex::decode(store.put(&original_content).unwrap()).unwrap();
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&original_hash))
            .unwrap();
        let original_path = "a".to_string();
        let original_record = FileRecord {
            path: original_path.clone(),
            size: original_content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo {
                hash: original_hash,
                offset: 0,
                size: original_content.len() as u32,
            }],
            deleted: false,
        };
        session
            .materialize(GROUP, &original_record, MaterializationPolicy::Eager, "device-a", None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(sync_root.join(&original_path)).unwrap(), original_content);

        // A distinct logical path that a Windows device would resolve onto
        // the SAME on-disk name as `original_path` — different content, so
        // an undetected collision would silently destroy `original_content`.
        let colliding_content = b"a different peer's write, must never land here".to_vec();
        let colliding_hash = hex::decode(store.put(&colliding_content).unwrap()).unwrap();
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&colliding_hash))
            .unwrap();
        let colliding_path = "a ".to_string();
        let colliding_record = FileRecord {
            path: colliding_path.clone(),
            size: colliding_content.len() as u64,
            mtime_unix_nanos: 2,
            blocks: vec![BlockInfo {
                hash: colliding_hash,
                offset: 0,
                size: colliding_content.len() as u32,
            }],
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &colliding_record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            matches!(
                result,
                Err(yadorilink_peer_session::error::PeerSessionError::NonPortablePath(ref p)) if p == &colliding_path
            ),
            "the colliding trailing-space path must be refused, not materialized: {result:?}"
        );

        // The original file must be completely untouched — no collision,
        // no partial overwrite, no trace of the refused write.
        assert_eq!(
            std::fs::read(sync_root.join(&original_path)).unwrap(),
            original_content,
            "a refused colliding write must never disturb the original path's bytes"
        );
        assert!(!sync_root.join(&colliding_path).exists());
    }

    /// NTFS `filename::$DATA` addresses `filename`'s own default stream —
    /// the same on-disk object — so `materialize` must refuse an
    /// ADS-suffixed alias for a versioned artefact exactly like the
    /// un-suffixed name, or a peer could get such a record admitted and
    /// later write through the alias into the artefact's own bytes.
    #[tokio::test]
    async fn materialize_rejects_an_alternate_data_stream_alias_for_a_versioned_artefact() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let artefact_path = format!(
            "{}::$DATA",
            yadorilink_root_authority::reserved_namespace::artefact_component_name(
                yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
                "deadbeef",
            )
            .unwrap()
        );
        let record = FileRecord {
            path: artefact_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
            "expected a ReservedNamespaceCollision naming the ADS-aliased path, got {result:?}"
        );
        assert!(!sync_root.join(&artefact_path).exists());
    }

    /// `change::validate_path` accepts both `/` and `\` as separators, so
    /// `materialize` must reject a backslash-delimited artefact component
    /// the same on every host — resolving `record.path` through the local
    /// `std::path::Path` type instead would make this check's outcome
    /// depend on which platform happens to be running it.
    #[tokio::test]
    async fn materialize_rejects_a_backslash_delimited_artefact_path_on_every_host() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        let artefact_path = format!(
            "safe\\{}",
            yadorilink_root_authority::reserved_namespace::artefact_component_name(
                yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
                "cafef00d",
            )
            .unwrap()
        );
        let record = FileRecord {
            path: artefact_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
            "expected a ReservedNamespaceCollision naming the backslash-delimited path, got {result:?}"
        );
    }

    /// The converse guardrail on the same seam: a FULLY successful live
    /// materialize must CLEAR its intent (right after the durable rename, before
    /// the post-write exec-bit touch), so the intent can never linger under a
    /// `Hydrated`+present file. If it lingered, a later genuine offline delete of
    /// that path would read `missing + intent present` and wrongly resurrect the
    /// file from its still-present blocks — the exact misclassification the
    /// journal exists to prevent, in the opposite direction. This drives the real
    /// `materialize` to success, asserts no intent remains, then deletes the file
    /// offline and asserts repair classifies it as a delete, not a reconstruct.
    #[tokio::test]
    async fn live_materialize_success_clears_intent_so_a_later_offline_delete_is_not_resurrected() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Claim the root while the index is still empty, the way linking a
        // folder does. Without it the repair below sees indexed files with no
        // bytes in an unmarked root -- byte-for-byte an unmounted volume -- and
        // correctly refuses to touch it.
        adopt_root(&state, GROUP, &sync_root);

        let content = b"received, materialized cleanly, later deleted offline".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        // See the sibling crash-before-rename test's identical seed for why:
        // without recorded group provenance, `ensure_blocks_present` treats
        // this block as missing for this group and the eager materialize
        // blocks on the unreachable peer channel for the full hydration
        // timeout instead of completing.
        state
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
            .unwrap();

        let record = FileRecord {
            path: "doc.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        // A live, started-up link is the only state a real daemon presents to a
        // peer session: `materialize` resolves its write target from the link
        // table on every call, and `wait_group_ready` defers a live link whose
        // startup never registered a gate.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // No injected fault: the real eager materialize runs to completion.
        let out_path = sync_root.join("doc.txt");
        session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a", None)
            .await
            .expect("a clean materialize must succeed");
        assert_eq!(std::fs::read(&out_path).unwrap(), content, "the file must be materialized");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrated)
        );
        // The crux: the success path cleared the intent after the durable rename.
        assert!(
            !state
                .materialization_job_repository()
                .has_materialization_intent(GROUP, "doc.txt")
                .unwrap(),
            "a completed materialize must leave NO materialization intent"
        );

        // The user deletes the file while the daemon is stopped. The row is still
        // Hydrated, blocks still present, and — because the intent was cleared —
        // this is a genuine offline delete, not a crash.
        std::fs::remove_file(&out_path).unwrap();
        let report = yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            state.as_ref(),
            store.as_ref(),
            &sync_root,
            GROUP,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        assert!(
            report.reconstructed.is_empty(),
            "a cleanly-materialized-then-offline-deleted file must NOT be reconstructed"
        );
        assert_eq!(
            report.offline_deleted,
            vec!["doc.txt".to_string()],
            "the missing file with no intent must be classified as an offline deletion"
        );
        assert!(!out_path.exists(), "repair must not resurrect the offline-deleted file");
    }
}

#[cfg(test)]
mod dag_negotiated_restart_regression_tests {
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_daemon::dag_import;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
    use yadorilink_local_capture::LocalChangeProcessor;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session_impl::{
        change_hash_to_wire, ChangeAuthenticator, PeerSyncSession, PeerSyncSessionOneTimeDeps,
    };
    use yadorilink_replica_domain::admission::ChangeEmitter;
    use yadorilink_replica_domain::change::Op;
    use yadorilink_root_authority::ignore_patterns::EffectiveIgnoreSet;

    const GROUP: &str = "restart-dag-negotiated-group";

    /// Pins one author's verifying key and treats it as a writer — the same
    /// shape `promoted_orphan_projection_tests`' `TestAuthenticator` uses.
    struct TestAuthenticator {
        author_device_id: String,
        author_verifying_key: [u8; 32],
    }

    impl ChangeAuthenticator for TestAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == self.author_device_id).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    /// A live channel with no reachable peer on the other end, exactly as
    /// `promoted_orphan_projection_tests::unreachable_channel` builds one:
    /// sending on it simply queues a datagram nobody reads (the send half
    /// stays open), which is all `handle_heads_announce` needs to run its
    /// real request-computation logic without a live two-sided connection.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    #[tokio::test]
    async fn startup_scan_change_must_reach_dag_negotiated_peer() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();

        // ---- The local device: existing DAG history, then an offline edit
        // ---- picked up only by the restart scan.
        let store_dir_a = tempfile::tempdir().unwrap();
        let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let state_a = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();

        let emitter = Arc::new(ChangeEmitter::new("device-a", signing_key.clone()));
        let processor = LocalChangeProcessor::new(
            state_a.clone(),
            store_a.clone(),
            "device-a".to_string(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(emitter.clone());
        // As the peer side below already does: the later offline edit and
        // restart scan leave the index and disk disagreeing on the same
        // path, indistinguishable from an unmounted volume unless the
        // folder's identity was established first, as a real link's would
        // have been. A real link row is required too: `set_link_root_token_
        // for_group` is an `UPDATE ... WHERE group_id = ?` with no matching
        // row otherwise, so without it the token silently never persists
        // and the live `process_event` call below (which requires the
        // persisted token, unlike `open`) fails with "no previously-adopted
        // root token".
        state_a.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &root,
            GROUP,
            state_a.as_ref(),
        )
        .unwrap();

        let file_path = root.join("notes.txt");
        std::fs::write(&file_path, b"version one").unwrap();
        processor
            .process_event(
                GROUP,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
        let heads_v1 = state_a.sqlite().dag_group_heads(GROUP).unwrap();
        assert_eq!(heads_v1.len(), 1, "sanity: one DAG head after the initial live edit");
        let change_v1 = state_a.sqlite().dag_get_change(&heads_v1[0]).unwrap().unwrap();
        let version_hash_v1 = match &change_v1.ops[0] {
            Op::Put { version, .. } => *version,
            other => panic!("expected the initial edit to be a Put op, got {other:?}"),
        };
        let version_v1 =
            state_a.sqlite().dag_get_file_version(GROUP, &version_hash_v1).unwrap().unwrap();

        // ---- The peer: a change-history-aware device that already synced
        // ---- up to the pre-restart head, exactly as if it had connected
        // ---- and pulled it earlier.
        let store_dir_b = tempfile::tempdir().unwrap();
        let store_b: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());
        // Retain a handle to the peer's block store so the test can supply the
        // block content the peer would fetch over a live channel — the
        // `unreachable_channel` delivers no `BlockResponse`, so without this the
        // peer's records stay content-less bootstrap scaffolds that never
        // materialize either version's bytes.
        let store_b_seed = store_b.clone();
        let state_b = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let peer_root_dir = tempfile::tempdir().unwrap();
        let peer_root = peer_root_dir.path().canonicalize().unwrap();
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state_b.link_repository().add_link(&peer_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &peer_root,
            GROUP,
            state_b.as_ref(),
        )
        .unwrap();
        let generation = state_b.startup_readiness().begin_group_startup(GROUP);
        state_b.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), peer_root)]);

        let session_b = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state_b.clone(),
            store_b,
            vec![GROUP.to_string()],
            sync_roots,
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        // The peer fetches v1's block content as part of pulling the
        // pre-restart head (a live channel carries it in a `BlockResponse`).
        // Seeding the bytes straight into the peer's own CAS store models
        // that fetch's *end state*, but skips the provenance record the real
        // fetch path (`ensure_blocks_present`) always writes alongside it --
        // without it, `handle_change_batch`'s materialize sees the block
        // physically present but not provenanced for this group, so it
        // tries to re-fetch over the (deliberately unreachable) channel and
        // blocks for the full 30s hydration timeout instead of using it.
        let hash_v1 = store_b_seed.put(b"version one").unwrap();
        state_b
            .change_history_repository()
            .record_group_block_provenance(
                GROUP,
                std::slice::from_ref(&hex::decode(&hash_v1).unwrap()),
            )
            .unwrap();
        let batch = yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: vec![change_v1.to_wire_bytes()],
            compressed_changes: Vec::new(),
            file_versions: vec![version_v1.canonical_encoding()],
        };
        session_b.handle_change_batch(batch).await.unwrap();
        // `handle_change_batch` only admits the change and enqueues a
        // materialization job now (CONV-1); drive the same projection step
        // the Convergence Engine would.
        session_b.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        assert!(
            state_b.change_history_repository().dag_has_change(&heads_v1[0]).unwrap(),
            "sanity: the peer admitted the pre-restart change the normal way"
        );
        let peer_record_v1 =
            state_b.file_index_repository().get_file(GROUP, "notes.txt").unwrap().unwrap();

        // ---- The local device "restarts": the file was edited offline, so
        // ---- only the startup scan (never a live `process_event`) notices
        // ---- it, exactly mirroring `local_change.rs`'s own restart test.
        std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records =
            processor.scan_existing_files_with_ignore(GROUP, &root, &ignore_set).unwrap();
        assert!(!scan_records.is_empty(), "sanity: the restart scan must notice the offline edit");
        dag_import::ensure_initial_import(state_a.as_ref(), GROUP, &emitter).unwrap();
        let heads_after_restart = state_a.sqlite().dag_group_heads(GROUP).unwrap();

        // ---- The local device announces its (possibly stale) heads to the
        // ---- DAG-negotiated peer, exactly as `announce_local_commit`/the
        // ---- daemon's post-restart announce would.
        let announce = yadorilink_sync_wire::HeadsAnnounceFrame {
            folder_group_id: GROUP.to_string(),
            heads: heads_after_restart.iter().map(change_hash_to_wire).collect(),
        };
        session_b.handle_heads_announce(announce).await.unwrap();

        // The fix advanced the announced heads past what the peer holds, so
        // the announce identified a genuinely missing change the peer now
        // knows to request (with the bug the announced heads were byte-
        // identical to the peer's, so it had nothing to ask for and never
        // converged). `handle_heads_announce` requested exactly that change
        // over the channel; serve the response the announcer would send back
        // over a live connection — the change plus its file version — since
        // the test's `unreachable_channel` carries no reply of its own.
        assert_ne!(
            heads_after_restart, heads_v1,
            "the restart scan must advance the announced heads so the peer has the offline \
             edit to request"
        );
        assert!(
            !state_b.change_history_repository().dag_has_change(&heads_after_restart[0]).unwrap(),
            "sanity: the peer is missing the newly-announced change before it is served"
        );
        let change_v2 = state_a.sqlite().dag_get_change(&heads_after_restart[0]).unwrap().unwrap();
        let version_hash_v2 = change_v2
            .ops
            .iter()
            .find_map(|op| match op {
                Op::Put { version, .. } => Some(*version),
                _ => None,
            })
            .expect("the offline edit change must carry a content op");
        let version_v2 =
            state_a.sqlite().dag_get_file_version(GROUP, &version_hash_v2).unwrap().unwrap();
        // The peer fetches the offline edit's block content, exactly as it
        // would over a live channel in response to the change request the
        // announce triggered above -- same provenance seed as v1 above, for
        // the same reason.
        let hash_v2 =
            store_b_seed.put(b"version two, edited while the daemon was stopped").unwrap();
        state_b
            .change_history_repository()
            .record_group_block_provenance(
                GROUP,
                std::slice::from_ref(&hex::decode(&hash_v2).unwrap()),
            )
            .unwrap();
        let batch_v2 = yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: vec![change_v2.to_wire_bytes()],
            compressed_changes: Vec::new(),
            file_versions: vec![version_v2.canonical_encoding()],
        };
        session_b.handle_change_batch(batch_v2).await.unwrap();
        session_b.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        // ---- The peer must have learned about the offline edit. It must
        // ---- not still be sitting on the pre-restart (V1) content.
        let peer_record_after =
            state_b.file_index_repository().get_file(GROUP, "notes.txt").unwrap().unwrap();
        assert_ne!(
            peer_record_after.blocks, peer_record_v1.blocks,
            "a DAG-heads-negotiated peer must receive the offline edit the restart scan \
             reconciled locally, not remain stuck on the pre-restart content because the \
             announced heads never advanced past what the peer already has"
        );
    }
}

#[cfg(test)]
mod dag_convergence_authority_tests {
    use yadorilink_peer_session::peer_session_impl::{
        ChangeAuthenticator, PeerSyncSession, PeerSyncSessionOneTimeDeps,
    };

    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion};
    use yadorilink_replica_domain::file::{FileRecord, RecordKind};
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

    const GROUP: &str = "shared-group";
    const OLD_MTIME: i64 = 1_000; // lamport WINNER carries the OLDER mtime …
    const NEW_MTIME: i64 = 9_000; // … and the mtime winner is the lamport LOSER.

    struct Harness {
        session: Arc<PeerSyncSession>,
        state: Arc<ReplicaCoordinator>,
        _root: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        root: std::path::PathBuf,
    }

    /// A live channel with no reachable peer: sends just queue on the open send
    /// half, so a call under test never blocks on a peer. (Same shape as the
    /// promoted-orphan projection tests.)
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    async fn harness(local: &str, peer: &str, dag_negotiated: bool) -> Harness {
        harness_with_deps(
            local,
            peer,
            dag_negotiated,
            PeerSyncSessionOneTimeDeps::test_permissive(),
        )
        .await
    }

    /// Like `harness`, but takes the session's 8 one-time capability
    /// injections explicitly instead of defaulting them.
    async fn harness_with_deps(
        local: &str,
        peer: &str,
        dag_negotiated: bool,
        one_time_deps: PeerSyncSessionOneTimeDeps,
    ) -> Harness {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP, state.as_ref())
            .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), root.clone())]);
        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            local.to_string(),
            peer.to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
            None,
            one_time_deps,
        );
        if dag_negotiated {
            session.record_peer_change_dag_support(true);
            assert!(session.change_dag_negotiated());
        }
        Harness { session, state, _root: root_dir, _store_dir: store_dir, root }
    }

    fn empty_record(path: &str, mtime: i64) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: mtime,
            blocks: vec![],
            deleted: false,
        }
    }

    /// Authoring identity is mandatory: an identity-less projected record is
    /// rejected instead of falling back to an empty version vector.
    #[tokio::test]
    async fn projected_rows_without_authoring_identity_are_rejected() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        let local = empty_record("split.txt", OLD_MTIME);
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &local,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(
            h.state
                .materialization_job_repository()
                .materialization_get_job(GROUP, "split.txt")
                .unwrap()
                .is_none(),
            "precondition: no job enqueued yet"
        );

        let incoming = empty_record("split.txt", NEW_MTIME);
        let meta = yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec_bit: false,
            origin_device_id: None,
            authoring_change_hash: None,
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let error = match h.session.apply_locked_record(GROUP, incoming, meta, policy).await {
            Ok(_) => panic!("missing authoring identity must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(error, yadorilink_peer_session::error::PeerSessionError::InvalidInput(_)));
        let record = h
            .state
            .file_index_repository()
            .get_file(GROUP, "split.txt")
            .unwrap()
            .expect("row still present");
        assert_eq!(
            record.mtime_unix_nanos, OLD_MTIME,
            "neither side may be adopted by the legacy exchange -- the DAG decides"
        );
        assert!(h
            .state
            .materialization_job_repository()
            .materialization_get_job(GROUP, "split.txt")
            .unwrap()
            .is_none());
    }

    /// An independent review's finding: `apply_locked_record`'s own
    /// `Equal`-authoring branch (and `authoring_proves_redundant`'s own
    /// batched fast path, `rematerialize_local_records`'s only skip
    /// mechanism) used to trust `same_record_content` alone -- content
    /// equality never proved `record_kind`/`symlink_target`/`exec_bit`
    /// hadn't independently diverged (an interrupted `apply_exec_bit`, or
    /// any other way the index/disk end up out of step with the identical,
    /// already-admitted DAG version's own metadata). Reached the materia-
    /// lization-audit way (`reconcile_local_materialization_audit` ->
    /// `rematerialize_local_records` -> `apply_locked_record`), not the
    /// primary DAG-admission path -- this is the backstop that repairs
    /// exactly this class of drift, and it must not just detect it and
    /// fall through as if fully settled.
    #[tokio::test]
    async fn equal_authoring_repairs_a_diverged_exec_bit() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        let out_path = h.root.join("run.sh");
        std::fs::write(&out_path, b"").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let version = FileVersion::from_index_row(
            vec![],
            0,
            OLD_MTIME,
            RecordKind::File,
            true, // the DAG version itself says executable
            None,
        );
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("run.sh".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version), true)
            .unwrap();
        let author = yadorilink_replica_domain::ids::ChangeHash(change.compute_hash().0);

        // This device already applied this exact version's content, but
        // its own exec bit (index AND disk) has drifted to non-executable
        // -- simulating an interrupted `apply_exec_bit`, with nothing
        // else about the record having changed.
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &FileRecord {
                    path: "run.sh".into(),
                    size: 0,
                    mtime_unix_nanos: OLD_MTIME,
                    blocks: vec![],
                    deleted: false,
                },
                "device-p",
                &author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        h.state
            .file_index_repository()
            .set_exec_bit(
                GROUP,
                "run.sh",
                false,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let incoming = FileRecord {
            path: "run.sh".into(),
            size: 0,
            mtime_unix_nanos: OLD_MTIME,
            blocks: vec![],
            deleted: false,
        };
        let meta = yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec_bit: true,
            origin_device_id: None,
            authoring_change_hash: Some(author),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h.session.apply_locked_record(GROUP, incoming, meta, policy).await.unwrap();

        assert!(
            matches!(
                outcome,
                yadorilink_peer_session::peer_session_impl::LockedRecordOutcome::Settled
            ),
            "an equal-authoring repair must settle, not error or defer: {outcome:?}"
        );
        assert!(
            h.state.file_index_repository().get_exec_bit(GROUP, "run.sh").unwrap(),
            "the index's own exec bit must be repaired to match the authoring change's version"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
            assert_ne!(mode & 0o100, 0, "the real on-disk file's exec bit must be repaired too");
        }
    }

    /// The materialization-audit backstop must keep repairing missing on-disk
    /// content for records this device already holds — on a change-DAG session —
    /// via the materialize-only `rematerialize_local_records` routine. This is
    /// the audit path that stays after the second convergence engine is gone; it
    /// only ever materializes what the DAG already projected, never resolves a
    /// concurrent edit.
    #[tokio::test]
    async fn materialization_audit_runs_on_dag_session() {
        let h = harness("device-d", "device-p", /*dag*/ true).await;
        // An indexed (empty-content) record whose on-disk file is missing — the
        // shape the audit exists to repair.
        let rec = empty_record("audit.txt", OLD_MTIME);
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &rec,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let emitter = ChangeEmitter::new("device-d", SigningKey::from_bytes(&[41; 32]));
        let author = h
            .state
            .append_history_backfill(
                GROUP,
                vec![Op::Delete { path: SyncPath("audit.txt".to_string()) }],
                &[],
                &emitter,
            )
            .unwrap();
        h.state
            .file_index_repository()
            .set_authoring_change_hash(GROUP, "audit.txt", &author)
            .unwrap();
        let on_disk = h.root.join("audit.txt");
        assert!(!on_disk.exists(), "precondition: the file is not yet materialized");

        let file_info = h.session.file_info_for_record(GROUP, rec).unwrap();
        h.session.clone().rematerialize_local_records(GROUP, vec![file_info]).await.unwrap();

        assert!(on_disk.exists(), "the audit must re-materialize the missing file");
    }

    /// The under-lock freshness check's other arm: when the winner has moved
    /// to a NEWER content head (not a tombstone) while the caller waited for
    /// the path lock, the materialize must upgrade in place — writing the
    /// fresh winner's content immediately rather than declining and paying a
    /// full decline→retry→re-resolve round-trip under exactly the contention
    /// that produces these races.
    #[tokio::test]
    async fn a_stale_content_materialize_upgrades_to_the_newer_winner_in_place() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let version_old = empty_version(OLD_MTIME);
        let change_old = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_old.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_old, std::slice::from_ref(&version_old), true)
            .unwrap();
        // A newer change by the same author supersedes it while the stale
        // caller is (conceptually) waiting for the lock.
        let version_new = empty_version(NEW_MTIME);
        let change_new = Change::create_signed(
            vec![change_old.compute_hash()],
            change_old.lamport,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_new.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_new, std::slice::from_ref(&version_new), true)
            .unwrap();

        let stale_head = yadorilink_replica_engine::conflict::PathHead {
            change_hash: change_old.compute_hash().0,
            lamport: change_old.lamport,
            device_id: "device-a".into(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: version_old.version_hash.0,
                mtime_unix_nanos: version_old.meta.mtime_unix_nanos,
            }),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let result = h
            .session
            .materialize_dag_content_head(GROUP, "shared.bin", &stale_head, policy, None)
            .await
            .unwrap();
        assert!(
            matches!(
                result,
                yadorilink_peer_session::peer_session_impl::MaterializeResult::Settled
            ),
            "the upgraded materialize must settle, not defer to a retry"
        );
        let record = h
            .state
            .file_index_repository()
            .get_file(GROUP, "shared.bin")
            .unwrap()
            .expect("record exists");
        assert_eq!(
            record.mtime_unix_nanos, version_new.meta.mtime_unix_nanos,
            "the CURRENT winner's version must be what actually landed, not the stale head's"
        );
        assert!(h.root.join("shared.bin").exists(), "the fresh winner's file must be on disk");
    }

    /// RED regression for the stale-materialize resurrection race, captured
    /// live (single-path DST trace, three-device mesh chaos seed 1000005):
    /// a projection attempt resolves a path's winner, and BEFORE its
    /// materialize acquires the path lock, this device's user deletes the
    /// file — the local tombstone change, index row, and disk removal all
    /// land first. The stale materialize then ran anyway, re-creating the
    /// file and clobbering the tombstone's index row; and because the
    /// tombstone was locally authored (already `applied`), no reprojection
    /// ever re-examined the path — a deterministic, permanent divergence
    /// (the traced device kept a live file every peer had deleted, under
    /// byte-identical DAG heads). The materialize must re-validate the
    /// resolution under the path lock and decline to write a head that is
    /// no longer the current winner.
    #[tokio::test]
    async fn a_stale_content_materialize_must_not_resurrect_a_newer_local_tombstone() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let change_w = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w), false)
            .unwrap();
        h.session
            .reconcile_paths_directly(
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".to_string()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(h.root.join("shared.bin").exists(), "precondition: the winner materialized");

        // The user deletes the file. Mirror the local-change pipeline's end
        // state exactly: tombstone change admitted as already-applied, index
        // row deleted, file gone from disk.
        let key_local = SigningKey::from_bytes(&[9u8; 32]);
        let change_t = Change::create_signed(
            vec![change_w.compute_hash()],
            change_w.lamport,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-local".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("shared.bin".into()),
            }],
            &key_local,
        );
        h.state.change_history_repository().dag_admit_change(&change_t, true).unwrap();
        std::fs::remove_file(h.root.join("shared.bin")).unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "shared.bin".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // The raced attempt: a materialize whose resolution predates the
        // tombstone finally gets the path lock and runs.
        let stale_head = yadorilink_replica_engine::conflict::PathHead {
            change_hash: change_w.compute_hash().0,
            lamport: change_w.lamport,
            device_id: "device-a".into(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: version_w.version_hash.0,
                mtime_unix_nanos: version_w.meta.mtime_unix_nanos,
            }),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let result = h
            .session
            .materialize_dag_content_head(GROUP, "shared.bin", &stale_head, policy, None)
            .await
            .unwrap();

        assert!(
            !h.root.join("shared.bin").exists(),
            "a stale materialize must not resurrect a file a newer local tombstone removed"
        );
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, "shared.bin")
                .unwrap()
                .is_none_or(|r| r.deleted),
            "the tombstone's index row must survive the stale attempt"
        );
        assert!(
            matches!(
                result,
                yadorilink_peer_session::peer_session_impl::MaterializeResult::RetryRequired
            ),
            "a declined stale write must not report the path as settled"
        );
    }

    /// Fully filesystem-independent (no case-fold/normalization probe
    /// involved, so it runs identically on every CI runner): a tombstone
    /// for a path this device has never seen must not leave the incoming
    /// wire metadata's kind/target/exec-bit on the landed row.
    /// `apply_locked_record`'s never-seen branch used to call
    /// `apply_incoming_wire_metadata` unconditionally before `materialize`,
    /// which bootstraps a `version_seq = 0` scaffold row and stamps it with
    /// the incoming meta; `upsert_file_in_tx`'s scaffold-promotion path
    /// then carries that stamped `record_kind`/`symlink_target`/`exec_bit`
    /// forward onto the real, landed tombstone row -- meaningless metadata
    /// (a delete has no kind) baked permanently into a deleted record. A
    /// tombstone with no genuine local history reaching a hazard hold and
    /// leaving that same scaffold behind unpromoted (see `peer_session`'s
    /// own `hazardous_tombstone_for_a_bootstrap_only_scaffold_is_not_held`)
    /// is the more severe half of this same root cause, but this half
    /// needs no filesystem probe to reproduce.
    #[tokio::test]
    async fn a_never_seen_tombstone_does_not_leak_wire_metadata_onto_its_landed_row() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        let key_a = SigningKey::from_bytes(&[3u8; 32]);
        let change_t = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("gone.txt".into()),
            }],
            &key_a,
        );
        h.state.change_history_repository().dag_admit_change(&change_t, false).unwrap();

        assert!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().is_none(),
            "precondition: no prior row at all for this path"
        );

        let incoming = FileRecord {
            path: "gone.txt".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let meta = yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
            record_kind: RecordKind::Symlink,
            symlink_target: Some(b"/somewhere-meaningless".to_vec()),
            symlink_out_of_root: true,
            exec_bit: true,
            origin_device_id: None,
            authoring_change_hash: Some(yadorilink_replica_domain::ids::ChangeHash(
                change_t.compute_hash().0,
            )),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        h.session.apply_locked_record(GROUP, incoming, meta, policy).await.unwrap();

        assert_eq!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().map(|r| r.deleted),
            Some(true),
            "the tombstone itself must still land"
        );
        assert_eq!(
            h.state.file_index_repository().get_record_kind(GROUP, "gone.txt").unwrap(),
            Some(RecordKind::File),
            "a tombstone's landed row must not inherit the incoming wire meta's record_kind \
             (Symlink) -- a delete has no kind to materialize, so this must stay the column's \
             own default"
        );
        assert_eq!(
            h.state.file_index_repository().get_symlink_target(GROUP, "gone.txt").unwrap(),
            None,
            "nor the incoming wire meta's symlink_target"
        );
        assert!(
            !h.state.file_index_repository().get_exec_bit(GROUP, "gone.txt").unwrap(),
            "nor the incoming wire meta's exec_bit"
        );
    }

    /// `reconcile_group_paths`'s `PathResolution::Absent` branch used to
    /// fold every `Ok(_)` from `materialize` into `settled`, unlike the
    /// `Present` branch a few lines below it, which has always distinguished
    /// `Settled` from `RetryRequired`. A hazard-collision tombstone that
    /// drops without applying anything (see the `version_hash_exact_
    /// capability_tests` module's `hazardous_tombstone_for_a_bootstrap_
    /// only_scaffold_is_not_held`, which proves `materialize` itself
    /// reports `RetryRequired` for exactly this case) would silently be
    /// marked "done" by this asymmetry -- the DAG projection layer would
    /// never revisit it, so if the sending peer later disappears before a
    /// periodic full-index resend delivers this deletion again, it is lost
    /// for good. Requires a case-insensitive filesystem to raise a real
    /// hazard through the full DAG projection path -- see this module's
    /// own `a_never_seen_tombstone_does_not_leak_wire_metadata_onto_its_
    /// landed_row` for the filesystem-independent half of this same fix.
    #[tokio::test]
    async fn a_hazard_declined_tombstone_reaching_dag_projection_is_not_marked_settled() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.root) {
            eprintln!("skipping: {} is case-sensitive here", h.root.display());
            return;
        }

        // "Gone.txt" is live and materialized -- the sibling the tombstone
        // will collide with.
        std::fs::write(h.root.join("Gone.txt"), b"sibling bytes").unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Gone.txt".into(),
                    size: b"sibling bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // A bootstrap-only scaffold at "gone.txt" itself -- the shape
        // `apply_locked_record`'s never-seen branch used to leave behind
        // for a hazard-declined tombstone (see the P1-1 fix this same
        // change makes). `still_live` in the `Absent` branch below reads
        // this scaffold's `deleted = 0` as "still live", which is exactly
        // what routes this case through `materialize` rather than the
        // trivial "already absent" fast path.
        yadorilink_peer_session::peer_session_impl::apply_incoming_wire_metadata(
            h.state.as_ref(),
            GROUP,
            &FileRecord {
                path: "gone.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                exec_bit: false,
                authoring_change_hash: None,
                origin_device_id: None,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        let key_p = SigningKey::from_bytes(&[4u8; 32]);
        let change_t = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("gone.txt".into()),
            }],
            &key_p,
        );
        h.state.change_history_repository().dag_admit_change(&change_t, false).unwrap();

        let attempt = h
            .session
            .reconcile_paths_directly(
                GROUP,
                std::collections::BTreeSet::from(["gone.txt".to_string()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");

        assert!(
            attempt.needs_retry("gone.txt"),
            "a dropped hazard-collision tombstone must be reported as needing retry, not settled: \
             {attempt:?}"
        );
        assert!(
            !attempt.is_settled("gone.txt"),
            "the DAG projection layer must never mark this path resolved while it never actually \
             applied the deletion anywhere"
        );
        assert!(h
            .state
            .materialization_state_repository()
            .get_held_state(GROUP, "gone.txt")
            .unwrap()
            .is_none());
        assert_eq!(
            std::fs::read(h.root.join("Gone.txt")).unwrap(),
            b"sibling bytes",
            "the sibling must remain untouched"
        );
    }

    /// The legacy `apply_locked_record` path had the identical asymmetry
    /// the DAG `Absent` branch above did, but one layer further out: its
    /// never-seen branch called `self.materialize(...).await?` and
    /// discarded the `Ok` value entirely, always returning
    /// `LockedRecordOutcome::Settled` regardless of whether `materialize`
    /// actually reported `Settled` or `RetryRequired`. This is reachable
    /// for non-tombstone records too (an eager fetch that couldn't obtain
    /// every block, a reconstruct failure), not just tombstones -- a
    /// hazard-collision tombstone for a never-seen path is simply the
    /// easiest case to construct directly.
    #[tokio::test]
    async fn apply_locked_record_propagates_retry_required_from_a_dropped_hazard_tombstone() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.root) {
            eprintln!("skipping: {} is case-sensitive here", h.root.display());
            return;
        }

        std::fs::write(h.root.join("Gone.txt"), b"sibling bytes").unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Gone.txt".into(),
                    size: b"sibling bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().is_none(),
            "precondition: no prior row at all for the tombstone's own path"
        );

        let key_p = SigningKey::from_bytes(&[5u8; 32]);
        let change_t = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("gone.txt".into()),
            }],
            &key_p,
        );
        h.state.change_history_repository().dag_admit_change(&change_t, false).unwrap();

        let incoming = FileRecord {
            path: "gone.txt".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let meta = yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec_bit: false,
            origin_device_id: None,
            authoring_change_hash: Some(yadorilink_replica_domain::ids::ChangeHash(
                change_t.compute_hash().0,
            )),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h.session.apply_locked_record(GROUP, incoming, meta, policy).await.unwrap();

        assert!(
            matches!(
                outcome,
                yadorilink_peer_session::peer_session_impl::LockedRecordOutcome::RetryRequired
            ),
            "a dropped hazard-collision tombstone must propagate RetryRequired through the legacy \
             path too, not just the DAG path -- got {outcome:?}"
        );
        assert!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().is_none(),
            "no scaffold left behind either"
        );
    }

    /// The strong version of the authoring-advance fix: unlike
    /// `hazardous_tombstone_materialize_advances_a_differing_authoring_hash`
    /// (which drives `materialize` directly with an arbitrary hash),
    /// this test builds two REAL admitted DAG changes -- a parent
    /// tombstone this device already applied, and a genuinely descendant
    /// tombstone from another device -- and goes in through
    /// `apply_locked_record`, so `dag_compare_authoring` itself proves the
    /// incoming identity is causally newer before the fast path inside
    /// `materialize` ever runs. Addresses the gap an independent review
    /// found in the direct-unit version: that test alone couldn't
    /// distinguish "advances to a newer identity" from "just overwrites
    /// with whatever's supplied", since `materialize` trusts its caller
    /// for causal ordering rather than checking it itself.
    #[tokio::test]
    async fn redelivery_of_a_real_dag_descendant_tombstone_advances_authoring_identity_through_the_ordering_gate(
    ) {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.root) {
            eprintln!("skipping: {} is case-sensitive here", h.root.display());
            return;
        }

        // Written and indexed BEFORE any change is admitted: once a group
        // has any admitted change, `files_require_authoring_identity_on_
        // insert`/`_on_update` require every `current`/`version_seq > 0`
        // row to carry a verified authoring identity, and this sibling's
        // own authoring change is irrelevant to what this test exercises.
        std::fs::write(h.root.join("Photo.jpg"), b"fresh photo bytes").unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let key_parent = SigningKey::from_bytes(&[6u8; 32]);
        let parent_change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("photo.jpg".into()),
            }],
            &key_parent,
        );
        h.state.change_history_repository().dag_admit_change(&parent_change, true).unwrap();
        let parent_hash =
            yadorilink_replica_domain::ids::ChangeHash(parent_change.compute_hash().0);
        // This device already applied the parent tombstone: a genuine
        // (version_seq > 0) row stamped with its authoring identity.
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                "device-p",
                &parent_hash,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // A different device re-tombstones the same path, causally AFTER
        // the parent -- a genuine DAG descendant, not an arbitrary hash.
        let key_descendant = SigningKey::from_bytes(&[8u8; 32]);
        let descendant_change = Change::create_signed(
            vec![parent_change.compute_hash()],
            parent_change.lamport,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-q".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("photo.jpg".into()),
            }],
            &key_descendant,
        );
        h.state.change_history_repository().dag_admit_change(&descendant_change, false).unwrap();
        let descendant_hash =
            yadorilink_replica_domain::ids::ChangeHash(descendant_change.compute_hash().0);

        let incoming = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let meta = yadorilink_peer_session::peer_session_impl::IncomingWireMeta {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec_bit: false,
            origin_device_id: None,
            authoring_change_hash: Some(descendant_hash),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h.session.apply_locked_record(GROUP, incoming, meta, policy).await.unwrap();

        assert!(
            matches!(
                outcome,
                yadorilink_peer_session::peer_session_impl::LockedRecordOutcome::Settled
            ),
            "this deletion already converged (already a genuine tombstone on both sides) -- got \
             {outcome:?}"
        );
        assert_eq!(
            h.state.file_index_repository().get_authoring_change_hash(GROUP, "photo.jpg").unwrap(),
            Some(descendant_hash),
            "the row's authoring identity must advance to the causally-newer descendant \
             tombstone, proven newer by dag_compare_authoring itself, not stay stuck at the \
             parent's"
        );
        assert!(
            h.state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().unwrap().deleted,
            "still a clean tombstone"
        );
        assert_eq!(
            std::fs::read(h.root.join("Photo.jpg")).unwrap(),
            b"fresh photo bytes",
            "the sibling must remain untouched"
        );
    }

    /// Regression for the confirmed arrival-order divergence (see
    /// `retire_unjustified_ephemeral_conflict_copies`'s own doc comment): a
    /// conflict copy the projection fixpoint derived while its losing head
    /// was live is a purely local, uncarried artifact. While the loser
    /// stays live the audit must KEEP it (a device that reconciles now
    /// derives the same copy — no divergence, and deleting it would fight
    /// the fixpoint). Once the loser is superseded by its own author's
    /// next edit — closing the conflict window with no cross-branch merge,
    /// so no change ever carries the copy — the audit must retire it,
    /// because a device that first reconciles after the window closed
    /// never derives it, and the two file sets would otherwise disagree
    /// forever under byte-identical DAGs.
    #[tokio::test]
    async fn audit_retires_an_ephemeral_conflict_copy_once_its_loser_window_closes() {
        let h = harness("device-local", "device-p", /*dag*/ true).await;
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let key_b = SigningKey::from_bytes(&[2u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let version_l = empty_version(NEW_MTIME);

        // Two concurrent roots on "shared.bin": winner W (device-a) and
        // loser L (device-b), genuinely different contents.
        let change_w = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        let change_l = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            yadorilink_replica_domain::ids::DeviceId("device-b".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_b,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w), true)
            .unwrap();
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_l, std::slice::from_ref(&version_l), true)
            .unwrap();

        // Reconcile at the transient frontier: the fixpoint derives and
        // materializes the loser's copy locally (ephemeral — no change
        // carries it).
        let (winner_head, loser_head, loser_version) = {
            let heads = h.state.sqlite().dag_group_heads(GROUP).unwrap();
            assert_eq!(heads.len(), 2, "sanity: W and L are concurrent heads");
            if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
                change_w.lamport,
                &change_w.compute_hash().0,
                change_l.lamport,
                &change_l.compute_hash().0,
            ) {
                (&change_l, &change_w, &version_w)
            } else {
                (&change_w, &change_l, &version_l)
            }
        };
        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            loser_head.device_id.0.as_str(),
            loser_version.meta.mtime_unix_nanos,
            &loser_version.version_hash.0,
        );
        h.session
            .reconcile_paths_directly(
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".into()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "precondition: the transient-frontier reconcile derived and indexed the loser's copy \
             at {copy_path:?}"
        );
        assert!(h.root.join(&copy_path).exists(), "precondition: the copy is on disk");

        // While the loser is still live, the audit must NOT retire it.
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "a copy still justified by a live loser must survive the audit"
        );

        // The loser's own author supersedes it: the conflict window closes
        // with no cross-branch merge, so no change ever carries the copy.
        let version_l2 = empty_version(NEW_MTIME + 1);
        let loser_child = Change::create_signed(
            vec![loser_head.compute_hash()],
            loser_head.lamport,
            ChangeAuth::PLACEHOLDER,
            loser_head.device_id.clone(),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l2.version_hash,
                origin: PutOrigin::Direct,
            }],
            if loser_head.device_id.0 == "device-a" { &key_a } else { &key_b },
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&loser_child, std::slice::from_ref(&version_l2), true)
            .unwrap();
        let _ = winner_head; // winner stays live; only the loser was superseded

        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
        assert!(
            !h.root.join(&copy_path).exists(),
            "the no-longer-justified, never-carried copy must be retired from disk"
        );
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_none_or(|r| r.deleted),
            "the retired copy's index row must not remain live"
        );
    }

    // ---- CORE: DAG-decided winner is order-independent and the gate keeps the
    // legacy mtime path from overriding it. ----

    struct MultiAuthenticator {
        keys: HashMap<String, [u8; 32]>,
    }
    impl ChangeAuthenticator for MultiAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            self.keys.get(device_id).copied()
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    fn empty_version(mtime: i64) -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }
    }

    /// Two genuinely concurrent Create-`file.bin` changes with mtime INVERTED
    /// against lamport: device-a's change carries the higher lamport (a warm-up
    /// change raises its clock) but the OLDER mtime, device-b's carries the
    /// lower lamport but the NEWER mtime. The DAG winner is therefore device-a
    /// (higher lamport) while the mtime resolver would pick device-b.
    fn concurrent_changes() -> (Change, Change, Change, FileVersion, FileVersion, FileVersion) {
        let key_a = SigningKey::from_bytes(&[7u8; 32]);
        let key_b = SigningKey::from_bytes(&[8u8; 32]);
        let warm_v = empty_version(500);
        let va = empty_version(OLD_MTIME);
        let vb = empty_version(NEW_MTIME);

        let conn_a = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn_a).unwrap();
        dag_store::put_file_version(&conn_a, GROUP, &warm_v).unwrap();
        dag_store::put_file_version(&conn_a, GROUP, &va).unwrap();
        let emitter_a = ChangeEmitter::new("device-a", key_a);
        let warm = dag_store::emit_local_change(
            &conn_a,
            GROUP,
            vec![create_op("warmup.txt", &warm_v)],
            ChangeAuth::PLACEHOLDER,
            &emitter_a,
        )
        .unwrap();
        let change_a = dag_store::emit_local_change(
            &conn_a,
            GROUP,
            vec![create_op("file.bin", &va)],
            ChangeAuth::PLACEHOLDER,
            &emitter_a,
        )
        .unwrap();

        let conn_b = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn_b).unwrap();
        dag_store::put_file_version(&conn_b, GROUP, &vb).unwrap();
        let emitter_b = ChangeEmitter::new("device-b", key_b);
        let change_b = dag_store::emit_local_change(
            &conn_b,
            GROUP,
            vec![create_op("file.bin", &vb)],
            ChangeAuth::PLACEHOLDER,
            &emitter_b,
        )
        .unwrap();

        assert!(
            change_a.lamport > change_b.lamport,
            "test setup: device-a's change must carry the higher lamport ({} vs {})",
            change_a.lamport,
            change_b.lamport
        );
        (warm, change_a, change_b, warm_v, va, vb)
    }

    fn change_batch(
        changes: Vec<&Change>,
        versions: Vec<&FileVersion>,
    ) -> yadorilink_sync_wire::ChangeBatchFrame {
        yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: changes.into_iter().map(|c| c.to_wire_bytes()).collect(),
            compressed_changes: Vec::new(),
            file_versions: versions.into_iter().map(|v| v.canonical_encoding()).collect(),
        }
    }

    async fn converge_via_change_batch(reversed_batch: bool) -> i64 {
        let (warm, change_a, change_b, warm_v, va, vb) = concurrent_changes();
        let h = harness_with_deps(
            "device-d",
            "device-p",
            /*dag*/ true,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(MultiAuthenticator {
                    keys: HashMap::from([
                        (
                            "device-a".to_string(),
                            SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes(),
                        ),
                        (
                            "device-b".to_string(),
                            SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes(),
                        ),
                    ]),
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        )
        .await;

        // The two genuinely concurrent Create-`file.bin` changes arrive in one
        // batch, forward or reversed; the DAG must converge to the lamport winner
        // (device-a, OLD_MTIME) either way — the newer-mtime edit never wins.
        let batch = if reversed_batch {
            change_batch(vec![&change_b, &change_a, &warm], vec![&vb, &va, &warm_v])
        } else {
            change_batch(vec![&warm, &change_a, &change_b], vec![&warm_v, &va, &vb])
        };
        h.session.handle_change_batch(batch).await.unwrap();
        // `handle_change_batch` only admits the DAG change and enqueues a
        // materialization job now (CONV-1); drive the same projection step
        // the Convergence Engine would, exactly as it would call it.
        h.session.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();

        h.state
            .file_index_repository()
            .get_file(GROUP, "file.bin")
            .unwrap()
            .unwrap()
            .mtime_unix_nanos
    }

    #[tokio::test]
    async fn dag_peers_converge_same_winner_regardless_of_arrival_order() {
        // Whether the concurrent changes arrive in forward or reversed batch
        // order, the change-DAG session converges to the LAMPORT winner
        // (device-a, OLD_MTIME); mtime never decides.
        let forward = converge_via_change_batch(false).await;
        let reversed = converge_via_change_batch(true).await;
        assert_eq!(forward, OLD_MTIME, "forward batch must keep the lamport winner");
        assert_eq!(reversed, OLD_MTIME, "reversed batch must keep the lamport winner");
        assert_eq!(forward, reversed, "the winner must be identical regardless of arrival order");
    }
}

#[cfg(test)]
mod authorization_monotonicity_tests {
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session_impl::{
        ChangeAuthenticator, PeerSyncSession, PeerSyncSessionOneTimeDeps,
    };
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::file::{FileMeta, FileVersion};
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

    const GROUP: &str = "shared-group";

    /// A permissive authenticator: it pins the author's key and treats it as a
    /// writer, and (via the trait default) accepts any authorization stamp.
    /// The monotonicity rule under test lives in `handle_change_batch` itself
    /// and is enforced independently of the authenticator, so a permissive
    /// authenticator isolates it: whatever passes here does so purely on the
    /// parent-pin comparison, not on policy replay.
    struct PermissiveAuthenticator {
        author_device_id: String,
        author_verifying_key: [u8; 32],
    }

    impl ChangeAuthenticator for PermissiveAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == self.author_device_id).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    fn empty_version() -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }
    }

    fn real_auth(seq: u64, epoch: u64) -> ChangeAuth {
        // A non-PLACEHOLDER pin. `policy_head_hash` is set to a distinct
        // non-zero marker so the stamp differs from `ChangeAuth::PLACEHOLDER`
        // (the exemption is keyed on the whole stamp being the placeholder).
        ChangeAuth { auth_seq: seq, auth_epoch: epoch, policy_head_hash: [seq as u8 ^ 0xA5; 32] }
    }

    /// Builds a signed root editing `a.txt` (pinning `parent_auth`) and a
    /// signed child editing `b.txt` that descends from it (pinning
    /// `child_auth`), by running the real local-emission path against a
    /// throwaway store so the child genuinely names the root as its parent.
    fn build_chain(
        signing_key: &SigningKey,
        parent_auth: ChangeAuth,
        child_auth: ChangeAuth,
    ) -> (Change, Change, FileVersion) {
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let version = empty_version();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let parent = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("a.txt", &version)],
            parent_auth,
            &emitter,
        )
        .unwrap();
        let child = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("b.txt", &version)],
            child_auth,
            &emitter,
        )
        .unwrap();
        // The child must genuinely descend from the parent for the causal
        // check to have anything to compare against.
        assert_eq!(child.parents, vec![parent.compute_hash()], "child must name the root parent");
        (parent, child, version)
    }

    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    /// Feeds `changes` (in the given order) as one batch to a fresh receiver
    /// and returns its `ReplicaCoordinator`. The temp dirs are returned so they outlive
    /// the call; assertions read the in-memory index, which persists
    /// regardless of the on-disk root.
    async fn admit_batch(
        changes: &[Change],
        version: &FileVersion,
        author_verifying_key: [u8; 32],
    ) -> (Arc<ReplicaCoordinator>, TempDir, TempDir) {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);

        let session = PeerSyncSession::new_with_forwarding(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
            None,
            PeerSyncSessionOneTimeDeps {
                change_authenticator: Arc::new(PermissiveAuthenticator {
                    author_device_id: "device-a".to_string(),
                    author_verifying_key,
                }),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            },
        );

        let batch = yadorilink_sync_wire::ChangeBatchFrame {
            folder_group_id: GROUP.to_string(),
            changes: changes.iter().map(|c| c.to_wire_bytes()).collect(),
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        };
        session.handle_change_batch(batch).await.unwrap();
        // `handle_change_batch` only admits the DAG changes and enqueues
        // materialization jobs now (CONV-1); drive the same projection step
        // the Convergence Engine would, so every caller of this helper still
        // sees the same synchronously-observable materialized state it did
        // before that change.
        session.reconcile_local_materialization_audit(GROUP).await.unwrap();
        (state, root_dir, store_dir)
    }

    /// The attack: a device revoked at seq N=10 forks off a post-revoke head
    /// (the root here pins seq 10, epoch 2) but stamps its own change with the
    /// OLD grant seq M=3 (epoch 1) it held before the revoke. Delivered
    /// parent-first so the parent's pin is already in the store when the child
    /// is checked, the child must be REJECTED and never enter the store.
    #[tokio::test]
    async fn revoked_writer_building_on_post_revoke_head_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(10, 2), real_auth(3, 1));

        let (state, _root, _store) =
            admit_batch(&[parent.clone(), child.clone()], &version, verifying_key).await;

        assert!(
            state.change_history_repository().dag_has_change(&parent.compute_hash()).unwrap(),
            "the honest post-revoke head is admitted"
        );
        assert!(
            !state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap(),
            "the revoked writer's older-pinned change must NOT enter the store"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "a.txt").unwrap().is_some(),
            "the parent's path materializes"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "b.txt").unwrap().is_none(),
            "the rejected change's path must never materialize"
        );
    }

    /// The orphan-first evasion: the same attack but delivered child-first, so
    /// the malicious change arrives before its post-revoke parent. It must be
    /// HELD (its parents can't be read yet, so monotonicity can't be verified)
    /// rather than buffered — otherwise the later arrival of the honest parent
    /// would silently promote it. The parent still lands; the child never does.
    #[tokio::test]
    async fn revoked_writer_orphan_first_ordering_is_held_not_promoted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(10, 2), real_auth(3, 1));

        // Child first, then its parent — the ordering that would exploit the
        // orphan buffer's promote-without-re-auth path.
        let (state, _root, _store) =
            admit_batch(&[child.clone(), parent.clone()], &version, verifying_key).await;

        assert!(
            state.change_history_repository().dag_has_change(&parent.compute_hash()).unwrap(),
            "the honest parent still lands"
        );
        assert!(
            !state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap(),
            "a held, monotonicity-unverified change must never be promoted into the store"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "b.txt").unwrap().is_none(),
            "the held change's path must never materialize"
        );
    }

    /// A legitimately-delayed change from a still-valid writer, authored
    /// offline concurrent with the revoke: its parent pins seq M=3 and it also
    /// pins seq 3, arriving after the revoke would have advanced the log. Its
    /// parents pin <= M, so monotonicity holds and it is ADMITTED — the fix
    /// must not punish honest delay.
    #[tokio::test]
    async fn legitimately_delayed_change_concurrent_with_revoke_is_admitted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(3, 1), real_auth(3, 1));

        let (state, _root, _store) =
            admit_batch(&[parent.clone(), child.clone()], &version, verifying_key).await;

        assert!(
            state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap(),
            "a change that pins the same coordinate as its parent must be admitted"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "b.txt").unwrap().is_some(),
            "the delayed change's path materializes"
        );
    }

    /// The ordinary forward case: a child pins a strictly newer coordinate
    /// than its parent (seq 3 -> seq 5). Non-decreasing pins are admitted.
    #[tokio::test]
    async fn monotonic_normal_changes_admitted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(3, 1), real_auth(5, 1));

        let (state, _root, _store) =
            admit_batch(&[parent.clone(), child.clone()], &version, verifying_key).await;

        assert!(
            state.change_history_repository().dag_has_change(&child.compute_hash()).unwrap(),
            "a change pinning a newer coordinate than its parent must be admitted"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "b.txt").unwrap().is_some(),
            "the forward change's path materializes"
        );
    }
}
