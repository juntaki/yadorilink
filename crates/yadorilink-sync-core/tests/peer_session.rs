use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use ed25519_dalek::SigningKey;
use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_sync_core::dag_store::ChangeEmitter;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::{
    BlockWriteActivityProvider, ChangeAuthenticator, PeerSyncSession,
};
use yadorilink_sync_core::rate_limiter::RateLimiters;
use yadorilink_sync_core::types::{MaterializationPolicy, MaterializationState};
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind};
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
    state: Arc<SyncState>,
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
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        // Link `GROUP` at this device's root, the same way linking the folder
        // would. A session's sync roots are *derived from* the link table in
        // production (`sync_roots_for_groups` reads `list_links`), and the
        // peer-apply path re-reads that table for every write it makes — so a
        // device holding a root with no matching link row is a state the daemon
        // cannot produce, and one the apply path deliberately refuses to write
        // for. Registering it here keeps the fixture's invariant the same as
        // production's; the tests that care about pause/unlink/policy still
        // drive those explicitly on top.
        state.add_link(&root.path().canonicalize().unwrap().to_string_lossy(), GROUP).unwrap();
        yadorilink_sync_core::root_identity::VerifiedRoot::open(root.path(), GROUP, &state)
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
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        Device {
            device_id: device_id.to_string(),
            root,
            store: Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            state,
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// A `ChangeEmitter` signing as this device. Recreated on demand — its
    /// lamport/parent state lives in the group's DAG in `SyncState`, not in the
    /// emitter, so a fresh instance auto-parents from the current heads.
    fn emitter(&self) -> Arc<ChangeEmitter> {
        Arc::new(ChangeEmitter::new(self.device_id.clone(), self.signing_key.clone()))
    }

    fn processor(&self) -> LocalChangeProcessor {
        LocalChangeProcessor::new(self.state.clone(), self.store.clone(), self.device_id.clone())
            .with_change_emitter(self.emitter())
    }

    /// A signed-change producer over this device's state/store, for scenarios
    /// that need to inject a specific record as a genuine DAG commit rather than
    /// via a real on-disk edit (`commit_create` stores the block and emits a
    /// signed Create, the same primitive the local-change producer drives).
    fn producer(&self) -> DagProducer {
        let store: Arc<dyn BlockStore + Send + Sync> = self.store.clone();
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
fn link_with_completed_startup(state: &SyncState, local_path: &str) {
    state.add_link(local_path, GROUP).unwrap();
    yadorilink_sync_core::root_identity::VerifiedRoot::open(
        std::path::Path::new(local_path),
        GROUP,
        state,
    )
    .unwrap();
    let generation = state.begin_group_startup(GROUP);
    state.mark_group_ready(GROUP, generation);
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

fn spawn_session(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> Arc<PeerSyncSession> {
    spawn_session_with_groups(channel, device, peer_device_id, vec![GROUP.to_string()])
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
    spawn_session_configured(channel, device, peer_device_id, vec![GROUP.to_string()], None)
}

/// Shared spawn seam: `resync_interval` of `None` leaves the production default
/// in place, `Some(i)` shortens the periodic frontier re-announce to `i`.
fn spawn_session_configured(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
    resync_interval: Option<Duration>,
) -> Arc<PeerSyncSession> {
    let session = PeerSyncSession::new(
        channel,
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone(),
        device.store.clone(),
        shared_group_ids,
        device.sync_roots(),
    );
    // Every spawned pair admits each other's signed changes (deterministic keys),
    // so a pre-existing file propagates over the DAG via the startup
    // heads-announce exactly as it would with a coordination-plane netmap.
    session.set_change_authenticator(Arc::new(DerivedKeyAuthenticator));
    if let Some(interval) = resync_interval {
        session.set_full_index_resync_interval(interval);
    }
    tokio::spawn(session.clone().run());
    session
}

fn expect_file_changed(outcome: LocalChangeOutcome) -> yadorilink_sync_core::types::FileRecord {
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // device-a's pre-existing file is already in its DAG (process_event above);
    // the startup heads-announce carries it to device-b once negotiated.
    let replicated_path = device_b.root_path().join("vacation.jpg");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;

    let original = std::fs::read(device_a.root_path().join("vacation.jpg")).unwrap();
    let replicated = std::fs::read(&replicated_path).unwrap();
    assert_eq!(original, replicated);

    let record = device_b.state.get_file(GROUP, "vacation.jpg").unwrap().unwrap();
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    // A short periodic heads-announce reliably carries device-a's committed
    // change to device-b over loopback so the eager adoption enters the gate.
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    let session_b = PeerSyncSession::new(
        channel_b,
        device_b.device_id.clone(),
        "device-a".into(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
    );
    session_b.set_change_authenticator(auth.clone());
    let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    session_b.set_block_write_activity_provider(Arc::new(BlockingActivityProvider {
        attempted: attempted_tx,
        release: release.clone(),
    }));
    tokio::spawn(session_b.clone().run());

    tokio::task::spawn_blocking(move || {
        attempted_rx.recv_timeout(Duration::from_secs(10)).expect("eager adoption must enter gate")
    })
    .await
    .unwrap();
    assert!(
        !device_b.state.live_block_hashes().unwrap().contains(&orphan_hash),
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
    device_b.state.set_materialization_policy(&root_b, MaterializationPolicy::OnDemand).unwrap();
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    // A short periodic heads-announce reliably carries device-a's committed
    // change to device-b over loopback so the on-demand adoption enters the gate.
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    let session_b = PeerSyncSession::new(
        channel_b,
        device_b.device_id.clone(),
        "device-a".into(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
    );
    session_b.set_change_authenticator(auth.clone());
    let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    session_b.set_block_write_activity_provider(Arc::new(BlockingActivityProvider {
        attempted: attempted_tx,
        release: release.clone(),
    }));
    tokio::spawn(session_b.clone().run());

    tokio::task::spawn_blocking(move || {
        attempted_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("on-demand adoption must enter the reference-write gate")
    })
    .await
    .unwrap();
    assert!(
        !device_b.state.live_block_hashes().unwrap().contains(&orphan_hash),
        "on-demand adoption must not commit a block reference during physical deletion"
    );

    {
        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    wait_until(
        || device_b.state.get_file(GROUP, "ondemand-restored.txt").ok().flatten().is_some(),
        Duration::from_secs(10),
    )
    .await;
    let adopted = device_b.state.get_file(GROUP, "ondemand-restored.txt").unwrap().unwrap();
    assert!(adopted.blocks.iter().any(|block| hex::encode(&block.hash) == orphan_hash));
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "ondemand-restored.txt").unwrap(),
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    session_b.set_full_index_resync_interval(Duration::from_millis(100));
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join(file_name);
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;

    std::fs::remove_file(&replicated_path).unwrap();
    device_b
        .state
        .set_materialization_state(GROUP, file_name, MaterializationState::Placeholder)
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
        device_b.state.get_materialization_state(GROUP, file_name).unwrap(),
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
    device_b.state.set_materialization_policy(&root_b, MaterializationPolicy::OnDemand).unwrap();

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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    session_b.set_full_index_resync_interval(Duration::from_millis(100));
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join(file_name);
    announce_until(
        &session_a,
        GROUP,
        || {
            device_b.state.get_materialization_state(GROUP, file_name).ok().flatten()
                == Some(MaterializationState::Placeholder)
        },
        Duration::from_secs(20),
    )
    .await;

    session_b.clone().reconcile_local_materialization_audit(GROUP).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        device_b.state.get_materialization_state(GROUP, file_name).unwrap(),
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
    assert!(device_b.state.get_file(GROUP, "vacation.jpg").unwrap().is_some());
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
    device_b.state.set_paused(&root_b, true).unwrap();

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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Announce device-a's change repeatedly; a paused link must drop every
    // HeadsAnnounce/ChangeBatch (handle_heads_announce and handle_change_batch
    // both gate on is_paused_for_group), so nothing ever lands on device-b.
    for _ in 0..5 {
        let _ = session_a.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!device_b.root_path().join("vacation.jpg").exists());
    assert!(device_b.state.get_file(GROUP, "vacation.jpg").unwrap().is_none());
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
    device_b.state.add_link(&root_b, GROUP).unwrap();

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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let landed = device_b.root_path().join("vacation.jpg");
    announce_until(&session_a, GROUP, || landed.exists(), Duration::from_secs(20)).await;
    assert!(landed.exists(), "precondition: the file must sync while the link is live");

    // The user unlinks. This is the entire local teardown — `session_b` is
    // untouched and stays live, which is exactly the situation under test.
    device_b.state.remove_link(&root_b).unwrap();

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
    device_b.state.remove_link(&device_b.root_path().to_string_lossy()).unwrap();
    device_b.state.add_link(&missing_root.to_string_lossy(), GROUP).unwrap();
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
    device_b.state.add_link(&root_b, GROUP).unwrap();
    device_b.state.remove_link(&root_b).unwrap();

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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    for _ in 0..5 {
        let _ = session_a.announce_local_commit(GROUP).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !device_b.root_path().join("vacation.jpg").exists(),
        "a peer change was written into a folder with no link row"
    );
    assert!(device_b.state.get_file(GROUP, "vacation.jpg").unwrap().is_none());
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    // Pin each device's signing key on both sessions so B admits A's signed
    // change, then wait for the automatic change-DAG negotiation.
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
    let record_a = device_a.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    let record_b = device_b.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    assert_eq!(
        record_a.version.compare(&record_b.version),
        yadorilink_sync_core::version_vector::VvOrdering::Concurrent
    );

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
    device_a.state.set_paused(&root_a, true).unwrap();
    device_b.state.set_paused(&root_b, true).unwrap();

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
        .mark_deleted_emitting_change(GROUP, "shared.txt", "device-b", 1000, &device_b.emitter())
        .unwrap();

    // Reconnect the link and let the concurrent changes cross and resolve.
    device_a.state.set_paused(&root_a, false).unwrap();
    device_b.state.set_paused(&root_b, false).unwrap();

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
            .filter(|name| name != yadorilink_sync_core::root_identity::ROOT_MARKER_FILE_NAME)
            .collect();
        assert_eq!(entries, vec!["shared.txt".to_string()], "unexpected extra file: {entries:?}");
        assert_eq!(
            std::fs::read(device.root_path().join("shared.txt")).unwrap(),
            content_a,
            "disk content must match the winner's real content, not an empty ghost file"
        );
        let record = device.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
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
    assert!(device_b.state.get_file(GROUP, "private.txt").unwrap().is_none());
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
        .set_materialization_policy(
            &root_b,
            yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
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

    let record = device_b.state.get_file(GROUP, "big-video.mp4").unwrap().unwrap();
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "big-video.mp4").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
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
        .set_materialization_policy(
            &root_b,
            yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
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
        device_b.state.get_materialization_state(GROUP, "report.pdf").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
    );

    session_b.hydrate_file(GROUP, "report.pdf").await.unwrap();

    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "report.pdf").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(&placeholder_path).unwrap(), content);

    let record = device_b.state.get_file(GROUP, "report.pdf").unwrap().unwrap();
    for block in &record.blocks {
        let hash_hex = hex::encode(&block.hash);
        assert!(yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &hash_hex)
            .unwrap());
    }
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

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "unreachable.bin".into(),
                size: 100,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: vec![0xCDu8; 32],
                    offset: 0,
                    size: 100,
                }],
                deleted: false,
            },
        )
        .unwrap();
    device_b
        .state
        .set_materialization_state(
            GROUP,
            "unreachable.bin",
            yadorilink_sync_core::types::MaterializationState::Placeholder,
        )
        .unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        session_b.hydrate_file_with_timeout(GROUP, "unreachable.bin", Duration::from_millis(500)),
    )
    .await
    .expect("hydrate_file must respect its own bounded timeout, not hang past it")
    .unwrap_err();
    assert!(matches!(err, yadorilink_sync_core::SyncError::HydrationFailed(_)));

    // Left as a placeholder, not stuck at `Hydrating`.
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "unreachable.bin").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
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
        .set_materialization_policy(
            &root_b,
            yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
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
    impl yadorilink_sync_core::custody::FullReplicaCustody for RejectCustody {
        fn confirm_exact_version(
            &self,
            _group_id: &str,
            _path: &str,
            _version_hash: &yadorilink_sync_core::change::VersionHash,
            _blocks: &[yadorilink_sync_core::change::VersionBlock],
        ) -> Option<yadorilink_sync_core::custody::CustodyStamp> {
            None
        }

        fn confirmation_still_valid(
            &self,
            _group_id: &str,
            _stamp: &yadorilink_sync_core::custody::CustodyStamp,
        ) -> bool {
            false
        }
    }

    yadorilink_sync_core::materialization::evict_file(
        &device_b.state,
        &yadorilink_sync_core::block_liveness::BlockLivenessGate::default(),
        device_b.store.as_ref(),
        &device_b.root_path(),
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
        device_b.state.get_materialization_state(GROUP, "archive.zip").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
    );
    assert_ne!(
        std::fs::read(&path_on_b).unwrap(),
        content,
        "evicted file must no longer hold real content"
    );

    session_b.hydrate_file(GROUP, "archive.zip").await.unwrap();
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "archive.zip").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Hydrated)
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
            .set_materialization_policy(
                &root,
                yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
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
            device.state.get_materialization_state(GROUP, "presentation.pptx").unwrap(),
            Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
        );
        let record = device.state.get_file(GROUP, "presentation.pptx").unwrap().unwrap();
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
        device_b.state.get_materialization_state(GROUP, "presentation.pptx").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(&path_on_b).unwrap(), content);

    // C was never asked to hydrate and remains an untouched placeholder.
    assert_eq!(
        device_c.state.get_materialization_state(GROUP, "presentation.pptx").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
    );
    assert_ne!(std::fs::read(&path_on_c).unwrap(), content);
    let record_c = device_c.state.get_file(GROUP, "presentation.pptx").unwrap().unwrap();
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
        .set_materialization_policy(
            &root_b,
            yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // A placeholder exists locally (as if adopted from a peer earlier),
    // but the connected peer never answers the resulting block request.
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "orphaned.bin".into(),
                size: 5_000,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: vec![0x11u8; 32],
                    offset: 0,
                    size: 5_000,
                }],
                deleted: false,
            },
        )
        .unwrap();
    device_b
        .state
        .set_materialization_state(
            GROUP,
            "orphaned.bin",
            yadorilink_sync_core::types::MaterializationState::Placeholder,
        )
        .unwrap();
    yadorilink_sync_core::chunker::write_placeholder(
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
        device_b.state.get_materialization_state(GROUP, "orphaned.bin").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
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

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "tampered.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();
    device_b
        .state
        .set_materialization_state(
            GROUP,
            "tampered.bin",
            yadorilink_sync_core::types::MaterializationState::Placeholder,
        )
        .unwrap();
    yadorilink_sync_core::chunker::write_placeholder(
        &device_b.root_path().join("tampered.bin"),
        expected.len() as u64,
        0,
    )
    .unwrap();

    let (responder_channel, channel_b) = connect_pair(addr).await;
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let responder = tokio::spawn(async move {
        loop {
            let bytes = responder_channel.recv().await.unwrap();
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockResponse(
                            proto::BlockResponse {
                                block_hash: req.block_hash,
                                data: bad_data,
                                not_found: false,
                                compression: proto::Compression::None as i32,
                                ..Default::default()
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
    responder.await.unwrap();

    assert!(
        matches!(result, Err(yadorilink_sync_core::SyncError::HydrationFailed(_))),
        "invalid block bytes must fail hydration, got {result:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "mismatched bytes must not be persisted under the expected block hash"
    );
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "tampered.bin").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
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

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "public.bin".into(),
                size: public_data.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: public_hash,
                    offset: 0,
                    size: public_data.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "public.bin".to_string(),
                    block_hash: secret_hash.clone(),
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let response = loop {
        let bytes = requester_channel.recv().await.unwrap();
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        if let Some(proto::sync_message::Payload::BlockResponse(resp)) = msg.payload {
            break resp;
        }
    };

    assert_eq!(response.block_hash, secret_hash);
    assert!(response.not_found, "unreferenced block hash must be refused");
    assert!(response.data.is_empty(), "refused block response must not leak content bytes");
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
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    let record = device_a.state.get_file(GROUP, "secret.bin").unwrap().unwrap();
    device_b.state.upsert_file(GROUP, &record).unwrap();
    device_b
        .state
        .set_materialization_state(
            GROUP,
            "secret.bin",
            yadorilink_sync_core::types::MaterializationState::Placeholder,
        )
        .unwrap();
    yadorilink_sync_core::chunker::write_placeholder(
        &device_b.root_path().join("secret.bin"),
        5_000,
        0,
    )
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

/// Waits for and returns the next `BlockResponse` matching `hash` on
/// `channel`, ignoring any other message types (handshake `ClusterConfig`/
/// `FullIndex`, etc.) that may arrive interleaved — same pattern
/// `block_request_for_unreferenced_hash_is_refused` inlines, factored out
/// here since the mid-session-revocation test below needs it twice.
async fn recv_matching_block_response(channel: &PeerChannel, hash: &[u8]) -> proto::BlockResponse {
    loop {
        let bytes = channel.recv().await.unwrap();
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        if let Some(proto::sync_message::Payload::BlockResponse(resp)) = msg.payload {
            if resp.block_hash == hash {
                return resp;
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
    device_a.state.record_group_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "public.bin".into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    // session_a is the *answering* side — its live authorization is what
    // gets revoked mid-session below.
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    assert!(session_a.shares_group(GROUP), "sanity: session starts out authorized for GROUP");

    let send_request = |channel: Arc<PeerChannel>, hash: Vec<u8>| async move {
        channel
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockRequest(
                        proto::BlockRequest {
                            folder_group_id: GROUP.to_string(),
                            file_path: "public.bin".to_string(),
                            block_hash: hash,
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
    let first_response = recv_matching_block_response(&requester_channel, &hash).await;
    assert!(!first_response.not_found, "block request must succeed while peer is authorized");
    assert_eq!(first_response.data, data);

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
    let second_response = recv_matching_block_response(&requester_channel, &hash).await;
    assert!(
        second_response.not_found,
        "block request must be refused once a mid-session revocation is reflected in local \
         netmap/ACL state, even though the transport tunnel hasn't been torn down"
    );
    assert!(second_response.data.is_empty(), "refused block response must not leak content bytes");
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
        device_b.state.get_file(GROUP, "sneaky.txt").unwrap().is_none(),
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
    device_a.state.record_group_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "readable.bin".into(),
                size: data.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: data.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();

    let (channel_a, requester_channel) = connect_pair(addr).await;
    // session_a is the *answering* side, playing the sharer who has
    // authorized device-b for GROUP.
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    assert!(session_a.shares_group(GROUP), "sanity: the peer is authorized for the group");

    let send_request = |channel: Arc<PeerChannel>, hash: Vec<u8>| async move {
        channel
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockRequest(
                        proto::BlockRequest {
                            folder_group_id: GROUP.to_string(),
                            file_path: "readable.bin".to_string(),
                            block_hash: hash,
                        },
                    )),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    };

    send_request(requester_channel.clone(), hash.clone()).await;
    let response = recv_matching_block_response(&requester_channel, &hash).await;
    assert!(
        !response.not_found,
        "an authorized peer must be served existing content: block requests are gated only on \
         group authorization (shares_group)"
    );
    assert_eq!(response.data, data);
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;
    // The three edits are already committed to device-a's DAG by process_event
    // above; announcing the head carries the whole frontier to device-b at once.
    let _ = records;

    for (name, content) in &files {
        let replicated_path = device_b.root_path().join(name);
        announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20))
            .await;
        assert_eq!(&std::fs::read(&replicated_path).unwrap(), content);
        let record = device_b.state.get_file(GROUP, name).unwrap().unwrap();
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
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    let record = yadorilink_sync_core::types::FileRecord {
        path: "loser.bin".into(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        version,
        blocks: vec![yadorilink_sync_core::types::BlockInfo {
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
    let absent_version = yadorilink_sync_core::change::FileVersion::new(
        vec![yadorilink_sync_core::change::VersionBlock {
            hash: yadorilink_sync_core::change::BlockHash(block_hash.clone()),
            size: content.len() as u32,
        }],
        content.len() as u64,
        yadorilink_sync_core::change::FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: yadorilink_sync_core::types::RecordKind::File,
        },
    );
    let create_op = yadorilink_sync_core::change::Op::Create {
        path: yadorilink_sync_core::change::SyncPath("loser.bin".into()),
        version: absent_version.version_hash,
    };
    device_a
        .state
        .upsert_file_emitting_change(
            GROUP,
            &record,
            "device-a",
            vec![create_op],
            std::slice::from_ref(&absent_version),
            None,
            &device_a.emitter(),
        )
        .unwrap();
    // Intentionally NOT `device_a.store.put(&content)` — the block is absent,
    // so device-a answers device-b's block request `not_found`.

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // device-b eagerly materializes, cannot fetch the block, and (with the
    // fix) records a retriable placeholder instead of a Hydrated row.
    announce_until(
        &session_a,
        GROUP,
        || {
            device_b.state.get_materialization_state(GROUP, "loser.bin").unwrap()
                == Some(MaterializationState::Placeholder)
        },
        Duration::from_secs(25),
    )
    .await;

    // (a) Placeholder, never Hydrated.
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "loser.bin").unwrap(),
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
    let report = yadorilink_sync_core::materialization::repair_interrupted_materializations(
        &device_b.state,
        device_b.store.as_ref(),
        &device_b.root_path(),
        GROUP,
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
    device_a.state.record_group_block_provenance(GROUP, std::slice::from_ref(&block_hash)).unwrap();
    session_b.hydrate_file(GROUP, "loser.bin").await.unwrap();
    let out = device_b.root_path().join("loser.bin");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        content,
        "the real content must materialize once the peer can serve the block"
    );
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, "loser.bin").unwrap(),
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Announce device-b's evil_link/pwned.txt commit and wait until device-a
    // has ADMITTED it into its index — the point at which it tries to
    // materialize. Admission is a DAG/auth decision; the path-escape defense
    // lives in materialization, which must fail closed.
    announce_until(
        &session_b,
        GROUP,
        || device_a.state.get_file(GROUP, "evil_link/pwned.txt").unwrap().is_some(),
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    let replicated_path = device_b.root_path().join("cache.tmp");
    announce_until(&session_a, GROUP, || replicated_path.exists(), Duration::from_secs(20)).await;
    assert!(device_a.state.get_file(GROUP, "cache.tmp").unwrap().is_some());

    // Device A alone decides to ignore "*.tmp" — device-local and unsynced
    // ; device B's own config is untouched.
    std::fs::write(device_a.root_path().join(".yadorilinkignore"), "*.tmp\n").unwrap();
    let ignore_set = yadorilink_sync_core::ignore_patterns::EffectiveIgnoreSet::load_for_link_root(
        device_a.root_path(),
    )
    .unwrap();
    let changed = device_a
        .processor()
        .scan_existing_files_with_ignore(GROUP, &device_a.root_path(), &ignore_set)
        .unwrap();

    // A's own index no longer carries the now-ignored file...
    assert!(device_a.state.get_file(GROUP, "cache.tmp").unwrap().is_none());
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
    let record_b = device_b.state.get_file(GROUP, "cache.tmp").unwrap().unwrap();
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
        let heads = device_a.state.dag_group_heads(GROUP).unwrap();
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
        device_b.state.get_file(GROUP, "secret.log").unwrap().is_none(),
        "an incoming change for a locally-ignored path must never be added to the local index"
    );

    // The relay half: ignoring a path locally must not remove its change from
    // this device's DAG, or a third device that does not ignore `secret.log`
    // could never receive it through device B.
    assert!(
        device_b.state.dag_has_change(&secret_change).unwrap(),
        "the ignored path's change must still be admitted to this device's DAG so it can \
         still relay onward to a device that does not ignore the path"
    );
    // ... and the skip must retire the change as applied, not park it as a
    // retryable failure. Heads advancing past it is what tells the peer "we
    // already hold this", so it is never re-sent.
    assert!(
        device_b.state.dag_list_unapplied_changes(GROUP).unwrap().is_empty(),
        "an ignored path's change must retire as applied — recording the skip as a failure \
         would hold it unapplied forever and re-drive it every reprojection cycle"
    );
    assert_eq!(
        device_b.state.dag_group_heads(GROUP).unwrap(),
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
    let record_a = device_a.state.get_file(GROUP, "secret.log").unwrap().unwrap();
    let record_b = device_b.state.get_file(GROUP, "secret.log").unwrap().unwrap();
    assert_eq!(
        record_a.version.compare(&record_b.version),
        yadorilink_sync_core::version_vector::VvOrdering::Concurrent
    );

    // A's change for the path, captured before connecting (it is A's only
    // change, so A's frontier is exactly it). Waiting for *this hash* to land in
    // B's DAG is the only sound way to know B has actually seen A's edit — see
    // the settle loop below.
    let a_heads = device_a.state.dag_group_heads(GROUP).unwrap();
    assert_eq!(a_heads.len(), 1, "device A should have exactly one change to propagate");
    let a_change = a_heads[0];

    // Now the user adds the rule on B only — device-local and unsynced, so A
    // neither knows nor cares. Written before B's session is constructed because
    // the session snapshots its ignore set there.
    std::fs::write(device_b.root_path().join(".yadorilinkignore"), "secret.log\n").unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
    let b_has_a_change = || device_b.state.dag_has_change(&a_change).unwrap();
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
        device_b.state.dag_list_unapplied_changes(GROUP).unwrap().is_empty(),
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
/// `SyncState` rather than produced by a live scan/watch or a genuine
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

    let mut base_version = yadorilink_sync_core::version_vector::VersionVector::new();
    base_version.increment("device-a");
    let symlink_record = yadorilink_sync_core::types::FileRecord {
        path: "link.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        version: base_version.clone(),
        blocks: vec![],
        deleted: false,
    };
    device_b.state.upsert_file(GROUP, &symlink_record).unwrap();
    device_b
        .state
        .set_record_kind(GROUP, "link.txt", yadorilink_sync_core::types::RecordKind::Symlink)
        .unwrap();
    device_b
        .state
        .set_symlink_target(GROUP, "link.txt", Some(&target_path.to_string_lossy()))
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
        .mark_deleted_emitting_change(GROUP, "link.txt", "device-a", 0, &device_a.emitter())
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
    let record = device_b.state.get_file(GROUP, "link.txt").unwrap().unwrap();
    assert!(record.deleted, "the index must agree the record is now a tombstone");
}

/// A held file's held state must clear
/// once its record is tombstoned, rather than leaving an orphaned
/// `held_reason`/`held_since_unix_nanos` entry with no corresponding live
/// index record. Driven by a real, wire-transmitted tombstone (`deleted`
/// is an ordinary already-supported `FileRecord` field) through an actual
/// two-peer `PeerSyncSession` exchange — the held-file setup itself is
/// device-local index state (`SyncState::set_held`), the same as it would
/// be from a real case-fold-collision/invalid-name detection (section 4,
/// not yet implemented).
#[tokio::test]
async fn held_file_tombstone_clears_held_state() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let mut base_version = yadorilink_sync_core::version_vector::VersionVector::new();
    base_version.increment("device-a");
    let held_record = yadorilink_sync_core::types::FileRecord {
        path: "A.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        version: base_version.clone(),
        blocks: vec![],
        deleted: false,
    };
    device_b.state.upsert_file(GROUP, &held_record).unwrap();
    device_b.state.set_held(GROUP, "A.txt", "case_collision", 1_000).unwrap();
    assert!(
        device_b.state.get_held_state(GROUP, "A.txt").unwrap().is_some(),
        "sanity check: the file really is held before the tombstone arrives"
    );

    // device_a commits a tombstone for A.txt into the change DAG; device_b
    // adopts it over the wire. (deleted is an ordinary FileRecord field the
    // Delete op carries; the held state was set up device-locally above.)
    device_a
        .state
        .mark_deleted_emitting_change(GROUP, "A.txt", "device-a", 0, &device_a.emitter())
        .unwrap();

    let (channel_a, channel_b) = connect_pair(addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    announce_until(
        &session_a,
        GROUP,
        || matches!(device_b.state.get_file(GROUP, "A.txt"), Ok(Some(r)) if r.deleted),
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(
        device_b.state.get_held_state(GROUP, "A.txt").unwrap(),
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
    if !yadorilink_sync_core::hazard::is_case_insensitive_filesystem(&device_b.root_path()) {
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
        || device_b.state.get_held_state(GROUP, "photo.jpg").unwrap().is_some(),
        Duration::from_secs(20),
    )
    .await;

    let held = device_b.state.get_held_state(GROUP, "photo.jpg").unwrap().unwrap();
    assert!(held.reason.starts_with("case_collision"), "unexpected reason: {}", held.reason);

    // A held record still keeps its own index row.
    let stored = device_b.state.get_file(GROUP, "photo.jpg").unwrap().unwrap();
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
        .filter(|name| name != yadorilink_sync_core::root_identity::ROOT_MARKER_FILE_NAME)
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

/// A held file's record and content
/// blocks must keep flowing to peers exactly like any other record — held
/// state is a *local* materialization gate (this device won't write the
/// bytes to disk under this hazardous name), not an exclusion from index
/// exchange or block serving (the design: "the index continues tracking
/// it... so it still syncs correctly to any peer/platform where the name
/// is valid"). Held state is set up directly against device B's own
/// `SyncState`/`BlockStore` here (the same device-local setup
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
    assert!(device_b.state.get_held_state(GROUP, "photo.jpg").unwrap().is_some());
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
    // text in device A's own `SyncState` in the first place.
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
        device_a.state.get_record_kind(GROUP, "shortcut").unwrap(),
        Some(yadorilink_sync_core::types::RecordKind::Symlink),
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
        device_b.state.get_record_kind(GROUP, "shortcut").unwrap(),
        Some(yadorilink_sync_core::types::RecordKind::Symlink)
    );
    assert_eq!(
        device_b.state.get_symlink_target(GROUP, "shortcut").unwrap(),
        Some("original.txt".to_string())
    );
}

/// Closes the same wire gap as the symlink
/// test above, for the other field the gap silently dropped in both
/// directions — the owner-executable bit. Device A's index records a file
/// as executable (`SyncState::set_exec_bit`, standing in for section 2/3's
/// still-separately-open local-capture wiring — see `types.rs`'s
/// `owner_exec_bit_from_metadata` doc comment for that distinct, still-
/// undone gap; this test is scoped to whether an *already-recorded* bit
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
    let _session_a = spawn_session(channel_a, &device_a, "device-b");

    // Advertise compression support as a raw peer (not a full
    // `PeerSyncSession`) so this test can inspect exactly what
    // `handle_block_request` puts on the wire in response.
    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                    folder_group_ids: vec![GROUP.to_string()],
                    known_peer_device_ids: vec!["device-b".to_string()],
                    supported_compression: vec![proto::Compression::Zstd as i32],
                    ..Default::default()
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
    // The handshake ClusterConfig is handled by a spawned message-handler
    // task (`run`'s recv loop), so give it a moment to land before the
    // block request that depends on it having been processed.
    tokio::time::sleep(Duration::from_millis(200)).await;

    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "big.txt".to_string(),
                    block_hash: block.hash.clone(),
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let response = recv_matching_block_response(&requester_channel, &block.hash).await;

    assert_eq!(
        response.compression,
        proto::Compression::Zstd as i32,
        "a negotiated-compression peer must receive a Zstd-tagged response for compressible \
         content"
    );
    assert!(
        response.data.len() < (block.size as usize) / 2,
        "compressed payload ({} bytes) should be well under half the raw block size ({} bytes) \
         for highly repetitive text",
        response.data.len(),
        block.size
    );
    let decompressed = zstd::stream::decode_all(response.data.as_slice()).unwrap();
    assert_eq!(decompressed.len(), block.size as usize);
    assert_eq!(
        sha256_bytes(&decompressed),
        block.hash,
        "decompressed wire bytes must match the block's content hash (D4)"
    );
}

/// A peer that never advertises compression support (an old,
/// pre-this-change peer, simulated here by simply never sending a
/// `ClusterConfig` with `supported_compression` set) must never receive a
/// `Compression::Zstd`-tagged response — block fetch behaves identically
/// to pre-change behavior, byte-for-byte.
#[tokio::test]
async fn block_response_is_uncompressed_when_peer_did_not_advertise_support() {
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
    let _session_a = spawn_session(channel_a, &device_a, "device-b");

    // Deliberately no `ClusterConfig` sent at all from this raw peer —
    // `PeerSyncSession::compression_negotiated` must stay `false`.
    requester_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: "big.txt".to_string(),
                    block_hash: block.hash.clone(),
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let response = recv_matching_block_response(&requester_channel, &block.hash).await;

    assert_eq!(
        response.compression,
        proto::Compression::None as i32,
        "a peer that never advertised compression support must never receive a compressed block"
    );
    assert_eq!(
        response.data, content,
        "an unnegotiated block response must carry the exact raw bytes, unchanged"
    );
}

/// A decompression-bomb bound: a `BlockResponse` declaring
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

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "bomb.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();
    device_b
        .state
        .set_materialization_state(
            GROUP,
            "bomb.bin",
            yadorilink_sync_core::types::MaterializationState::Placeholder,
        )
        .unwrap();
    yadorilink_sync_core::chunker::write_placeholder(
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
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let responder = tokio::spawn(async move {
        loop {
            let bytes = responder_channel.recv().await.unwrap();
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockResponse(
                            proto::BlockResponse {
                                block_hash: req.block_hash,
                                data: bomb,
                                not_found: false,
                                compression: proto::Compression::Zstd as i32,
                                ..Default::default()
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
    responder.await.unwrap();

    assert!(
        matches!(result, Err(yadorilink_sync_core::SyncError::HydrationFailed(_))),
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
        device_b.state.get_materialization_state(GROUP, "bomb.bin").unwrap(),
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
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

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "corrupt.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();
    device_b
        .state
        .set_materialization_state(
            GROUP,
            "corrupt.bin",
            yadorilink_sync_core::types::MaterializationState::Placeholder,
        )
        .unwrap();
    yadorilink_sync_core::chunker::write_placeholder(
        &device_b.root_path().join("corrupt.bin"),
        expected.len() as u64,
        0,
    )
    .unwrap();

    let (responder_channel, channel_b) = connect_pair(addr).await;
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let responder = tokio::spawn(async move {
        loop {
            let bytes = responder_channel.recv().await.unwrap();
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
                continue;
            };
            responder_channel
                .send(
                    proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockResponse(
                            proto::BlockResponse {
                                block_hash: req.block_hash,
                                data: vec![0xFFu8; 256], // not a valid zstd frame
                                not_found: false,
                                compression: proto::Compression::Zstd as i32,
                                ..Default::default()
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
    responder.await.unwrap();

    assert!(
        matches!(result, Err(yadorilink_sync_core::SyncError::HydrationFailed(_))),
        "an undecompressable block response must fail hydration, got {result:?}"
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
        .set_materialization_policy(
            &root_b,
            yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
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
/// `reconcile_files`'s batched prefetch (`SyncState::get_files_by_paths` +
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
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let auth = dag_authenticator(&[&device_a, &device_b]);
    session_a.set_change_authenticator(auth.clone());
    session_b.set_change_authenticator(auth.clone());
    wait_dag_negotiated(&session_a, &session_b, Duration::from_secs(10)).await;

    // Initial full sync over the DAG — every file materializes on device_b.
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
    let all_records = device_a.state.list_files(GROUP).unwrap();
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
    // is `SyncState::get_files_by_paths`'s own comparative timing test in
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
/// adopts it outright via `reconcile_one_file`'s `VvOrdering::Before`
/// branch — exercising `materialize`'s tombstone-apply path over the real
/// wire, not a direct `SyncState` call.
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
        .mark_deleted_emitting_change(GROUP, "shared.txt", "device-b", 2000, &device_b.emitter())
        .unwrap();
    announce_until(
        &session_b,
        GROUP,
        || !device_a.root_path().join("shared.txt").exists(),
        Duration::from_secs(20),
    )
    .await;

    // The tombstone is now device A's current record for this path...
    let current = device_a.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    assert!(current.deleted, "device A must have adopted the peer's tombstone");

    // ...but its own prior real content is recoverable from trash, not
    // discarded — this is the property this test exists to prove.
    let trashed = device_a.state.list_trashed(GROUP).unwrap();
    assert_eq!(trashed.len(), 1, "the file's last live content must be listed under trash");
    assert_eq!(trashed[0].path, "shared.txt");
    assert_eq!(trashed[0].last_known_size, content_a.len() as u64);

    let versions = device_a.state.list_versions(GROUP, "shared.txt").unwrap();
    let trashed_version =
        versions.iter().find(|v| v.state == yadorilink_sync_core::index::VersionState::Trashed);
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
    let _session_a = spawn_session(channel_a, &device_a, "device-b");

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
                        payload: Some(proto::sync_message::Payload::BlockResponse(
                            proto::BlockResponse {
                                block_hash: hash.clone(),
                                data: content.clone(),
                                not_found: false,
                                compression: proto::Compression::None as i32,
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
    // held by a task awaiting a `BlockResponse` nobody had sent yet.
    wait_until(
        || device_a.state.get_file(GROUP, "stress-control-signal").unwrap().is_some(),
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
