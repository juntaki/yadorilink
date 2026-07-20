//! parallel-multi-peer-fetch real, connected-session
//! integration tests for `yadorilink_daemon::hydration`'s multi-session
//! block dispatch. Deliberately lightweight — directly paired transport
//! channels over loopback plus hand-built `PeerSyncSession`s, like
//! `yadorilink-sync-core/tests/peer_session.rs`, rather than the full
//! coordination-plane harness other daemon tests use — so each device's
//! block store can be populated with a precise, controlled subset of a
//! file's blocks (asymmetric holdings aren't something normal sync traffic
//! produces on its own).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_sync_core::chunker::DEFAULT_BLOCK_SIZE;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::types::{BlockInfo, FileRecord, MaterializationState};
use yadorilink_sync_core::version_vector::VersionVector;
use yadorilink_transport::{PeerChannel, TransportHub};

const GROUP: &str = "shared";
const PATH: &str = "big.bin";

// Peers connect directly over loopback. This still hands back a real,
// unused address so the existing call sites keep their shape;
// `connect_pair` ignores it and wires a direct loopback pair instead.
async fn bind_unused_addr() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn connect_pair(_addr: std::net::SocketAddr) -> (Arc<PeerChannel>, Arc<PeerChannel>) {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    // Direct loopback: bind each side's UDP socket and hand the other its
    // address as the sole direct candidate — the same wiring the daemon's
    // peer orchestrator uses to pair two channels.
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![addr_b],
        TransportHub::from_socket(socket_a, None),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        TransportHub::from_socket(socket_b, None),
    )
    .await
    .unwrap();
    (Arc::new(a), Arc::new(b))
}

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    store_root: tempfile::TempDir,
}

fn new_device(device_id: &str) -> TestDevice {
    let store_root = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_root.path()).unwrap());
    let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDevice {
        device_id: device_id.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        store_root,
    }
}

/// Chunks `content` once (via a throwaway store, purely to compute the
/// canonical block list/hashes) and returns the block list plus each
/// block's raw bytes, so the caller can selectively populate different
/// devices' block stores with different subsets.
fn chunk_content(content: &[u8]) -> (Vec<BlockInfo>, HashMap<Vec<u8>, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsBlockStore::new(dir.path()).unwrap();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, content).unwrap();
    let blocks = yadorilink_sync_core::chunker::chunk_file(&store, &src).unwrap();
    let mut data_by_hash = HashMap::new();
    for block in &blocks {
        let hash_hex = hex::encode(&block.hash);
        data_by_hash.insert(block.hash.clone(), store.get(&hash_hex).unwrap());
    }
    (blocks, data_by_hash)
}

/// Indexes the file as a placeholder on `device` (no full-content write to
/// disk — this test only cares about block-store/hydration behavior) and
/// stores exactly `owned_blocks` worth of raw content in its block store.
fn seed_placeholder(
    device: &TestDevice,
    blocks: &[BlockInfo],
    total_size: u64,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    let mut version = VersionVector::new();
    version.increment("device-seed");
    let record = FileRecord {
        path: PATH.to_string(),
        size: total_size,
        mtime_unix_nanos: 0,
        version,
        blocks: blocks.to_vec(),
        deleted: false,
    };
    device.state.sync_state.upsert_file(GROUP, &record).unwrap();
    device
        .state
        .sync_state
        .set_materialization_state(GROUP, PATH, MaterializationState::Placeholder)
        .unwrap();
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.sync_state.add_link(&local_path, GROUP).unwrap();
    device
        .state
        .sync_state
        .set_materialization_policy(
            &local_path,
            yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
        )
        .unwrap();
    for block in owned_blocks {
        device.state.block_store.put(&data_by_hash[&block.hash]).unwrap();
    }
}

/// Connects `hydrating`'s session-to-`peer` (inserted into `hydrating`'s
/// own `state.sessions`, as `peer_orchestrator` would) and `peer`'s
/// session-to-`hydrating` (spawned and running, so it can answer block
/// requests, but not tracked anywhere `hydrating`-side needs).
async fn connect_as_peer(addr: std::net::SocketAddr, hydrating: &TestDevice, peer: &TestDevice) {
    let (channel_hydrating, channel_peer) = connect_pair(addr).await;
    let session_to_peer = PeerSyncSession::new(
        channel_hydrating,
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.sync_state.clone(),
        hydrating.state.block_store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), hydrating.root.path().to_path_buf())]),
    );
    tokio::spawn(session_to_peer.clone().run());
    hydrating.state.sessions.lock().unwrap().insert(peer.device_id.clone(), session_to_peer);

    let session_from_hydrating = PeerSyncSession::new(
        channel_peer,
        peer.device_id.clone(),
        hydrating.device_id.clone(),
        peer.state.sync_state.clone(),
        peer.state.block_store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), peer.root.path().to_path_buf())]),
    );
    tokio::spawn(session_from_hydrating.run());
}

fn big_content() -> Vec<u8> {
    (0..(DEFAULT_BLOCK_SIZE * 6)).map(|i| (i % 251) as u8).collect()
}

/// blocks split across two peer sessions, each holding only
/// some of the blocks — hydration succeeds and reconstructs identical
/// content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_split_across_two_peers_each_holding_a_disjoint_subset() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 4, "test needs multiple blocks to split meaningfully");
    let half = blocks.len() / 2;

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_d = new_device("device-d");

    seed_placeholder(&device_b, &blocks, content.len() as u64, &blocks[..half], &data_by_hash);
    seed_placeholder(&device_c, &blocks, content.len() as u64, &blocks[half..], &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(addr, &device_d, &device_b).await;
    connect_as_peer(addr, &device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();

    assert_eq!(
        device_d.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Hydrated)
    );
    let reconstructed = std::fs::read(device_d.root.path().join(PATH)).unwrap();
    assert_eq!(reconstructed, content);
}

/// one peer reports a block not found; a second connected peer
/// does hold it — hydration still succeeds via the second peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_not_found_on_one_peer_is_fetched_from_another() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 2);

    let device_b = new_device("device-b"); // has nothing at all
    let device_c = new_device("device-c"); // has everything
    let device_d = new_device("device-d"); // hydrating

    seed_placeholder(&device_b, &blocks, content.len() as u64, &[], &data_by_hash);
    seed_placeholder(&device_c, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(addr, &device_d, &device_b).await;
    connect_as_peer(addr, &device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();

    let reconstructed = std::fs::read(device_d.root.path().join(PATH)).unwrap();
    assert_eq!(reconstructed, content);
}

/// no connected peer holds one particular block — hydration
/// fails cleanly, the file remains a placeholder, and nothing corrupt is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_missing_from_every_peer_fails_hydration_cleanly() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 2);
    // Neither device ever gets the *last* block.
    let owned = &blocks[..blocks.len() - 1];

    let device_b = new_device("device-b");
    let device_d = new_device("device-d");

    seed_placeholder(&device_b, &blocks, content.len() as u64, owned, &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(addr, &device_d, &device_b).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = hydration::hydrate(&device_d.state, GROUP, PATH).await;
    assert!(result.is_err(), "hydration must fail when a block is unavailable from every peer");
    assert_eq!(
        device_d.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Placeholder),
        "file must remain a placeholder, not end up stuck Hydrating or falsely Hydrated"
    );
    assert!(
        !device_d.root.path().join(PATH).exists(),
        "no partial/corrupt content should be written on failure"
    );
}

/// hydrating with three connected peers, all holding the full
/// file, completes correctly — not just the two-peer minimum case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hydration_succeeds_with_three_full_peers() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_e = new_device("device-e");
    let device_d = new_device("device-d");

    for peer in [&device_b, &device_c, &device_e] {
        seed_placeholder(peer, &blocks, content.len() as u64, &blocks, &data_by_hash);
    }
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(addr, &device_d, &device_b).await;
    connect_as_peer(addr, &device_d, &device_c).await;
    connect_as_peer(addr, &device_d, &device_e).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();
    assert_eq!(std::fs::read(device_d.root.path().join(PATH)).unwrap(), content);
}

/// A non-timeout failure after entering `Hydrating` must restore the
/// retryable placeholder state.  Making the registered link root a regular
/// file forces `reconstruct_file` to fail deterministically after all blocks
/// have already been found locally, without relying on transport timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_hydration_error_restores_placeholder_state() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let peer = new_device("device-peer");
    let hydrating = new_device("device-hydrating");
    seed_placeholder(&peer, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &blocks, &data_by_hash);
    connect_as_peer(addr, &hydrating, &peer).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let root_path = hydrating.root.path().to_path_buf();
    std::fs::remove_dir_all(&root_path).unwrap();
    std::fs::write(&root_path, b"not a directory").unwrap();

    let result = hydration::hydrate(&hydrating.state, GROUP, PATH).await;
    assert!(result.is_err(), "the invalid output root must fail hydration");
    assert_eq!(
        hydrating.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Placeholder),
        "ordinary hydration errors must not leave the file stuck Hydrating"
    );
}

/// A corrupt hash-named block that cannot be repaired — no peer is reachable
/// to supply a good copy — is reported by `BlockStore::get` during
/// reconstruction. That ordinary error must leave the file retryable rather
/// than permanently stuck `Hydrating`. (When a peer *is* connected the
/// corrupt block is instead refetched and hydration succeeds — see
/// `corrupt_local_block_is_refetched_when_peer_exists`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_local_block_restores_placeholder_state() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    // No peer is connected, so the corrupt block genuinely cannot be
    // refetched: the checksum mismatch surfaces at reconstruction time.
    let hydrating = new_device("device-hydrating");
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &blocks, &data_by_hash);

    let hash = hex::encode(&blocks[0].hash);
    let block_path = hydrating.store_root.path().join(&hash[..2]).join(&hash[2..4]).join(&hash);
    std::fs::write(block_path, b"corrupt bytes").unwrap();

    let result = hydration::hydrate(&hydrating.state, GROUP, PATH).await;
    assert!(result.is_err(), "an unrepairable checksum mismatch must fail hydration");
    assert_eq!(
        hydrating.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Placeholder),
        "corrupt-block hydration failure must restore Placeholder"
    );
}

/// `hydration::pin`'s multi-session dispatch path — the pin
/// flag is set correctly alongside successful multi-peer hydration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pin_hydrates_via_multiple_peers_and_sets_the_pin_flag() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    let half = blocks.len() / 2;

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_d = new_device("device-d");

    seed_placeholder(&device_b, &blocks, content.len() as u64, &blocks[..half], &data_by_hash);
    seed_placeholder(&device_c, &blocks, content.len() as u64, &blocks[half..], &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(addr, &device_d, &device_b).await;
    connect_as_peer(addr, &device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    hydration::pin(&device_d.state, GROUP, PATH).await.unwrap();

    assert_eq!(
        device_d.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert!(device_d.state.sync_state.is_pinned(GROUP, PATH).unwrap());
    assert_eq!(std::fs::read(device_d.root.path().join(PATH)).unwrap(), content);
}

/// the file-level deadline bounds the *whole* multi-session
/// dispatch — hydration against an unresponsive peer (connected, but
/// never answering any request) fails within roughly the configured
/// deadline rather than hanging indefinitely.
///
/// Note: this test covers the deterministic, always-guaranteed half of
/// 's goal (the deadline is a hard upper bound on the whole
/// operation). The more optimistic "a fast, fully-responsive peer's
/// share completes without waiting for a co-present unresponsive peer"
/// is *not* separately asserted here — sophisticated
/// piece-selection/peer-prioritization is explicitly out of scope
/// (round-robin/first-available assignment is deliberately simple), so
/// whether a slow peer's checked-out-but-never-returned block delays the
/// fast peer's otherwise-complete result is inherent to that simplicity,
/// not a regression to guard against here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hydration_deadline_bounds_an_unresponsive_peer() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device_b = new_device("device-b");
    let device_d = new_device("device-d");
    seed_placeholder(&device_b, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    // Connect D's session to B, but never start B's session-to-D — B is
    // reachable at the transport level but never answers anything,
    // simulating a peer that's connected yet fully unresponsive.
    let (channel_d, _channel_b_unused) = connect_pair(addr).await;
    let session_d_to_b = PeerSyncSession::new(
        channel_d,
        device_d.device_id.clone(),
        device_b.device_id.clone(),
        device_d.state.sync_state.clone(),
        device_d.state.block_store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), device_d.root.path().to_path_buf())]),
    );
    tokio::spawn(session_d_to_b.clone().run());
    device_d.state.sessions.lock().unwrap().insert(device_b.device_id.clone(), session_d_to_b);

    let short_timeout = Duration::from_millis(500);
    let started = std::time::Instant::now();
    let result = hydration::hydrate_with_timeout(&device_d.state, GROUP, PATH, short_timeout).await;
    let elapsed = started.elapsed();

    assert!(result.is_err(), "hydration against a fully unresponsive peer must fail, not hang");
    assert!(
        elapsed < short_timeout + Duration::from_secs(2),
        "the deadline must bound the whole operation; took {elapsed:?} for a {short_timeout:?} deadline"
    );
    assert_eq!(
        device_d.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Placeholder)
    );
}

/// Cancelling the hydration future after it entered `Hydrating` must run
/// the same state cleanup as an ordinary error or timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_hydration_restores_placeholder_state() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let peer = new_device("device-peer");
    let hydrating = new_device("device-hydrating");
    seed_placeholder(&peer, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &[], &data_by_hash);

    let (channel_hydrating, _unresponsive_peer) = connect_pair(addr).await;
    let session = PeerSyncSession::new(
        channel_hydrating,
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.sync_state.clone(),
        hydrating.state.block_store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), hydrating.root.path().to_path_buf())]),
    );
    tokio::spawn(session.clone().run());
    hydrating.state.sessions.lock().unwrap().insert(peer.device_id.clone(), session);

    let state = hydrating.state.clone();
    let task = tokio::spawn(async move { hydration::hydrate(&state, GROUP, PATH).await });
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if hydrating.state.sync_state.get_materialization_state(GROUP, PATH).unwrap()
                == Some(MaterializationState::Hydrating)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("hydration should enter Hydrating before cancellation");

    task.abort();
    let _ = task.await;
    assert_eq!(
        hydrating.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Placeholder),
        "cancelling hydration must not leave the file stuck Hydrating"
    );
}

/// A configured download rate caps *aggregate* throughput across
/// concurrent multi-peer hydration — the hydrating device's sessions to
/// two different peers share the daemon's one `state.rate_limiters`
/// instance (exactly as `peer_orchestrator`
/// wires real sessions), so fetching one block from each peer concurrently
/// draws down the *same* bucket rather than each peer's fetch getting an
/// independent full-rate allowance. Distinguishes the two by wall-clock
/// time: under a shared bucket, the combined 2-block transfer takes
/// roughly `(total_bytes - burst) / rate`; under independent per-peer
/// buckets, both blocks would complete in parallel in roughly
/// `(block_size - burst) / rate` — well under half the shared-bucket time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_rate_caps_aggregate_throughput_across_concurrent_multi_peer_hydration() {
    let addr = bind_unused_addr().await;
    // Exactly 2 blocks (not `big_content`'s 6) — enough to split one per
    // peer while keeping the throttled transfer's real wall-clock time
    // reasonable for a test.
    let content: Vec<u8> = (0..(DEFAULT_BLOCK_SIZE * 2)).map(|i| (i % 251) as u8).collect();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert_eq!(blocks.len(), 2, "test assumes exactly 2 blocks, one per peer");
    let half = blocks.len() / 2;

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_d = new_device("device-d");

    seed_placeholder(&device_b, &blocks, content.len() as u64, &blocks[..half], &data_by_hash);
    seed_placeholder(&device_c, &blocks, content.len() as u64, &blocks[half..], &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    // Throttle D's *shared* download bucket before connecting — every
    // session D constructs below is wired to this exact `Arc`, the same
    // way `peer_orchestrator::spawn_peer_session` wires real ones to
    // `state.rate_limiters`.
    let rate_bytes_per_sec = 50_000u64;
    device_d.state.rate_limiters.download.set_rate_bytes_per_sec(rate_bytes_per_sec);

    connect_as_peer_sharing_hydrating_rate_limiters(addr, &device_d, &device_b).await;
    connect_as_peer_sharing_hydrating_rate_limiters(addr, &device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let start = std::time::Instant::now();
    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();
    let elapsed = start.elapsed();

    let reconstructed = std::fs::read(device_d.root.path().join(PATH)).unwrap();
    assert_eq!(reconstructed, content);

    // The independent-per-peer prediction for a single ~half-content block
    // under this rate/capacity is well under 3s; a shared bucket pushes the
    // *combined* transfer well past it — see the doc comment above for the
    // exact math.
    assert!(
        elapsed >= Duration::from_secs(3),
        "expected the shared download bucket to bound aggregate throughput \
         (roughly (total_bytes - burst) / rate), took only {elapsed:?}"
    );
}

/// A placeholder whose blocks are all already present in the local block
/// store (e.g. retained from a prior version, or not yet evicted because
/// custody was never confirmed) must hydrate from local storage alone —
/// no candidate peer is connected at all here, so a hydration that
/// insisted on a reachable peer before ever checking local presence would
/// fail this file for no reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn placeholder_with_all_local_blocks_hydrates_without_peers() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device = new_device("device-solo");
    // Every block this placeholder needs is already in the local block
    // store; no peer is connected at all.
    seed_placeholder(&device, &blocks, content.len() as u64, &blocks, &data_by_hash);

    hydration::hydrate(&device.state, GROUP, PATH)
        .await
        .expect("all needed blocks are already local; hydration must not require a peer");

    assert_eq!(
        device.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(device.root.path().join(PATH)).unwrap(), content);
}

/// One needed block is corrupt on disk locally, but a connected peer holds
/// a good copy of it — hydration must still succeed by fetching just that
/// one block from the peer, rather than failing the whole operation
/// because a shallow "is this hash's file present" check treated the
/// corrupt bytes as already-satisfied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_local_block_is_refetched_when_peer_exists() {
    let addr = bind_unused_addr().await;
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let peer = new_device("device-peer");
    let hydrating = new_device("device-hydrating");
    seed_placeholder(&peer, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &blocks, &data_by_hash);
    connect_as_peer(addr, &hydrating, &peer).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let hash = hex::encode(&blocks[0].hash);
    let block_path = hydrating.store_root.path().join(&hash[..2]).join(&hash[2..4]).join(&hash);
    std::fs::write(block_path, b"corrupt bytes").unwrap();

    hydration::hydrate(&hydrating.state, GROUP, PATH).await.expect(
        "a corrupt local block should be refetched from a peer that holds it, \
         not fail the whole hydration",
    );

    assert_eq!(std::fs::read(hydrating.root.path().join(PATH)).unwrap(), content);
}

/// A file evicted back to a placeholder while custody was never confirmed
/// (the "last known local copy" case: an on-demand device that can't yet
/// prove a full replica durably holds this version, so it fails closed and
/// keeps its cached blocks rather than reclaiming them) must remain
/// readable while completely offline — every block it needs is still in
/// the local block store even though the on-disk file itself is now a
/// placeholder marker, and no peer is reachable to re-fetch anything from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_last_local_copy_remains_user_accessible_offline() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device = new_device("device-solo");
    seed_placeholder(&device, &blocks, content.len() as u64, &blocks, &data_by_hash);
    std::fs::write(device.root.path().join(PATH), &content).unwrap();
    device
        .state
        .sync_state
        .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated)
        .unwrap();

    // No custody confirmer is installed on this device, so it can never
    // confirm a full replica durably holds this version — eviction fails
    // closed and retains the cached blocks (see
    // `DaemonState::full_replica_custody_confirmed`'s doc comment).
    hydration::evict(&device.state, GROUP, PATH).unwrap();
    assert_eq!(
        device.state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(MaterializationState::Placeholder),
        "eviction placeholders the on-disk file even when the blocks themselves are retained"
    );
    let hashes: Vec<_> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    assert!(
        device
            .state
            .block_store
            .present_blocks(&hashes)
            .unwrap()
            .into_iter()
            .all(|present| present),
        "custody-unconfirmed eviction must retain every block rather than reclaiming them"
    );

    // No peer is connected at all — offline. Every block this placeholder
    // needs is still sitting in the local block store from before eviction.
    hydration::hydrate(&device.state, GROUP, PATH)
        .await
        .expect("a retained last local copy must remain hydratable while offline");

    assert_eq!(std::fs::read(device.root.path().join(PATH)).unwrap(), content);
}

/// Like `connect_as_peer`, but wires both of the hydrating device's
/// sessions-to-peer onto `hydrating.state.rate_limiters` ("same
/// bucket" — mirrors what `peer_orchestrator::spawn_peer_session` does for
/// every real production session) instead of each session defaulting to
/// its own independent unlimited pair.
async fn connect_as_peer_sharing_hydrating_rate_limiters(
    addr: std::net::SocketAddr,
    hydrating: &TestDevice,
    peer: &TestDevice,
) {
    let (channel_hydrating, channel_peer) = connect_pair(addr).await;
    let session_to_peer = PeerSyncSession::new(
        channel_hydrating,
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.sync_state.clone(),
        hydrating.state.block_store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), hydrating.root.path().to_path_buf())]),
    );
    session_to_peer.set_rate_limiters(hydrating.state.rate_limiters.clone());
    tokio::spawn(session_to_peer.clone().run());
    hydrating.state.sessions.lock().unwrap().insert(peer.device_id.clone(), session_to_peer);

    let session_from_hydrating = PeerSyncSession::new(
        channel_peer,
        peer.device_id.clone(),
        hydrating.device_id.clone(),
        peer.state.sync_state.clone(),
        peer.state.block_store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), peer.root.path().to_path_buf())]),
    );
    // The serving peer's own upload bucket is irrelevant to this test (this
    // asserts on D's shared *download* bucket only) — left unlimited, the
    // session's construction default.
    tokio::spawn(session_from_hydrating.run());
}
