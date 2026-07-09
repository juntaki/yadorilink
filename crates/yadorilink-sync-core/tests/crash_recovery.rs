//! add-crash-power-loss-recovery task 3.2: a daemon-restart integration
//! test proving a local change already committed to this device's
//! `SyncState` (as it would be by `LocalChangeProcessor` processing a
//! real filesystem event) but never yet broadcast to a connected peer —
//! exactly what a crash right after the DB commit but before the
//! outbound `IndexUpdate`/broadcast would leave behind — still reaches
//! that peer once this device reconnects after "restarting", with no
//! separate persisted retry queue needed.
//!
//! This lives in its own integration-test binary (new file, no edits to
//! the existing `tests/peer_session.rs`) specifically so it can be
//! developed and run independently of that file's own concurrent,
//! unrelated in-flight changes — it duplicates a small slice of that
//! file's test harness (`start_relay`/`gen_keypair`/`connect_pair`/
//! `spawn_session`) rather than sharing code with it, deliberately, for
//! the same reason.
//!
//! The mechanism this proves already exists and needed no new production
//! code: `PeerSyncSession::run` unconditionally sends a full index for
//! every shared folder group at the *start* of every session (see that
//! function's doc comment, "sends the initial handshake + full index for
//! each shared folder group"), independent of whatever the previous
//! session for the same peer did or didn't manage to broadcast before it
//! died. Combined with `yadorilink-daemon::main`'s startup resuming every
//! link's watcher (a full `scan_existing_files` rescan, which independently
//! catches any change made while the daemon was down entirely), this is
//! what closes the "pending local changes are retried after restart" gap
//! — this test is what turns that into a verified guarantee instead of an
//! assumption.

use std::sync::Arc;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::TcpListener;
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::types::{BlockInfo, FileRecord};
use yadorilink_sync_core::version_vector::VersionVector;
use yadorilink_transport::{PeerChannel, RelayHub, TransportMode};

const GROUP: &str = "shared-photos";

async fn start_relay() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = yadorilink_transport::relay_server::serve(listener).await;
    });
    addr
}

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// A persistent device identity: state and block store survive across a
/// simulated crash/restart (only the `PeerSyncSession`/`PeerChannel` pair
/// gets torn down and rebuilt), exactly as a real daemon's on-disk SQLite
/// DB and block store survive a process kill.
struct Device {
    device_id: String,
    root: tempfile::TempDir,
    store: Arc<FsBlockStore>,
    state: Arc<SyncState>,
}

impl Device {
    fn new(device_id: &str) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        Device {
            device_id: device_id.to_string(),
            root: tempfile::tempdir().unwrap(),
            store: Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            state: Arc::new(SyncState::open_in_memory().unwrap()),
        }
    }

    fn sync_roots(&self) -> std::collections::HashMap<String, std::path::PathBuf> {
        std::collections::HashMap::from([(GROUP.to_string(), self.root.path().to_path_buf())])
    }
}

async fn connect_pair(relay_addr: std::net::SocketAddr) -> (Arc<PeerChannel>, Arc<PeerChannel>) {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let hub_a = RelayHub::connect(relay_addr, secret_a.clone()).await.unwrap();
    let hub_b = RelayHub::connect(relay_addr, secret_b.clone()).await.unwrap();
    let a = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_a,
        public_b,
        0,
        Some(hub_a),
        vec![],
        None,
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_b,
        public_a,
        1,
        Some(hub_b),
        vec![],
        None,
    )
    .await
    .unwrap();
    (Arc::new(a), Arc::new(b))
}

fn spawn_session(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> (Arc<PeerSyncSession>, tokio::task::JoinHandle<()>) {
    let session = PeerSyncSession::new(
        channel,
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone(),
        device.store.clone(),
        vec![GROUP.to_string()],
        device.sync_roots(),
    );
    let handle = tokio::spawn({
        let session = session.clone();
        async move {
            let _ = session.run().await;
        }
    });
    (session, handle)
}

async fn wait_until<F: Fn() -> bool>(cond: F, timeout: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        if tokio::time::Instant::now() >= deadline {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn record_with_content(path: &str, content: &[u8], hash_hex: &str) -> FileRecord {
    let mut version = VersionVector::new();
    version.increment("device-a");
    FileRecord {
        path: path.to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        version,
        blocks: vec![BlockInfo {
            hash: hex::decode(hash_hex).unwrap(),
            offset: 0,
            size: content.len() as u32,
        }],
        deleted: false,
    }
}

/// task 3.2: the core restart-retry scenario. Device A commits a local
/// change directly to its own `SyncState`/block store/disk — simulating
/// exactly what `LocalChangeProcessor` would have already durably done
/// for a real filesystem event — but its first session with device B is
/// torn down (simulating a crash) before anything ever broadcasts that
/// change over the wire. A fresh session for the same two persistent
/// device identities (device B's state/store are also untouched by the
/// "crash", exactly like a peer that stayed running throughout) must
/// still converge: device B ends up with the file even though it was
/// never told about it before the "restart".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_change_committed_before_a_crash_is_retried_via_full_index_on_reconnect() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // --- "pre-crash" session pair: an empty initial sync settles first,
    // matching a real daemon's startup handshake before any local edit
    // happens. ---
    let (chan_a1, chan_b1) = connect_pair(relay_addr).await;
    let (session_a1, handle_a1) = spawn_session(chan_a1.clone(), &device_a, "device-b");
    let (session_b1, handle_b1) = spawn_session(chan_b1.clone(), &device_b, "device-a");

    // Give the initial (empty) handshake a moment to complete before the
    // "crash" — a real daemon restart happens well after startup, not
    // mid-handshake.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Device A's local change: committed to its index and written to disk
    // and its block store — everything a real watcher-driven local change
    // would have already durably done — but note nothing here ever calls
    // any send/broadcast method on `session_a1`. This is the exact
    // "committed but never broadcast" state a crash immediately after the
    // DB commit would leave behind.
    let content = b"a change made just before the crash".to_vec();
    let hash_hex = device_a.store.put(&content).unwrap();
    std::fs::write(device_a.root.path().join("new-file.txt"), &content).unwrap();
    device_a
        .state
        .upsert_file(GROUP, &record_with_content("new-file.txt", &content, &hash_hex))
        .unwrap();

    // Confirm the peer genuinely never received it pre-crash (the
    // baseline this test would otherwise be trivially true against).
    assert!(
        device_b.state.get_file(GROUP, "new-file.txt").unwrap().is_none(),
        "sanity check: peer must not already have the file before the crash"
    );

    // --- simulate the crash: abort both sessions' tasks and drop their
    // transport, exactly as a killed daemon process would drop every
    // in-memory connection while leaving `device_a`/`device_b`'s SyncState
    // and block store (their on-disk, persisted state) untouched. ---
    handle_a1.abort();
    handle_b1.abort();
    drop(session_a1);
    drop(session_b1);
    drop(chan_a1);
    drop(chan_b1);

    // --- simulate the restart: a fresh session pair for the same two
    // persistent device identities, as `yadorilink-daemon::main` would
    // build on the next process start (new `PeerSyncSession`s wrapping
    // the same, restart-surviving `SyncState`/`FsBlockStore`). ---
    let (chan_a2, chan_b2) = connect_pair(relay_addr).await;
    let (_session_a2, _handle_a2) = spawn_session(chan_a2, &device_a, "device-b");
    let (_session_b2, _handle_b2) = spawn_session(chan_b2, &device_b, "device-a");

    // The reconnect's own initial full-index send must deliver the
    // pre-crash change with no separate persisted retry queue involved.
    // Waits for the fully-reconciled record specifically (not just any
    // row's existence) — an incoming file can transiently pass through an
    // intermediate bootstrap-only row (see `SyncState::
    // ensure_bootstrap_row_for_metadata`'s doc comment) before the real
    // content upsert lands a moment later.
    wait_until(
        || {
            device_b
                .state
                .get_file(GROUP, "new-file.txt")
                .unwrap()
                .is_some_and(|r| r.size == content.len() as u64)
        },
        std::time::Duration::from_secs(5),
    )
    .await;

    let received = device_b.state.get_file(GROUP, "new-file.txt").unwrap().unwrap();
    assert_eq!(received.size, content.len() as u64);
    assert_eq!(hex::encode(&received.blocks[0].hash), hash_hex);
}
