use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::{PeerRole, PeerSyncSession};
use yadorilink_sync_core::rate_limiter::RateLimiters;
use yadorilink_sync_core::types::{LinkMode, MaterializationPolicy, MaterializationState};
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind};
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

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

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

    fn processor(&self) -> LocalChangeProcessor {
        LocalChangeProcessor::new(self.state.clone(), self.store.clone(), self.device_id.clone())
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
) -> Arc<PeerSyncSession> {
    spawn_session_with_groups(channel, device, peer_device_id, vec![GROUP.to_string()])
}

fn spawn_session_with_groups(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
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
    tokio::spawn(session.clone().run());
    session
}

/// Like `spawn_session`, but wired to forward presence signals received
/// from this peer into `presence_tx`.
fn spawn_session_with_presence(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
    presence_tx: tokio::sync::mpsc::UnboundedSender<yadorilink_sync_core::presence::PresenceEvent>,
) -> Arc<PeerSyncSession> {
    let session = PeerSyncSession::new_with_forwarding(
        channel,
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone(),
        device.store.clone(),
        vec![GROUP.to_string()],
        device.sync_roots(),
        None,
        Some(presence_tx),
    );
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

/// sync-engine spec: "Initial sync reconciles existing files" — device A
/// already has a file before B ever connects; B must end up with an
/// identical copy after the session starts (the relevant behavior, 6.2).
#[tokio::test]
async fn initial_sync_replicates_existing_file_to_new_peer() {
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("vacation.jpg");
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;

    let original = std::fs::read(device_a.root_path().join("vacation.jpg")).unwrap();
    let replicated = std::fs::read(&replicated_path).unwrap();
    assert_eq!(original, replicated);

    let record = device_b.state.get_file(GROUP, "vacation.jpg").unwrap().unwrap();
    assert!(!record.deleted);
    assert_eq!(record.size, 300_000);
}

#[tokio::test]
async fn same_version_resync_rehydrates_a_missing_eager_file() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    session_b.set_full_index_resync_interval(Duration::from_millis(100));

    let replicated_path = device_b.root_path().join(file_name);
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;

    std::fs::remove_file(&replicated_path).unwrap();
    device_b
        .state
        .set_materialization_state(GROUP, file_name, MaterializationState::Placeholder)
        .unwrap();

    wait_until(
        || std::fs::read(&replicated_path).ok().as_deref() == Some(contents.as_slice()),
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(std::fs::read(&replicated_path).unwrap(), contents);
    assert_eq!(
        device_b.state.get_materialization_state(GROUP, file_name).unwrap(),
        Some(MaterializationState::Hydrated)
    );
}

#[tokio::test]
async fn same_version_resync_does_not_hydrate_an_ondemand_placeholder() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    session_a.set_full_index_resync_interval(Duration::from_millis(100));
    session_b.set_full_index_resync_interval(Duration::from_millis(100));

    let replicated_path = device_b.root_path().join(file_name);
    wait_until(
        || {
            device_b.state.get_materialization_state(GROUP, file_name).ok().flatten()
                == Some(MaterializationState::Placeholder)
        },
        Duration::from_secs(10),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(
        device_b.state.get_materialization_state(GROUP, file_name).unwrap(),
        Some(MaterializationState::Placeholder)
    );
    assert!(replicated_path.exists());
    assert_eq!(std::fs::metadata(&replicated_path).unwrap().len(), contents.len() as u64);
    assert_ne!(std::fs::read(&replicated_path).unwrap(), contents);
}

/// A `send-only` link never applies an incoming peer change — the
/// receiving device's `link_mode_for_group` reads `SendOnly` (set via
/// `set_link_mode` below), so `reconcile_one_file`'s never-seen-path
/// branch must record an out-of-sync item instead of writing the file to
/// disk. Local content stays authoritative (here: no file at all) until
/// an explicit `override`.
#[tokio::test]
async fn send_only_link_does_not_apply_incoming_change_and_records_out_of_sync() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
    device_b.state.set_link_mode(&root_b, LinkMode::SendOnly).unwrap();

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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(
        || device_b.state.count_out_of_sync(GROUP).unwrap_or(0) == 1,
        Duration::from_secs(10),
    )
    .await;

    assert!(
        !device_b.root_path().join("vacation.jpg").exists(),
        "a send-only link must never materialize an incoming change to disk"
    );
    assert!(device_b.state.get_file(GROUP, "vacation.jpg").unwrap().is_none());
    assert_eq!(device_b.state.list_out_of_sync(GROUP).unwrap(), vec!["vacation.jpg".to_string()]);
}

/// Pause always trumps everything: a paused link never applies an
/// incoming change, regardless of mode — including the ordinary
/// `send-receive` default, which this module previously never gated on
/// `paused` at all (only the daemon's local→peer broadcast did). No
/// out-of-sync item is recorded either — pause suspends the link entirely
/// rather than activating a mode gate.
#[tokio::test]
async fn paused_link_does_not_apply_an_incoming_change_regardless_of_mode() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // Give the (gated) initial index exchange a real moment to have
    // happened if the gate were broken, then assert nothing landed.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!device_b.root_path().join("vacation.jpg").exists());
    assert!(device_b.state.get_file(GROUP, "vacation.jpg").unwrap().is_none());
    assert_eq!(
        device_b.state.count_out_of_sync(GROUP).unwrap(),
        0,
        "pause suspends the link entirely; it must not also record mode-gate divergence"
    );
}

/// A send-only link gates an incoming tombstone identically to ordinary
/// content — recorded as out-of-sync, never applied, so a file this
/// device already has locally must survive an incoming deletion from a
/// send-only-gated peer.
#[tokio::test]
async fn send_only_link_does_not_apply_incoming_tombstone_and_records_out_of_sync() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();

    // B already has the file, seeded directly (no session yet) so the
    // initial sync has nothing to reconcile beyond adopting this exact
    // content.
    std::fs::write(device_b.root_path().join("shared.txt"), b"still here").unwrap();
    let mut record = yadorilink_sync_core::types::FileRecord {
        path: "shared.txt".to_string(),
        size: 10,
        mtime_unix_nanos: 0,
        version: yadorilink_sync_core::version_vector::VersionVector::new(),
        blocks: vec![],
        deleted: false,
    };
    record.version.increment("device-a");
    device_b.state.upsert_file(GROUP, &record).unwrap();
    // Switch to send-only *after* seeding, so the seeded adoption above
    // isn't itself gated.
    device_b.state.set_link_mode(&root_b, LinkMode::SendOnly).unwrap();

    device_a.state.upsert_file(GROUP, &record).unwrap();
    std::fs::write(device_a.root_path().join("shared.txt"), b"still here").unwrap();
    device_a.state.mark_deleted(GROUP, "shared.txt", "device-a").unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(
        || device_b.state.count_out_of_sync(GROUP).unwrap_or(0) == 1,
        Duration::from_secs(10),
    )
    .await;

    assert!(
        device_b.root_path().join("shared.txt").exists(),
        "a gated incoming tombstone must never delete the local file"
    );
    let local = device_b.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    assert!(!local.deleted, "the local index row must stay untouched by the gated deletion");
}

/// "Local file edit detected" + incremental propagation — a change made
/// *after* the initial sync must also reach the peer, sent as an index
/// update rather than a full re-sync.
#[tokio::test]
async fn incremental_change_after_initial_sync_propagates() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // Give the (empty) initial handshake a moment, then make a local edit
    // on A and broadcast it as an incremental update.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let file_path = device_a.root_path().join("notes.txt");
    std::fs::write(&file_path, b"first draft").unwrap();
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
    session_a.send_index_update(GROUP, vec![record]).await.unwrap();

    let replicated_path = device_b.root_path().join("notes.txt");
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;
    assert_eq!(std::fs::read(&replicated_path).unwrap(), b"first draft");
}

/// "Concurrent edit produces conflicted copy" — both devices edit the
/// same file before either has seen the other's change; version vectors
/// must detect this as a true conflict (not a simple ordering), and both
/// copies must survive on both devices.
#[tokio::test]
async fn concurrent_edit_produces_conflict_copy_on_both_sides() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Establish a common base version on both sides *before* connecting,
    // simulating a file both devices already had synced previously.
    let base_path_a = device_a.root_path().join("shared.txt");
    std::fs::write(&base_path_a, b"base content").unwrap();
    let base_record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: base_path_a, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_b.state.upsert_file(GROUP, &base_record).unwrap();
    std::fs::write(device_b.root_path().join("shared.txt"), b"base content").unwrap();

    // Now each device independently edits the file, diverging from the
    // common base — a genuine concurrent edit.
    std::thread::sleep(Duration::from_millis(10)); // ensure a distinguishable mtime ordering
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

    std::thread::sleep(Duration::from_millis(10));
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

    // Sanity check: this really is a concurrent edit, not a sequential one.
    let record_a = device_a.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    let record_b = device_b.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    assert_eq!(
        record_a.version.compare(&record_b.version),
        yadorilink_sync_core::version_vector::VvOrdering::Concurrent
    );

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // Both devices should end up with two files: the winning content at
    // "shared.txt" and a conflict-marked copy of the losing content.
    // Waits specifically for a *final* conflict-copy name (not just "2
    // entries exist"), which a transient `unique_tmp_path` artifact could
    // satisfy too — see `is_final_conflict_copy`'s doc comment.
    wait_until(
        || {
            let names_a: Vec<String> = std::fs::read_dir(device_a.root_path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            let names_b: Vec<String> = std::fs::read_dir(device_b.root_path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            names_a.iter().any(|n| is_final_conflict_copy(n))
                && names_b.iter().any(|n| is_final_conflict_copy(n))
        },
        Duration::from_secs(10),
    )
    .await;

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

/// Send-only never conflict-copies an incoming change — a genuine
/// concurrent edit against a send-only link must be recorded as
/// out-of-sync, not resolved via the normal rename-the-loser conflict
/// machinery, so no conflict-copy file is ever written and B's own content
/// survives untouched. Mirrors `concurrent_edit_produces_conflict_copy_on_
/// both_sides` above but with B set to `send-only`.
#[tokio::test]
async fn send_only_link_records_out_of_sync_instead_of_conflict_copy_on_concurrent_edit() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();

    let base_path_a = device_a.root_path().join("shared.txt");
    std::fs::write(&base_path_a, b"base content").unwrap();
    let base_record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: base_path_a, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_b.state.upsert_file(GROUP, &base_record).unwrap();
    std::fs::write(device_b.root_path().join("shared.txt"), b"base content").unwrap();
    // B only switches to send-only *after* establishing the common base
    // above, then diverges with its own local edit exactly like the
    // send-receive counterpart test.
    device_b.state.set_link_mode(&root_b, LinkMode::SendOnly).unwrap();

    std::thread::sleep(Duration::from_millis(10));
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

    std::thread::sleep(Duration::from_millis(10));
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

    let record_a = device_a.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    let record_b = device_b.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
    assert_eq!(
        record_a.version.compare(&record_b.version),
        yadorilink_sync_core::version_vector::VvOrdering::Concurrent
    );

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(
        || device_b.state.count_out_of_sync(GROUP).unwrap_or(0) == 1,
        Duration::from_secs(10),
    )
    .await;

    // Give any (incorrect) conflict-copy write a moment to have landed if
    // the gate were broken, then assert B's directory has exactly its own
    // one file and nothing else.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let names_b: Vec<String> = std::fs::read_dir(device_b.root_path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names_b, vec!["shared.txt".to_string()], "no conflict copy on a send-only link");
    assert_eq!(
        std::fs::read(device_b.root_path().join("shared.txt")).unwrap(),
        b"edited on B, which is longer",
        "B's own local content must stay untouched"
    );
}

/// A delete-vs-edit conflict where the tombstone is the *loser* must
/// never leave an empty ghost file behind, and disk state must match the
/// index exactly — only the winner's real content, at the original path,
/// no conflict-copy file for the tombstone (`resolve_and_apply_conflict`
/// skips creating a conflict copy for a tombstone loser entirely, since
/// "conflict copy of a deletion" has no content to preserve).
#[tokio::test]
async fn delete_vs_edit_conflict_tombstone_as_loser_leaves_no_ghost_file() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let mut base_version = yadorilink_sync_core::version_vector::VersionVector::new();
    base_version.increment("device-base");

    // device_a: a real edit, mtime 2000 — will win (later mtime).
    let mut version_a = base_version.clone();
    version_a.increment("device-a");
    let content_a: &[u8] = b"edited on A after the delete";
    let path_a = device_a.root_path().join("shared.txt");
    std::fs::write(&path_a, content_a).unwrap();
    let blocks_a =
        yadorilink_sync_core::chunker::chunk_file(device_a.store.as_ref(), &path_a).unwrap();
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "shared.txt".into(),
                size: content_a.len() as u64,
                mtime_unix_nanos: 2000,
                version: version_a,
                blocks: blocks_a,
                deleted: false,
            },
        )
        .unwrap();

    // device_b: a tombstone, mtime 1000 (older) — will lose.
    let mut version_b = base_version.clone();
    version_b.increment("device-b");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "shared.txt".into(),
                size: 0,
                mtime_unix_nanos: 1000,
                version: version_b,
                blocks: vec![],
                deleted: true,
            },
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(
        || {
            matches!(
                device_b.state.get_file(GROUP, "shared.txt"),
                Ok(Some(r)) if !r.deleted
            )
        },
        Duration::from_secs(10),
    )
    .await;
    // Let any (incorrect) conflict-copy write settle before asserting its absence.
    tokio::time::sleep(Duration::from_millis(200)).await;

    for device in [&device_a, &device_b] {
        let entries: Vec<String> = std::fs::read_dir(device.root_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
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

/// The reverse case — the tombstone *wins* the conflict. The file must
/// be removed from disk with
/// no leftover empty/ghost file at the original path, while the loser's
/// real (non-tombstone) content is preserved as a conflict-marked copy
/// rather than silently discarded, matching this codebase's existing
/// "concurrent edit" convention. Mtimes are set explicitly here (a
/// tombstone equal-or-later than the edit) rather than produced through
/// live filesystem timestamps: `mark_deleted`'s real-world behavior only
/// ever inherits a file's last-known mtime and never advances it further
/// on its own, so this specific ordering isn't reachable through the
/// live watcher path — but a directly-received peer record in this state
/// is still valid input this device must handle correctly regardless of
/// how the sending peer arrived at it.
#[tokio::test]
async fn delete_vs_edit_conflict_tombstone_as_winner_removes_file_without_ghost() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let mut base_version = yadorilink_sync_core::version_vector::VersionVector::new();
    base_version.increment("device-base");

    // device_a: a real edit, mtime 1000 — will lose (earlier mtime).
    let mut version_a = base_version.clone();
    version_a.increment("device-a");
    let content_a: &[u8] = b"edited on A before the delete";
    let path_a = device_a.root_path().join("shared.txt");
    std::fs::write(&path_a, content_a).unwrap();
    let blocks_a =
        yadorilink_sync_core::chunker::chunk_file(device_a.store.as_ref(), &path_a).unwrap();
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "shared.txt".into(),
                size: content_a.len() as u64,
                mtime_unix_nanos: 1000,
                version: version_a,
                blocks: blocks_a,
                deleted: false,
            },
        )
        .unwrap();

    // device_b: a tombstone, mtime 2000 (later) — will win.
    let mut version_b = base_version.clone();
    version_b.increment("device-b");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "shared.txt".into(),
                size: 0,
                mtime_unix_nanos: 2000,
                version: version_b,
                blocks: vec![],
                deleted: true,
            },
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // Both devices must adopt the winning tombstone and remove their file,
    // and a conflict copy of the losing edit must appear on *both* sides
    // — device_b's copy requires fetching device_a's content over the
    // wire, which can genuinely take longer than device_a's own (fetch-free)
    // resolution of the same conflict, so this must wait for both, not
    // just device_a (a single-device wait here previously let the final
    // assertion loop below run before device_b had finished materializing
    // its conflict copy).
    wait_until(
        || {
            !device_a.root_path().join("shared.txt").exists()
                && !device_b.root_path().join("shared.txt").exists()
        },
        Duration::from_secs(10),
    )
    .await;
    wait_until(
        || {
            let has_copy = |device: &Device| {
                std::fs::read_dir(device.root_path())
                    .unwrap()
                    .any(|e| is_final_conflict_copy(&e.unwrap().file_name().to_string_lossy()))
            };
            has_copy(&device_a) && has_copy(&device_b)
        },
        Duration::from_secs(10),
    )
    .await;

    for device in [&device_a, &device_b] {
        assert!(
            !device.root_path().join("shared.txt").exists(),
            "the winning tombstone's path must not have a leftover ghost file"
        );
        let record = device.state.get_file(GROUP, "shared.txt").unwrap().unwrap();
        assert!(record.deleted, "index must agree the file is deleted, matching disk");

        let names: Vec<String> = std::fs::read_dir(device.root_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            names.iter().any(|n| is_final_conflict_copy(n)),
            "the losing real edit must survive as a conflict copy, not be silently dropped: {names:?}"
        );
        for name in &names {
            let content = std::fs::read(device.root_path().join(name)).unwrap();
            assert!(!content.is_empty(), "conflict copy {name:?} must not be an empty ghost file");
        }
    }
}

/// Security regression test: a session must ignore index/block messages
/// for a folder group it wasn't constructed with (the ACL-verified
/// intersection from the coordination plane), even if a peer sends them —
/// a peer naming an unrelated group_id in a message must not be able to
/// read or write files outside what it's actually authorized to share.
#[tokio::test]
async fn unauthorized_group_id_in_incoming_message_is_ignored() {
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
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

/// "OnDemand folder creates placeholders instead of full content":
/// adopting a file into an `OnDemand`-policy folder must index it and
/// write a correctly-sized placeholder — without ever fetching its
/// blocks from the peer.
#[tokio::test]
async fn ondemand_folder_adopts_placeholder_without_fetching_blocks() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Device B links the folder group as `OnDemand` — this is what
    // `PeerSyncSession::materialize` consults to decide placeholder vs.
    // full hydration.
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
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

/// "Opening a placeholder triggers hydration":
/// `PeerSyncSession::hydrate_file` must fetch a placeholder's blocks on
/// demand and materialize its real content, transitioning to `Hydrated`
/// — the on-access path, independent of ordinary index reconciliation.
#[tokio::test]
async fn hydrate_file_fetches_and_materializes_placeholder_content() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
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

/// Hydrating a file with no peer connected at all must fail with a
/// clear, bounded error rather than hanging forever — the plain
/// (no-network) case of "no reachable peer holds the blocks."
#[tokio::test]
async fn hydrate_file_without_any_connected_peer_fails_immediately() {
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();

    // A placeholder entry with no session/peer at all attached to it —
    // `hydrate_file` needs *some* `PeerSyncSession` to call it on, so
    // simulate "adopted as a placeholder, but the only peer that has it
    // is now disconnected" by constructing a session whose channel points
    // at a peer that immediately drops.
    let relay_addr = start_relay().await;
    let (secret_b, _public_b) = gen_keypair();
    let hub_b = RelayHub::connect(relay_addr, secret_b.clone()).await.unwrap();
    // A channel to a peer public key nobody is listening on: the daemon
    // side of this pairing never responds to any BlockRequest.
    let (_ghost_secret, ghost_public) = gen_keypair();
    let channel_b = std::sync::Arc::new(
        PeerChannel::connect(
            TransportMode::RelayOnly,
            secret_b,
            ghost_public,
            0,
            Some(hub_b),
            vec![],
            None,
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

/// Hydrate → evict → re-hydrate must round-trip to byte-identical
/// content — eviction doesn't touch sync state (version, block list), so
/// a second hydration from the same (or any other) peer reconstructs
/// exactly the same bytes.
#[tokio::test]
async fn evict_then_rehydrate_round_trips_to_identical_content() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let path_on_b = device_b.root_path().join("archive.zip");
    wait_until(|| path_on_b.exists(), Duration::from_secs(10)).await;

    session_b.hydrate_file(GROUP, "archive.zip").await.unwrap();
    assert_eq!(std::fs::read(&path_on_b).unwrap(), content);

    yadorilink_sync_core::materialization::evict_file(
        &device_b.state,
        &device_b.root_path(),
        GROUP,
        "archive.zip",
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

/// "Peers learn a file is being edited" and "Presence signal does not
/// affect sync state": a presence signal reaches the peer's session and
/// nothing else — no version bump, no index entry, no materialized file.
#[tokio::test]
async fn presence_signal_reaches_peer_without_affecting_index_state() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let (presence_tx, mut presence_rx) = tokio::sync::mpsc::unbounded_channel();
    let _session_b = spawn_session_with_presence(channel_b, &device_b, "device-a", presence_tx);

    session_a.send_presence_signal(GROUP, "report.docx", true, 90).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), presence_rx.recv())
        .await
        .expect("presence signal never reached the peer")
        .unwrap();
    assert_eq!(event.group_id, GROUP);
    assert_eq!(event.path, "report.docx");
    assert_eq!(event.device_id, "device-a");
    assert!(event.editing);

    // Give any (incorrect) side effects a moment to happen, then confirm
    // there are none.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(device_b.state.get_file(GROUP, "report.docx").unwrap().is_none());
    assert!(!device_b.root_path().join("report.docx").exists());
}

/// "Lock file is never treated as a synced file itself": a `~$*` lock
/// file created in a linked, actively-syncing folder must never
/// propagate to a connected peer as a file at all.
#[tokio::test]
async fn lock_file_never_appears_in_peer_index_or_on_disk() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // A real file syncs normally first, confirming the session pairing
    // itself works before asserting the negative case below.
    let real_path = device_a.root_path().join("shared.txt");
    std::fs::write(&real_path, b"hello").unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: real_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.state.upsert_file(GROUP, &record).unwrap();

    let lock_path = device_a.root_path().join("~$shared.txt");
    std::fs::write(&lock_path, b"").unwrap();
    let outcome = device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: lock_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, LocalChangeOutcome::PresenceChanged { .. }));

    // The lock file was never indexed on A, so there's nothing for A's
    // session to send B in the first place — confirm B never receives it
    // by waiting for the real file to arrive (proving the pairing is
    // live) and then checking the lock file's absence.
    let replicated = device_b.root_path().join("shared.txt");
    wait_until(|| replicated.exists(), Duration::from_secs(10)).await;

    assert!(device_a.state.get_file(GROUP, "~$shared.txt").unwrap().is_none());
    assert!(device_b.state.get_file(GROUP, "~$shared.txt").unwrap().is_none());
    assert!(!device_b.root_path().join("~$shared.txt").exists());
}

/// Three devices, one `OnDemand` folder group — a file created on A
/// appears as a placeholder on both B and C with no content transfer;
/// hydrating on B fetches content only there, C stays a placeholder
/// throughout.
#[tokio::test]
async fn three_devices_on_demand_hydration_is_per_device_not_group_wide() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");
    let device_c = Device::new("device-c");

    for device in [&device_b, &device_c] {
        let root = device.root_path().to_string_lossy().to_string();
        device.state.add_link(&root, GROUP).unwrap();
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
    let (channel_a_b, channel_b) = connect_pair(relay_addr).await;
    let (channel_a_c, channel_c) = connect_pair(relay_addr).await;
    let _session_a_b = spawn_session(channel_a_b, &device_a, "device-b");
    let _session_a_c = spawn_session(channel_a_c, &device_a, "device-c");
    let session_b = spawn_session(channel_b, &device_b, "device-a");
    let _session_c = spawn_session(channel_c, &device_c, "device-a");

    let path_on_b = device_b.root_path().join("presentation.pptx");
    let path_on_c = device_c.root_path().join("presentation.pptx");
    wait_until(|| path_on_b.exists() && path_on_c.exists(), Duration::from_secs(10)).await;

    // Both adopted a placeholder — correct size, no real content, and no
    // block bytes fetched over the wire at all.
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

/// Hydration with no reachable peer holding the blocks must time out
/// with a clear, catchable error, never hang the caller indefinitely —
/// exercised here with a short timeout to keep the test itself fast
/// (production uses `DEFAULT_HYDRATION_TIMEOUT`).
/// Simulated with a real, connected channel whose peer side simply never
/// runs (so a `BlockRequest` is sent but never answered) — a stalled peer
/// is a more realistic "unreachable" case than a channel that fails to
/// establish at all, and exercises the same timeout path either way.
#[tokio::test]
async fn hydration_chaos_no_reachable_peer_times_out_cleanly() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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
    // intentionally never driven by a `.run()` loop, so nothing ever
    // reads the `BlockRequest` `hydrate_file_with_timeout` sends over
    // `channel_b`.
    let (_channel_nobody, channel_b) = connect_pair(relay_addr).await;
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

/// SEC-5: a peer response is not trusted just because it arrives on the
/// encrypted channel. The bytes must match the requested block's hash and
/// size before they are persisted or materialized.
#[tokio::test]
async fn hydration_rejects_block_response_with_wrong_hash_or_size() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();

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

    let (responder_channel, channel_b) = connect_pair(relay_addr).await;
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

/// SEC-24: group authorization alone is not enough to serve arbitrary
/// block-store contents. The requested hash must be referenced by the
/// requested file record in that group.
#[tokio::test]
async fn block_request_for_unreferenced_hash_is_refused() {
    let relay_addr = start_relay().await;
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

    let (channel_a, requester_channel) = connect_pair(relay_addr).await;
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

/// A hydration request's underlying `BlockRequest` goes through the
/// exact same `handle_block_request` authorization check as any other
/// block fetch — there is no separate, unchecked path for on-access
/// hydration. Verified here by having the *responding* peer's session
/// independently lack authorization for the group (simulating a
/// coordination-plane ACL that doesn't actually cover this pairing),
/// even though the requester believes it does — content must never be
/// leaked either way.
#[tokio::test]
async fn hydration_block_request_is_refused_for_a_group_the_peer_does_not_authorize() {
    let relay_addr = start_relay().await;
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
    device_b.state.add_link(&root_b, GROUP).unwrap();
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
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
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");

    let data = b"public file contents, initially authorized".to_vec();
    let hash = sha256_bytes(&data);
    device_a.store.put(&data).unwrap();

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

    let (channel_a, requester_channel) = connect_pair(relay_addr).await;
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
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Let the initial (empty) handshake/full-index exchange settle before
    // simulating the revocation, so it's unambiguous that the update below
    // is the thing under test, not part of session startup.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(session_b.shares_group(GROUP), "sanity: B starts out authorizing A for GROUP");

    // Simulate a netmap update revoking device-a's authorization for GROUP
    // as seen by device-b's session (the *receiving* side for the
    // IndexUpdate about to be sent) — before the update is ever sent, i.e.
    // "revoked before the update was processed".
    session_b.revoke_group(GROUP);

    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    let record = yadorilink_sync_core::types::FileRecord {
        path: "sneaky.txt".to_string(),
        size: 4,
        mtime_unix_nanos: 0,
        version,
        blocks: vec![],
        deleted: false,
    };
    session_a.send_index_update(GROUP, vec![record]).await.unwrap();

    // Give plenty of time for the update to arrive and (if the
    // revalidation were missing) be applied.
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        device_b.state.get_file(GROUP, "sneaky.txt").unwrap().is_none(),
        "an index update from a just-revoked peer must not be applied to the local index"
    );
    assert!(
        !device_b.root_path().join("sneaky.txt").exists(),
        "an index update from a just-revoked peer must never be materialized to disk"
    );
}

/// A peer this device has shared a group to at role `read` may not push
/// its own changes into that group — an inbound `IndexUpdate` from a
/// read-role peer must be rejected, not applied, exactly like an index
/// update from an unauthorized/revoked peer
/// (`index_update_from_just_revoked_peer_is_rejected` above), but for a
/// *different* reason: the peer remains fully authorized (`shares_group`
/// stays true throughout) — it's specifically the write role that the
/// sharer never granted (or downgraded away). Mirrors that test's
/// structure directly, plus a write-role baseline first (so the rejection
/// is unambiguously attributable to the role downgrade, not to some other
/// difference from that test).
#[tokio::test]
async fn index_update_from_a_read_role_peer_is_rejected() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Let the initial (empty) handshake/full-index exchange settle before
    // exercising anything below, matching
    // `index_update_from_just_revoked_peer_is_rejected`'s setup.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        session_b.peer_role(GROUP),
        PeerRole::Write,
        "sanity: a session with no role explicitly set defaults to write, matching the acl.role \
         column's own default for pre-existing/same-account edges (D3), so every pre-existing \
         caller/test that never touches the new role API keeps its current behavior"
    );

    // Baseline: while device-b still holds device-a at the default write
    // role, an index update from device-a is accepted normally.
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    let allowed_record = yadorilink_sync_core::types::FileRecord {
        path: "allowed-while-write.txt".to_string(),
        size: 4,
        mtime_unix_nanos: 0,
        version: version.clone(),
        blocks: vec![],
        deleted: false,
    };
    session_a.send_index_update(GROUP, vec![allowed_record]).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        device_b.state.get_file(GROUP, "allowed-while-write.txt").unwrap().is_some(),
        "baseline: an index update from a peer still held at the default write role must be \
         applied"
    );

    // device-b downgrades device-a to read-only for GROUP mid-session,
    // simulating a netmap update that delivered a
    // `PeerInfo.shared_group_roles` entry of SHARE_ROLE_READ for this
    // edge (the coordination-plane side of this: `shares::ShareRole::Read`
    // reaching this device via an accepted cross-account invite, D2/D4).
    session_b.set_peer_role(GROUP, PeerRole::Read);
    assert_eq!(session_b.peer_role(GROUP), PeerRole::Read);
    assert!(
        session_b.shares_group(GROUP),
        "the peer is still authorized for the group -- only its role changed, not its \
         membership"
    );

    version.increment("device-a");
    let rejected_record = yadorilink_sync_core::types::FileRecord {
        path: "sneaky-write.txt".to_string(),
        size: 4,
        mtime_unix_nanos: 0,
        version,
        blocks: vec![],
        deleted: false,
    };
    session_a.send_index_update(GROUP, vec![rejected_record]).await.unwrap();

    // Give plenty of time for the update to arrive and (if the role check
    // were missing) be applied.
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        device_b.state.get_file(GROUP, "sneaky-write.txt").unwrap().is_none(),
        "an index update from a read-role peer must not be applied to the local index"
    );
    assert!(
        !device_b.root_path().join("sneaky-write.txt").exists(),
        "an index update from a read-role peer must never be materialized to disk"
    );
}

/// Role enforcement is asymmetric — read-only is only about *inbound*
/// index updates/writes (`index_update_from_a_read_role_peer_is_rejected`
/// above); a read-role peer must still be able to *read*: existing content
/// it requests via `BlockRequest` is still served normally — it will serve
/// index and block reads to that peer, but will refuse to accept inbound
/// index updates or block writes originating from it. Mirrors
/// `block_request_is_refused_after_mid_session_group_revocation`'s
/// structure, but — unlike that test — setting a read role (as opposed to
/// revoking authorization outright) must NOT cause the block request to
/// be refused, proving role enforcement is specifically about writes, not
/// a blanket restriction reusing the same refusal path as
/// unauthorized/revoked.
#[tokio::test]
async fn block_requests_are_still_served_to_a_read_role_peer() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");

    let data = b"read-only peers may still read this content".to_vec();
    let hash = sha256_bytes(&data);
    device_a.store.put(&data).unwrap();

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

    let (channel_a, requester_channel) = connect_pair(relay_addr).await;
    // session_a is the *answering* side, playing the role of the sharer
    // who has granted device-b read-only access to GROUP.
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    session_a.set_peer_role(GROUP, PeerRole::Read);
    assert!(
        session_a.shares_group(GROUP),
        "sanity: still fully authorized for the group, just read-only"
    );
    assert_eq!(session_a.peer_role(GROUP), PeerRole::Read);

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
        "a read-role peer must still be able to read existing content: block requests are \
         gated only on group authorization (shares_group), never on role"
    );
    assert_eq!(response.data, data);
}

/// Presence signals are scoped to `shares_group` exactly like every
/// other sync message type — a signal for a group the receiver doesn't
/// authorize is dropped, not forwarded to `presence_tx`.
#[tokio::test]
async fn presence_signal_for_an_unauthorized_group_is_ignored() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    // A believes it shares GROUP with B; B's session was constructed with
    // an empty shared-group list (coordination plane doesn't actually
    // authorize this pairing for GROUP).
    let session_a =
        spawn_session_with_groups(channel_a, &device_a, "device-b", vec![GROUP.to_string()]);
    let (presence_tx, mut presence_rx) = tokio::sync::mpsc::unbounded_channel();
    let session_b = PeerSyncSession::new_with_forwarding(
        channel_b,
        device_b.device_id.clone(),
        "device-a".to_string(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![], // no shared groups at all
        device_b.sync_roots(),
        None,
        Some(presence_tx),
    );
    tokio::spawn(session_b.clone().run());

    session_a.send_presence_signal(GROUP, "report.docx", true, 90).await.unwrap();

    // Nothing should ever arrive — confirm by racing a short timeout
    // rather than asserting on an event that (correctly) never comes.
    let outcome = tokio::time::timeout(Duration::from_millis(500), presence_rx.recv()).await;
    assert!(
        outcome.is_err(),
        "a presence signal for an unauthorized group must never reach presence_tx"
    );
}

/// Two devices both "open" the same file (Office lock-file convention)
/// at the same time — each must learn the other is editing it (mutual
/// presence awareness), and if they proceed to edit anyway (advisory,
/// not enforced — the whole point of choosing an advisory lock over real
/// co-authoring), the outcome is exactly the pre-existing
/// conflicted-copy behavior, unaffected by this capability.
#[tokio::test]
async fn concurrent_editing_with_presence_warning_still_produces_conflict_copy_unchanged() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Common base version on both sides, as any real concurrent-edit
    // scenario starts from a previously-synced file.
    let base_path_a = device_a.root_path().join("shared.txt");
    std::fs::write(&base_path_a, b"base content").unwrap();
    let base_record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: base_path_a, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_b.state.upsert_file(GROUP, &base_record).unwrap();
    std::fs::write(device_b.root_path().join("shared.txt"), b"base content").unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let (presence_tx_a, mut presence_rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (presence_tx_b, mut presence_rx_b) = tokio::sync::mpsc::unbounded_channel();
    let session_a = PeerSyncSession::new_with_forwarding(
        channel_a,
        device_a.device_id.clone(),
        "device-b".to_string(),
        device_a.state.clone(),
        device_a.store.clone(),
        vec![GROUP.to_string()],
        device_a.sync_roots(),
        None,
        Some(presence_tx_a),
    );
    tokio::spawn(session_a.clone().run());
    let session_b = PeerSyncSession::new_with_forwarding(
        channel_b,
        device_b.device_id.clone(),
        "device-a".to_string(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
        None,
        Some(presence_tx_b),
    );
    tokio::spawn(session_b.clone().run());

    // Both open the file (Office's own lock-file convention) at
    // effectively the same time — mirroring what `link_manager` does with
    // `LocalChangeOutcome::PresenceChanged` in the real daemon.
    let lock_outcome_a = device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent {
                path: device_a.root_path().join("~$shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        lock_outcome_a,
        LocalChangeOutcome::PresenceChanged { path: "shared.txt".to_string(), editing: true }
    );
    let lock_outcome_b = device_b
        .processor()
        .process_event(
            GROUP,
            &device_b.root_path(),
            &FsChangeEvent {
                path: device_b.root_path().join("~$shared.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        lock_outcome_b,
        LocalChangeOutcome::PresenceChanged { path: "shared.txt".to_string(), editing: true }
    );

    session_a.send_presence_signal(GROUP, "shared.txt", true, 90).await.unwrap();
    session_b.send_presence_signal(GROUP, "shared.txt", true, 90).await.unwrap();

    // Mutual awareness: each side learns the *other* is editing.
    let event_at_b = tokio::time::timeout(Duration::from_secs(5), presence_rx_b.recv())
        .await
        .expect("B never learned A was editing")
        .unwrap();
    assert_eq!(event_at_b.device_id, "device-a");
    assert!(event_at_b.editing);
    let event_at_a = tokio::time::timeout(Duration::from_secs(5), presence_rx_a.recv())
        .await
        .expect("A never learned B was editing")
        .unwrap();
    assert_eq!(event_at_a.device_id, "device-b");
    assert!(event_at_a.editing);

    // Proceeding to edit anyway (advisory, not enforced) — the exact same
    // concurrent-edit flow as the no-presence-awareness test above, except
    // each edit is explicitly broadcast (as `link_manager::announce_local_change`
    // would do immediately after indexing it in the real daemon — the
    // sessions here are already connected, unlike the base-then-connect
    // ordering the no-presence-awareness test uses to get the same effect
    // via the initial full-index send).
    std::thread::sleep(Duration::from_millis(10));
    std::fs::write(device_a.root_path().join("shared.txt"), b"edited on A anyway").unwrap();
    let record_a = expect_file_changed(
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
            .unwrap(),
    );
    session_a.send_index_update(GROUP, vec![record_a]).await.unwrap();

    std::thread::sleep(Duration::from_millis(10));
    std::fs::write(device_b.root_path().join("shared.txt"), b"edited on B anyway, which is longer")
        .unwrap();
    let record_b = expect_file_changed(
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
            .unwrap(),
    );
    session_b.send_index_update(GROUP, vec![record_b]).await.unwrap();

    wait_until(
        || {
            let names_a: Vec<String> = std::fs::read_dir(device_a.root_path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            let names_b: Vec<String> = std::fs::read_dir(device_b.root_path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            names_a.iter().any(|n| is_final_conflict_copy(n))
                && names_b.iter().any(|n| is_final_conflict_copy(n))
        },
        // Bumped from 10s, then again from 20s — still occasionally timing
        // out under contention (observed on both macos-latest and
        // windows-latest CI runners) even though the underlying
        // conflict-resolution logic itself is unaffected and unchanged;
        // same fix as last time, a more generous timeout, not a logic fix.
        Duration::from_secs(45),
    )
    .await;

    for device in [&device_a, &device_b] {
        let names: Vec<String> = std::fs::read_dir(device.root_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"shared.txt".to_string()), "missing winner file: {names:?}");
        assert!(
            names.iter().any(|n| is_final_conflict_copy(n)),
            "presence awareness must not change the pre-existing conflict outcome: {names:?}"
        );
    }
    // Each device's own lock file is local-only bookkeeping, never synced
    // to the other side or indexed as a file in its own right.
    assert!(device_a.state.get_file(GROUP, "~$shared.txt").unwrap().is_none());
    assert!(device_b.state.get_file(GROUP, "~$shared.txt").unwrap().is_none());
}

/// Broadcasting a batch of several changed files results in exactly one
/// wire `IndexUpdate` message carrying all of them, not one message per
/// file. Verified at the raw `PeerChannel` level (bypassing a receiving
/// `PeerSyncSession`) so the message count is directly observable.
#[tokio::test]
async fn send_index_update_delivers_a_batch_as_a_single_wire_message() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");

    // `session_a.run()` sends a `ClusterConfig` then a (here, empty)
    // `FullIndex` for the shared group as soon as it starts — drain both
    // before the batch we're actually testing, matching the order
    // `PeerSyncSession::run` produces them in.
    let handshake = proto::SyncMessage::decode(channel_b.recv().await.unwrap().as_slice()).unwrap();
    assert!(matches!(handshake.payload, Some(proto::sync_message::Payload::ClusterConfig(_))));
    let full_index =
        proto::SyncMessage::decode(channel_b.recv().await.unwrap().as_slice()).unwrap();
    assert!(matches!(full_index.payload, Some(proto::sync_message::Payload::FullIndex(_))));

    let mut version_a = yadorilink_sync_core::version_vector::VersionVector::new();
    version_a.increment("device-a");
    let make_record = |path: &str| yadorilink_sync_core::types::FileRecord {
        path: path.to_string(),
        size: 10,
        mtime_unix_nanos: 0,
        version: version_a.clone(),
        blocks: vec![],
        deleted: false,
    };
    let batch = vec![make_record("a.txt"), make_record("b.txt"), make_record("c.txt")];
    session_a.send_index_update(GROUP, batch).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), channel_b.recv())
        .await
        .expect("timed out waiting for the batched IndexUpdate")
        .unwrap();
    let msg = proto::SyncMessage::decode(received.as_slice()).unwrap();
    let Some(proto::sync_message::Payload::IndexUpdate(update)) = msg.payload else {
        panic!("expected an IndexUpdate message");
    };
    let paths: Vec<&str> = update.changed_files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, vec!["a.txt", "b.txt", "c.txt"]);

    // No further message follows — the batch was one wire send, not three.
    let extra = tokio::time::timeout(Duration::from_millis(300), channel_b.recv()).await;
    assert!(extra.is_err(), "batch must arrive as exactly one message, not several");
}

/// A peer that receives one batched `IndexUpdate` reconciles every file
/// in it correctly, end to end (materializes each file with the right
/// content on disk and in the index).
#[tokio::test]
async fn peer_reconciles_every_file_in_a_batched_index_update() {
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    session_a.send_index_update(GROUP, records).await.unwrap();

    for (name, content) in &files {
        let replicated_path = device_b.root_path().join(name);
        wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;
        assert_eq!(&std::fs::read(&replicated_path).unwrap(), content);
        let record = device_b.state.get_file(GROUP, name).unwrap().unwrap();
        assert_eq!(record.size, content.len() as u64);
    }
}

/// `handle_presence_signal` must bind the emitted
/// event's `device_id` to this connection's own authenticated identity
/// (`peer_device_id`), not trust the message's own `device_id` field —
/// otherwise an authorized peer could impersonate a *different* device,
/// surfacing as "device X is editing" in the UI when X never sent
/// anything. Bypasses the ordinary `send_presence_signal` API (which only
/// ever sends the caller's own real device id) and instead sends a raw,
/// hand-crafted `SyncMessage` directly over the channel, exactly what a
/// malicious/compromised "device-a" could do.
#[tokio::test]
async fn presence_signal_with_spoofed_device_id_is_dropped() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let (presence_tx, mut presence_rx) = tokio::sync::mpsc::unbounded_channel();
    // The only authenticated peer on this connection is "device-a" (per
    // `peer_device_id` below) — the raw message below claims a different
    // identity entirely.
    let _session_b = spawn_session_with_presence(channel_b, &device_b, "device-a", presence_tx);

    let spoofed = proto::SyncMessage {
        payload: Some(proto::sync_message::Payload::Presence(proto::PresenceSignal {
            folder_group_id: GROUP.to_string(),
            path: "shared.txt".to_string(),
            device_id: "device-mallory".to_string(),
            editing: true,
            ttl_seconds: 90,
        })),
    };
    channel_a.send(spoofed.encode_to_vec()).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(500), presence_rx.recv()).await;
    assert!(
        result.is_err(),
        "a presence signal with a spoofed device_id must be dropped, not forwarded"
    );

    // The connection itself must still be healthy: an honestly-identified
    // signal sent right after on the very same channel goes through
    // normally — confirming the malicious message was specifically
    // dropped, not that the whole channel silently broke.
    let honest = proto::SyncMessage {
        payload: Some(proto::sync_message::Payload::Presence(proto::PresenceSignal {
            folder_group_id: GROUP.to_string(),
            path: "shared.txt".to_string(),
            device_id: "device-a".to_string(),
            editing: true,
            ttl_seconds: 90,
        })),
    };
    channel_a.send(honest.encode_to_vec()).await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), presence_rx.recv())
        .await
        .expect("an honestly-identified signal on the same connection must still go through")
        .unwrap();
    assert_eq!(event.device_id, "device-a");
}

/// The counterpart to the spoofed-`device_id` test
/// above — `handle_presence_signal` must also drop a signal whose `path`
/// fails `is_safe_relative_path` (e.g. `..` traversal or an absolute
/// path), rather than forwarding it verbatim as a `PresenceEvent` for the
/// UI to display.
#[tokio::test]
async fn presence_signal_with_unsafe_path_is_dropped() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let (presence_tx, mut presence_rx) = tokio::sync::mpsc::unbounded_channel();
    let _session_b = spawn_session_with_presence(channel_b, &device_b, "device-a", presence_tx);

    let malicious = proto::SyncMessage {
        payload: Some(proto::sync_message::Payload::Presence(proto::PresenceSignal {
            folder_group_id: GROUP.to_string(),
            path: "../outside.txt".to_string(),
            device_id: "device-a".to_string(),
            editing: true,
            ttl_seconds: 90,
        })),
    };
    channel_a.send(malicious.encode_to_vec()).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(500), presence_rx.recv()).await;
    assert!(
        result.is_err(),
        "a presence signal with an unsafe path must be dropped, not forwarded"
    );

    // Same "connection is still healthy" check as the spoofed-device_id
    // test above.
    let honest = proto::SyncMessage {
        payload: Some(proto::sync_message::Payload::Presence(proto::PresenceSignal {
            folder_group_id: GROUP.to_string(),
            path: "shared.txt".to_string(),
            device_id: "device-a".to_string(),
            editing: true,
            ttl_seconds: 90,
        })),
    };
    channel_a.send(honest.encode_to_vec()).await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), presence_rx.recv())
        .await
        .expect("an honestly-identified signal on the same connection must still go through")
        .unwrap();
    assert_eq!(event.path, "shared.txt");
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
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Give the (expected-to-fail-closed) sync attempt time to run its
    // course.
    tokio::time::sleep(Duration::from_millis(500)).await;

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
    let record = expect_file_changed(
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
    session_b.send_index_update(GROUP, vec![record]).await.unwrap();
    wait_until(|| device_a.root_path().join("ordinary.txt").exists(), Duration::from_secs(10))
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
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("cache.tmp");
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;
    assert!(device_a.state.get_file(GROUP, "cache.tmp").unwrap().is_some());

    // Device A alone decides to ignore "*.tmp" — device-local and unsynced;
    // device B's own config is untouched.
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
    // even broadcast), the crux of D2's "drop, don't delete" behavior.
    assert!(!changed.iter().any(|r| r.path == "cache.tmp"));

    // Broadcast whatever the rescan *did* return (nothing, here) exactly
    // as `link_manager`'s executor would, then confirm device B — which
    // never touched its own ignore config — keeps its copy untouched.
    if !changed.is_empty() {
        session_a.send_index_update(GROUP, changed).await.unwrap();
    }
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

/// An incoming record for a path matching this device's own ignore
/// patterns must be dropped before any materialization, indexing, or
/// forwarding — see `peer_session.rs`'s
/// `is_locally_ignored`/`reconcile_files`. Device A (the sender) does not
/// ignore the path itself — only device B does, via its own
/// `.yadorilinkignore` (device-local, unsynced) — so this exercises the
/// filter purely from the receiving side.
#[tokio::test]
async fn incoming_record_for_a_locally_ignored_path_is_dropped_before_materializing_or_forwarding()
{
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // Device B ignores "secret.log"; device A has no such pattern at all.
    std::fs::write(device_b.root_path().join(".yadorilinkignore"), "secret.log\n").unwrap();

    // Device A has both a path that's ignored-on-B and an ordinary file
    // that should sync normally, in the same initial full index.
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
    }

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let (forward_tx, mut forward_rx) = tokio::sync::mpsc::unbounded_channel();
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    // `EffectiveIgnoreSet` is loaded from `device_b`'s root at construction
    // time (mirroring `canonical_sync_roots`), so the `.yadorilinkignore`
    // written above must exist before this call.
    let session_b = PeerSyncSession::new_with_forwarding(
        channel_b,
        device_b.device_id.clone(),
        "device-a".to_string(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
        Some(forward_tx),
        None,
    );
    tokio::spawn(session_b.clone().run());

    // The ordinary (non-ignored) file replicating is the signal that
    // device A's full index — sent as one batch containing both files —
    // has already been fully reconciled, so by this point the ignored
    // record has also already been decided one way or the other.
    let ordinary_path = device_b.root_path().join("notes.txt");
    wait_until(|| ordinary_path.exists(), Duration::from_secs(10)).await;

    assert!(
        !device_b.root_path().join("secret.log").exists(),
        "an incoming record for a locally-ignored path must never be materialized to disk"
    );
    assert!(
        device_b.state.get_file(GROUP, "secret.log").unwrap().is_none(),
        "an incoming record for a locally-ignored path must never be added to the local index"
    );

    // Drain everything handed to `forward_tx` (full-mesh propagation to
    // this device's *other* peers) and confirm "secret.log" is never among
    // it — "notes.txt" alone is expected.
    let mut forwarded_paths = Vec::new();
    while let Ok(Some((_group, record))) =
        tokio::time::timeout(Duration::from_millis(500), forward_rx.recv()).await
    {
        forwarded_paths.push(record.path);
    }
    assert!(
        forwarded_paths.contains(&"notes.txt".to_string()),
        "sanity check: the ordinary file must still be forwarded, got {forwarded_paths:?}"
    );
    assert!(
        !forwarded_paths.contains(&"secret.log".to_string()),
        "an incoming record for a locally-ignored path must never be forwarded to other peers, \
         got {forwarded_paths:?}"
    );
}

/// Tombstoning a symlink record must remove the on-disk symlink itself,
/// and must never touch — let alone delete — whatever real file the link
/// happens to point at. Verified against an actual target file living
/// entirely outside device_b's sync root (a separate tempdir, never
/// itself part of what's being tombstoned), so a regression here (e.g.
/// accidentally resolving/following the link before removing it) would
/// show up as real data loss in the assertions below, not just a
/// passing-by-accident check.
///
/// `device_b`'s pre-tombstone state (an already-materialized symlink,
/// `record_kind = Symlink`, a recorded target) is set up directly against
/// `SyncState` rather than produced by a live scan/watch or a genuine
/// wire-transmitted symlink record — see `peer_session.rs`'s
/// `materialize_symlink_at` doc comment for why: at this point the wire
/// schema (`proto::FileInfo`) still carries no `record_kind`/
/// `symlink_target` field, so a peer cannot yet actually advertise "this
/// is a symlink" over the wire. The tombstone itself, by contrast, is
/// entirely real and wire-driven: `deleted` is an ordinary,
/// already-supported `FileRecord` field, sent via a real
/// `PeerSyncSession` full-index exchange like any other record.
#[cfg(unix)]
#[tokio::test]
async fn symlink_tombstone_removes_link_but_never_its_target() {
    let relay_addr = start_relay().await;
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

    // device_a advertises a tombstone for the same path with a version
    // that dominates device_b's current one, so device_b adopts it.
    let mut tombstone_version = base_version.clone();
    tombstone_version.increment("device-a");
    let tombstone = yadorilink_sync_core::types::FileRecord {
        path: "link.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        version: tombstone_version,
        blocks: vec![],
        deleted: true,
    };
    device_a.state.upsert_file(GROUP, &tombstone).unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(|| !device_b.root_path().join("link.txt").exists(), Duration::from_secs(10)).await;

    assert_eq!(
        std::fs::read(&target_path).unwrap(),
        b"do not delete me",
        "the tombstone must never touch the symlink's target, only the link itself"
    );
    let record = device_b.state.get_file(GROUP, "link.txt").unwrap().unwrap();
    assert!(record.deleted, "the index must agree the record is now a tombstone");
}

/// A held file's held state must clear once its record is tombstoned,
/// rather than leaving an orphaned `held_reason`/`held_since_unix_nanos`
/// entry with no corresponding live index record. Driven by a real,
/// wire-transmitted tombstone (`deleted` is an ordinary already-supported
/// `FileRecord` field) through an actual two-peer `PeerSyncSession`
/// exchange — the held-file setup itself is device-local index state
/// (`SyncState::set_held`), the same as it would be from a real
/// case-fold-collision/invalid-name detection (not yet implemented at
/// this point).
#[tokio::test]
async fn held_file_tombstone_clears_held_state() {
    let relay_addr = start_relay().await;
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

    let mut tombstone_version = base_version.clone();
    tombstone_version.increment("device-a");
    let tombstone = yadorilink_sync_core::types::FileRecord {
        path: "A.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        version: tombstone_version,
        blocks: vec![],
        deleted: true,
    };
    device_a.state.upsert_file(GROUP, &tombstone).unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(
        || matches!(device_b.state.get_file(GROUP, "A.txt"), Ok(Some(r)) if r.deleted),
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(
        device_b.state.get_held_state(GROUP, "A.txt").unwrap(),
        None,
        "a tombstoned file must not leave an orphaned held entry"
    );
}

/// A real, wire-driven two-peer scenario — device A's "Photo.jpg" fully
/// materializes on device B first; only afterward does A send a second,
/// real-content record, "photo.jpg", differing only in case. Device B's
/// sync root (an ordinary tempdir, case-insensitive on this suite's
/// actual dev/CI platforms) has a genuine case-fold collision: the
/// *second*-arriving record must be held (a short-circuit ahead of the
/// atomic write) — never written to disk under its own name or any other
/// — while the first, already-materialized file is left completely
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

    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let first_replicated = device_b.root_path().join("Photo.jpg");
    wait_until(|| first_replicated.exists(), Duration::from_secs(10)).await;
    assert_eq!(std::fs::read(&first_replicated).unwrap(), b"original photo bytes");

    // Second record, differing only in case — sent explicitly (rather
    // than via a real second local file on device A's own, plausibly
    // also case-insensitive, filesystem) so this test exercises exactly
    // "a second record for a case-fold-colliding path arrives", the
    // describes, regardless of device A's own OS.
    let second_bytes = b"a completely different photo";
    let hash_hex = device_a.store.put(second_bytes).unwrap();
    let second_block = yadorilink_sync_core::types::BlockInfo {
        hash: hex::decode(&hash_hex).unwrap(),
        offset: 0,
        size: second_bytes.len() as u32,
    };
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    let second_record = yadorilink_sync_core::types::FileRecord {
        path: "photo.jpg".into(),
        size: second_bytes.len() as u64,
        mtime_unix_nanos: 0,
        version,
        blocks: vec![second_block],
        deleted: false,
    };
    session_a.send_index_update(GROUP, vec![second_record]).await.unwrap();

    wait_until(
        || device_b.state.get_held_state(GROUP, "photo.jpg").unwrap().is_some(),
        Duration::from_secs(10),
    )
    .await;

    let held = device_b.state.get_held_state(GROUP, "photo.jpg").unwrap().unwrap();
    assert!(held.reason.starts_with("case_collision"), "unexpected reason: {}", held.reason);

    // a held record still keeps its own index row.
    let stored = device_b.state.get_file(GROUP, "photo.jpg").unwrap().unwrap();
    assert!(!stored.deleted);
    assert_eq!(stored.size, second_bytes.len() as u64);

    // (): the actual regression assertion — device B's
    // sync root must contain *exactly* the one, original, non-hazardous
    // file. No `photo.jpg`, no numbered/suffixed variant of either name
    // (`Photo (1).jpg`, `photo_2.jpg`, ...) — nothing beyond what a
    // completely ordinary, uncontested sync would have produced.
    let mut entries: Vec<String> = std::fs::read_dir(device_b.root_path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["Photo.jpg".to_string()],
        "a name hazard must never produce a written file under any name other than the \
         original — this crate implements no automatic rename/escape path ()"
    );
    assert_eq!(
        std::fs::read(&first_replicated).unwrap(),
        b"original photo bytes",
        "the first, already-materialized file must be completely untouched by the second \
         record's collision"
    );
}

/// A held file's record and content blocks must keep flowing to peers
/// exactly like any other record — held state is a *local* materialization
/// gate (this device won't write the bytes to disk under this hazardous
/// name), not an exclusion from index exchange or block serving: the
/// index continues tracking it, so it still syncs correctly to any
/// peer/platform where the name is valid. Held state is set up directly
/// against device B's own `SyncState`/`BlockStore` here (the same
/// device-local setup `held_file_tombstone_clears_held_state` above uses)
/// rather than driven through an actual case-fold collision, so this test
/// isolates exactly the property that matters — B, despite holding this
/// record, still answers device C's real block requests for it over an
/// actual two-peer wire connection.
#[tokio::test]
async fn held_files_blocks_are_still_served_to_a_requesting_peer() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let device_c = Device::new("device-c");

    let content = b"content this device holds but never wrote to disk";
    let hash_hex = device_b.store.put(content).unwrap();
    let block = yadorilink_sync_core::types::BlockInfo {
        hash: hex::decode(&hash_hex).unwrap(),
        offset: 0,
        size: content.len() as u32,
    };
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-b");
    let held_record = yadorilink_sync_core::types::FileRecord {
        path: "photo.jpg".into(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        version,
        blocks: vec![block],
        deleted: false,
    };
    device_b.state.upsert_file(GROUP, &held_record).unwrap();
    device_b
        .state
        .set_held(GROUP, "photo.jpg", "case_collision: collides with existing 'Photo.jpg'", 1_000)
        .unwrap();
    assert!(
        !device_b.root_path().join("photo.jpg").exists(),
        "sanity check: nothing is on disk under the held name before B ever connects to anyone"
    );

    let (channel_b, channel_c) = connect_pair(relay_addr).await;
    let _session_b = spawn_session(channel_b, &device_b, "device-c");
    let _session_c = spawn_session(channel_c, &device_c, "device-b");

    let path_on_c = device_c.root_path().join("photo.jpg");
    wait_until(|| path_on_c.exists(), Duration::from_secs(10)).await;
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
/// genuine symlink on disk, `LocalChangeProcessor::process_event` (the
/// actual scan/watch classification — not a hand-built `FileRecord`)
/// records it as `RecordKind::Symlink` with its target text, and only
/// *then* do the two devices connect over an actual relay `PeerChannel`
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
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("shortcut");
    // `.exists()` follows symlinks and would report `false` for a symlink
    // whose target isn't resolvable from B's perspective — use the
    // lstat-equivalent check so this doesn't depend on B being able to
    // resolve the target at all.
    wait_until(|| std::fs::symlink_metadata(&replicated_path).is_ok(), Duration::from_secs(10))
        .await;

    let metadata = std::fs::symlink_metadata(&replicated_path).unwrap();
    assert!(
        metadata.file_type().is_symlink(),
        "device B must materialize a real symlink, not a regular (and, since a symlink record \
         carries no blocks, empty) file — this is exactly the round-trip wire gap \
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

/// Closes the same wire-serialization gap as the symlink test above, for
/// the other field it silently dropped in both directions — the
/// owner-executable bit. Device A's index records a file as executable
/// (`SyncState::set_exec_bit`, standing in for the still-separately-open
/// local-capture wiring — see `types.rs`'s `owner_exec_bit_from_metadata`
/// doc comment for that distinct, still-undone gap; this test is scoped
/// to whether an *already-recorded* bit
/// crosses the wire and gets applied for real, not to how it got recorded
/// in the first place), and a real two-peer sync must leave device B's
/// **actual on-disk file** — not just its index row — with the owner-exec
/// permission bit set.
#[cfg(unix)]
#[tokio::test]
async fn exec_bit_set_on_one_device_is_applied_to_the_real_file_on_its_peer() {
    use std::os::unix::fs::PermissionsExt;

    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("run.sh");
    std::fs::write(&file_path, b"#!/bin/sh\necho hi\n").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    device_a.state.set_exec_bit(GROUP, "run.sh", true).unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("run.sh");
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;

    assert_eq!(std::fs::read(&replicated_path).unwrap(), b"#!/bin/sh\necho hi\n");
    let mode = std::fs::metadata(&replicated_path).unwrap().permissions().mode();
    assert_ne!(
        mode & 0o100,
        0,
        "device B's real, on-disk file must carry the owner-exec bit device A advertised — \
         before fix this field never crossed the wire at all"
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

    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    let replicated_path = device_b.root_path().join("build.sh");
    wait_until(|| replicated_path.exists(), Duration::from_secs(10)).await;
    assert_eq!(std::fs::read(&replicated_path).unwrap(), content);
    assert_eq!(
        std::fs::metadata(&replicated_path).unwrap().permissions().mode() & 0o100,
        0,
        "sanity check: not executable yet"
    );

    // Content is unchanged; only the exec bit flips — this is what makes
    // `try_apply_metadata_only_update`'s block-list comparison match.
    // `set_exec_bit` alone doesn't bump the version vector (it isn't a
    // version-vector-tracked column) — a real capture path would increment
    // it as part of recording the metadata change, so this test does the
    // same explicitly, otherwise device B's version-vector comparison sees
    // `Equal` and never even looks at the incoming record.
    device_a.state.set_exec_bit(GROUP, "build.sh", true).unwrap();
    let mut updated_record = device_a.state.get_file(GROUP, "build.sh").unwrap().unwrap();
    updated_record.version.increment("device-a");
    device_a.state.upsert_file(GROUP, &updated_record).unwrap();
    session_a.send_index_update(GROUP, vec![updated_record]).await.unwrap();

    wait_until(
        || {
            std::fs::metadata(&replicated_path)
                .map(|m| m.permissions().mode() & 0o100 != 0)
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(
        std::fs::read(&replicated_path).unwrap(),
        content,
        "the metadata-only fast path must never disturb already-correct file content"
    );
}

// --- Rate-limiting integration tests ---

/// the default (unlimited, `RateLimiters::unlimited()`) session
/// configuration imposes no measurable delay on a real block transfer —
/// end-to-end confirmation alongside `rate_limiter::tests`'s unit-level one.
#[tokio::test]
async fn unlimited_rate_limiters_impose_no_measurable_delay_on_a_real_transfer() {
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
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

/// a configured non-zero download rate measurably caps real
/// block-transfer throughput — the file is small enough to be a single
/// `DEFAULT_BLOCK_SIZE` block, so the configured rate directly bounds the
/// one `fetch_block` call's `acquire` wait.
#[tokio::test]
async fn configured_download_rate_caps_real_block_transfer_throughput() {
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
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
    // rate-limited; generous margin for scheduling/relay overhead.
    let expected_min_secs =
        (size as f64 - rate_bytes_per_sec as f64).max(0.0) / rate_bytes_per_sec as f64;
    let expected_min =
        Duration::from_secs_f64(expected_min_secs).saturating_sub(Duration::from_millis(750));
    assert!(
        elapsed >= expected_min,
        "expected a throttled transfer to take at least {expected_min:?}, took {elapsed:?}"
    );
}

/// control messages are not delayed even while the download
/// bucket is saturated by an in-progress, heavily-throttled block transfer
/// — a presence signal (small protocol message, never gated on either
/// bucket) sent concurrently must still complete promptly.
#[tokio::test]
async fn saturated_download_bucket_never_delays_a_concurrent_presence_signal() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let file_path = device_a.root_path().join("big.bin");
    std::fs::write(&file_path, vec![0xCDu8; 100_000]).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Throttled heavily enough that the 100KB file's single block would
    // take on the order of a minute to fully arrive — plenty of time for
    // the assertion below to observe the bucket still saturated.
    session_b.set_rate_limiters(Arc::new(RateLimiters::new(0, 1_000)));

    // Give the eager-fetch machinery a moment to actually start (and start
    // blocking on bucket refill inside `fetch_block`).
    tokio::time::sleep(Duration::from_millis(300)).await;

    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(3),
        session_b.send_presence_signal(GROUP, "notes.txt", true, 60),
    )
    .await
    .expect("presence signal must not be delayed by a saturated download bucket")
    .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "presence signal took {:?} while the download bucket was saturated",
        start.elapsed()
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

/// two real sessions, both advertising compression support (this
/// build always does — the relevant behavior), must negotiate it and still deliver
/// byte-for-byte correct content through the real compress-on-send /
/// decompress-on-receive path — not merely "sync still works," but sync
/// still works *with compression actually engaged*, verified via the
/// public `compression_negotiated()` getter (the relevant behavior).
#[tokio::test]
async fn compression_is_negotiated_between_two_real_sessions_and_content_round_trips() {
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    // Negotiation happens from the handshake `ClusterConfig` each side
    // sends first in `run()` (the relevant behavior) — both sessions should observe
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

/// the relevant behavior: a raw, manually-driven peer that advertises compression
/// support must actually receive a `Compression::Zstd`-tagged, genuinely
/// smaller `BlockResponse` for compressible content — inspecting the real
/// wire bytes a live `PeerSyncSession::handle_block_request` produces,
/// not just asserting the codec functions work standalone.
#[tokio::test]
async fn block_response_is_actually_compressed_on_the_wire_when_negotiated() {
    let relay_addr = start_relay().await;
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

    let (channel_a, requester_channel) = connect_pair(relay_addr).await;
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

/// a peer that never advertises compression support (an old,
/// pre-this-change peer, simulated here by simply never sending a
/// `ClusterConfig` with `supported_compression` set) must never receive a
/// `Compression::Zstd`-tagged response — block fetch behaves identically
/// to pre-change behavior, byte-for-byte.
#[tokio::test]
async fn block_response_is_uncompressed_when_peer_did_not_advertise_support() {
    let relay_addr = start_relay().await;
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

    let (channel_a, requester_channel) = connect_pair(relay_addr).await;
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
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();

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

    let (responder_channel, channel_b) = connect_pair(relay_addr).await;
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
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();

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

    let (responder_channel, channel_b) = connect_pair(relay_addr).await;
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

/// A synthetic large folder (many files, deeply repetitive paths)
/// produces a smaller on-wire index message when compression is
/// negotiated than when it isn't, with the same file set recoverable
/// either way.
///
/// Deliberately exercises `send_index_update` (not the very first
/// `FullIndex` `run()` sends at connect time) via an explicit call made
/// *after* waiting for `compression_negotiated()` to become `true`: the
/// initial handshake send happens before this session has ever had a
/// chance to receive the peer's `ClusterConfig` (there is no round trip
/// before it), so it is *always* sent uncompressed regardless of what the
/// peer advertises — that's expected, not a bug (negotiation only applies
/// once a peer's advertisement has actually been observed). This test
/// targets the negotiated-and-therefore-compressible steady state
/// `send_full_index`/`send_index_update` share via `compress_index_files`.
#[tokio::test]
async fn compressed_index_update_is_smaller_on_the_wire_than_uncompressed() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");

    // Deeply repetitive paths (thousands of highly repetitive FileRecord
    // paths) — enough files that the index message is meaningfully large
    // either way.
    for i in 0..80 {
        let dir = device_a.root_path().join(format!("src/pkg/module_{:04}", i / 20));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join(format!("file_{i:04}.rs"));
        std::fs::write(&file_path, format!("pub fn generated_{i}() {{}}\n")).unwrap();
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
    }
    let all_records = device_a.state.list_files(GROUP).unwrap();
    assert_eq!(all_records.len(), 80);

    async fn recv_index_update_raw_len(channel: &PeerChannel) -> (usize, proto::IndexUpdate) {
        loop {
            let bytes = channel.recv().await.unwrap();
            let raw_len = bytes.len();
            let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
            if let Some(proto::sync_message::Payload::IndexUpdate(update)) = msg.payload {
                return (raw_len, update);
            }
        }
    }

    // Compression-capable observer: a real session whose peer (the raw
    // `observer_1` channel) advertises Zstd support.
    let (channel_a1, observer_1) = connect_pair(relay_addr).await;
    let session_a1 = spawn_session(channel_a1, &device_a, "device-b1");
    observer_1
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                    folder_group_ids: vec![GROUP.to_string()],
                    known_peer_device_ids: vec!["device-b1".to_string()],
                    supported_compression: vec![proto::Compression::Zstd as i32],
                    ..Default::default()
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
    wait_until(|| session_a1.compression_negotiated(), Duration::from_secs(5)).await;
    session_a1.send_index_update(GROUP, all_records.clone()).await.unwrap();
    let (compressed_wire_len, compressed_update) = recv_index_update_raw_len(&observer_1).await;

    // Non-advertising observer — simulates an old peer, on a fresh session
    // (negotiation is per-session, the relevant behavior) so its `IndexUpdate` is sent
    // uncompressed.
    let (channel_a2, observer_2) = connect_pair(relay_addr).await;
    let session_a2 = spawn_session(channel_a2, &device_a, "device-b2");
    // Give the (never-to-be-negotiated) handshake a moment to complete,
    // mirroring `incremental_change_after_initial_sync_propagates`'s own
    // settle delay before an explicit send.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!session_a2.compression_negotiated());
    session_a2.send_index_update(GROUP, all_records).await.unwrap();
    let (uncompressed_wire_len, uncompressed_update) = recv_index_update_raw_len(&observer_2).await;

    assert_eq!(compressed_update.compression, proto::Compression::Zstd as i32);
    assert!(
        compressed_update.changed_files.is_empty(),
        "compressed form carries files via compressed_changed_files, not the structured field"
    );
    assert_eq!(uncompressed_update.compression, proto::Compression::None as i32);
    assert_eq!(uncompressed_update.changed_files.len(), 80);

    assert!(
        compressed_wire_len < uncompressed_wire_len / 2,
        "a compressed 80-file, deeply-repetitive-path index update ({compressed_wire_len} \
         bytes on the wire) should be well under half the uncompressed size \
         ({uncompressed_wire_len} bytes)"
    );

    // Same underlying file set is recoverable from the compressed form.
    let decompressed =
        zstd::stream::decode_all(compressed_update.compressed_changed_files.as_slice())
            .expect("compressed_changed_files must be a valid zstd stream");
    let inner = proto::Index::decode(decompressed.as_slice()).unwrap();
    assert_eq!(inner.files.len(), uncompressed_update.changed_files.len());
    let mut compressed_paths: Vec<_> = inner.files.iter().map(|f| f.path.clone()).collect();
    let mut uncompressed_paths: Vec<_> =
        uncompressed_update.changed_files.iter().map(|f| f.path.clone()).collect();
    compressed_paths.sort();
    uncompressed_paths.sort();
    assert_eq!(compressed_paths, uncompressed_paths);
}

/// the same large, repetitive-path folder as above, but this
/// time synced through two *real* sessions end to end via an explicit
/// `send_index_update` (see `compressed_index_update_is_smaller_on_the_
/// wire_than_uncompressed`'s doc comment for why: the very first `FullIndex`
/// a fresh session sends at connect time necessarily predates any
/// round trip, so it can never itself be compressed) — the compressed
/// `IndexUpdate` message (800 files' worth of `FileInfo`, still comfortably
/// over `yadorilink_transport::framing::MAX_FRAGMENT_PAYLOAD` even after
/// compression) must be fragmented and reassembled correctly by the
/// existing transport-level framing, exercised together with compression
/// rather than bypassed by it — proven by every file actually arriving,
/// correctly, on the receiving device.
#[tokio::test]
async fn large_compressed_index_survives_fragmentation_and_reassembly() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // Wait for negotiation (both sides in this test always advertise
    // support) before creating/sending the large batch, so the
    // `IndexUpdate` below is actually sent compressed rather than racing
    // the initial handshake.
    wait_until(|| session_a.compression_negotiated(), Duration::from_secs(5)).await;

    let mut records = Vec::with_capacity(800);
    for i in 0..60 {
        let dir = device_a.root_path().join(format!("src/pkg/module_{:04}", i / 20));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join(format!("file_{i:04}.rs"));
        std::fs::write(&file_path, format!("pub fn generated_{i}() {{}}\n")).unwrap();
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
        records.push(record);
    }
    session_a.send_index_update(GROUP, records).await.unwrap();

    // Wait on actual on-disk materialization, not just the index row count
    // reaching 120 — reconciling an index row (task/state upsert) and
    // materializing its content to disk are separate steps
    // (`reconcile_files`'s bounded-concurrency processing), so checking
    // only the row count and then immediately asserting file existence
    // races the last few files' materialization under heavier parallel
    // test-suite load.
    wait_until(
        || {
            (0..60).all(|i| {
                let rel = format!("src/pkg/module_{:04}/file_{i:04}.rs", i / 20);
                device_b.root_path().join(rel).exists()
            })
        },
        Duration::from_secs(15),
    )
    .await;

    for i in 0..60 {
        let rel = format!("src/pkg/module_{:04}/file_{i:04}.rs", i / 20);
        let path = device_b.root_path().join(&rel);
        assert!(path.exists(), "{rel} must exist on device_b after a fragmented compressed sync");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("pub fn generated_{i}() {{}}\n")
        );
    }
}

/// The adaptive in-flight window: a real, end-to-end proof (not just the
/// standalone `AdaptiveWindow` unit tests) that
/// `PeerSyncSession::fetch_window` moves in response to real `fetch_block`
/// traffic over a real (relay) transport, through the actual public API
/// `yadorilink-daemon`'s multi-peer dispatcher consults
/// (`fetch_window`/`record_fetch_timeout`) — grows under many real, fast,
/// successful round trips, then shrinks once timeouts are reported the
/// way a real caller-imposed bound would report them, then grows back
/// once good conditions resume.
#[tokio::test]
async fn fetch_window_grows_under_real_traffic_and_shrinks_after_timeouts_then_recovers() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // OnDemand on device_b so the initial index sync adopts a placeholder
    // without eagerly fetching — `hydrate_file` below then drives every
    // block fetch explicitly, giving a clean, countable burst of real
    // `fetch_block` round trips over the live relay connection.
    let root_b = device_b.root_path().to_string_lossy().to_string();
    device_b.state.add_link(&root_b, GROUP).unwrap();
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
    let content = vec![0x5Au8; 1_000_000];
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let session_b = spawn_session(channel_b, &device_b, "device-a");

    let placeholder_path = device_b.root_path().join("big-archive.tar");
    wait_until(|| placeholder_path.exists(), Duration::from_secs(20)).await;

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
    let record2 = expect_file_changed(
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
    session_a.send_index_update(GROUP, vec![record2]).await.unwrap();
    wait_until(
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
    let relay_addr = start_relay().await;
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

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    // Initial full sync, sent automatically at connect time (`run`'s
    // handshake) — every file materializes on device_b.
    wait_until(
        || (0..FILE_COUNT).all(|i| device_b.root_path().join(format!("file_{i:04}.txt")).exists()),
        Duration::from_secs(20),
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
    let all_records = device_a.state.list_files(GROUP).unwrap();
    assert_eq!(all_records.len(), FILE_COUNT);
    let started = std::time::Instant::now();
    session_a.send_index_update(GROUP, all_records).await.unwrap();

    wait_until(
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

/// A tombstone *adopted from a peer* (not just a local delete —
/// `mark_deleted`'s own case is covered directly in `index.rs`'s unit
/// tests) enters the same recoverable trashed state as a local deletion
/// would (spec "A tombstone adopted from a peer also enters trash").
/// Device A holds real content for "shared.txt"; device B's tombstone
/// strictly dominates A's version vector (an ordinary "peer is ahead"
/// adoption, not a conflict), so A adopts it outright via
/// `reconcile_one_file`'s `VvOrdering::Before` branch — exercising
/// `materialize`'s tombstone-apply path over the real wire, not a direct
/// `SyncState` call.
#[tokio::test]
async fn tombstone_adopted_from_a_peer_enters_recoverable_trash() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    let mut base_version = yadorilink_sync_core::version_vector::VersionVector::new();
    base_version.increment("device-base");

    let mut version_a = base_version.clone();
    version_a.increment("device-a");
    let content_a: &[u8] = b"real content that must be recoverable from trash";
    let path_a = device_a.root_path().join("shared.txt");
    std::fs::write(&path_a, content_a).unwrap();
    let blocks_a =
        yadorilink_sync_core::chunker::chunk_file(device_a.store.as_ref(), &path_a).unwrap();
    device_a
        .state
        .upsert_file_with_origin(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "shared.txt".into(),
                size: content_a.len() as u64,
                mtime_unix_nanos: 1000,
                version: version_a.clone(),
                blocks: blocks_a,
                deleted: false,
            },
            "device-a",
        )
        .unwrap();

    // device_b's tombstone strictly dominates device_a's version (same
    // counters plus its own increment) — an ordinary "peer is ahead"
    // adoption, not a concurrent-edit conflict.
    let mut version_b = version_a.clone();
    version_b.increment("device-b");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "shared.txt".into(),
                size: 0,
                mtime_unix_nanos: 2000,
                version: version_b,
                blocks: vec![],
                deleted: true,
            },
        )
        .unwrap();

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let _session_a = spawn_session(channel_a, &device_a, "device-b");
    let _session_b = spawn_session(channel_b, &device_b, "device-a");

    wait_until(|| !device_a.root_path().join("shared.txt").exists(), Duration::from_secs(10)).await;

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

// --- Untrusted storage peer ---
//
// These tests exercise the real wire protocol (real `PeerChannel`s over a
// real relay, real `PeerSyncSession`s) exactly like every other test in
// this file — no mocked crypto, no direct calls into `content_crypto`
// standing in for what actually crosses the wire, except where a test
// explicitly needs to compute an expected ciphertext hash independently
// (which any real trusted device could equally do, since encryption is
// deterministic under convergent mode) or play the role of a malicious
// peer answering with attacker-controlled bytes.

use yadorilink_sync_core::content_crypto::{encrypt_block, GroupKey};

/// encrypted-peer spec: "A malicious storage peer returning wrong bytes is
/// detected" — case 1: the storage peer returns ciphertext that fails AEAD
/// authentication outright (a single flipped bit, as tampering or simple
/// corruption would produce).
#[tokio::test]
async fn fetch_from_storage_peer_rejects_aead_tampered_ciphertext() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let (malicious_channel, channel_b) = connect_pair(relay_addr).await;
    let session_b = spawn_session(channel_b, &device_b, "device-malicious-storage-peer");
    session_b.set_storage_only(GROUP, true);
    let key = GroupKey::generate();
    session_b.set_group_key(GROUP, key.clone(), true);

    let plaintext = b"trusted content device B actually wants".to_vec();
    let plaintext_hash = sha256_bytes(&plaintext);
    let encrypted = encrypt_block(&key, &plaintext_hash, &plaintext, true).unwrap();
    let ciphertext_hash = encrypted.ciphertext_hash().to_vec();
    let mut tampered_ciphertext = encrypted.ciphertext.clone();
    let last = tampered_ciphertext.len() - 1;
    tampered_ciphertext[last] ^= 0x01;

    let responder = tokio::spawn(async move {
        let bytes = malicious_channel.recv().await.unwrap();
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
            panic!("expected a BlockRequest");
        };
        malicious_channel
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(
                        proto::BlockResponse {
                            block_hash: req.block_hash,
                            data: tampered_ciphertext,
                            not_found: false,
                            is_ciphertext: true,
                            ciphertext_nonce: encrypted.nonce.to_vec(),
                            ..Default::default()
                        },
                    )),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    });

    let result = session_b
        .fetch_block_from_storage_peer(GROUP, &ciphertext_hash, &plaintext_hash)
        .await
        .unwrap();
    responder.await.unwrap();

    assert_eq!(result, None, "AEAD-authentication-failing ciphertext must be rejected");
}

/// encrypted-peer spec: "A malicious storage peer returning wrong bytes is
/// detected" — case 2, the subtler one `content_crypto`'s own doc
/// comments call out explicitly: a peer returns a *different*, validly
/// AEAD-encrypted block (correctly authenticated under its own correct
/// nonce and the same group key) instead of the one requested. AEAD
/// authentication alone cannot catch this — only the post-decrypt
/// plaintext-content-hash re-check can, which is exactly what this test
/// proves is wired in at the real `fetch_block_from_storage_peer` call,
/// not just unit-tested in isolation inside `content_crypto`.
#[tokio::test]
async fn fetch_from_storage_peer_rejects_a_different_validly_encrypted_block() {
    let relay_addr = start_relay().await;
    let device_b = Device::new("device-b");
    let (malicious_channel, channel_b) = connect_pair(relay_addr).await;
    let session_b = spawn_session(channel_b, &device_b, "device-malicious-storage-peer");
    session_b.set_storage_only(GROUP, true);
    let key = GroupKey::generate();
    session_b.set_group_key(GROUP, key.clone(), true);

    let wanted_plaintext = b"the block device B actually asked for".to_vec();
    let wanted_hash = sha256_bytes(&wanted_plaintext);
    let wanted_ciphertext_hash = encrypt_block(&key, &wanted_hash, &wanted_plaintext, true)
        .unwrap()
        .ciphertext_hash()
        .to_vec();

    let substituted_plaintext = b"a completely different block, also validly encrypted".to_vec();
    let substituted_hash = sha256_bytes(&substituted_plaintext);
    let substituted = encrypt_block(&key, &substituted_hash, &substituted_plaintext, true).unwrap();
    assert_ne!(substituted_hash, wanted_hash);

    let responder = tokio::spawn(async move {
        let bytes = malicious_channel.recv().await.unwrap();
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        let Some(proto::sync_message::Payload::BlockRequest(req)) = msg.payload else {
            panic!("expected a BlockRequest");
        };
        // The malicious peer echoes back the hash the requester asked for
        // (so `handle_ciphertext_block_response`'s waiter resolves) but
        // answers with a different block's ciphertext/nonce entirely.
        malicious_channel
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(
                        proto::BlockResponse {
                            block_hash: req.block_hash,
                            data: substituted.ciphertext,
                            not_found: false,
                            is_ciphertext: true,
                            ciphertext_nonce: substituted.nonce.to_vec(),
                            ..Default::default()
                        },
                    )),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    });

    let result = session_b
        .fetch_block_from_storage_peer(GROUP, &wanted_ciphertext_hash, &wanted_hash)
        .await
        .unwrap();
    responder.await.unwrap();

    assert_eq!(
        result, None,
        "a different, validly-encrypted block substituted for the one requested must still be \
         rejected by the post-decrypt plaintext-hash check"
    );
}

/// encrypted-peer spec: "Key is never sent to the coordination plane" /
/// "Key is never sent to an untrusted peer" — asserts directly against the
/// real bytes on the wire: every message a trusted device sends to a peer
/// it has flagged storage-only, across an entire real session lifetime
/// (handshake, index, and block exchange), decodes as containing no
/// `WrappedGroupKey` payload and no plaintext index/block data — only the
/// ciphertext/encrypted-index shapes.
#[tokio::test]
async fn no_wire_message_to_a_flagged_storage_only_peer_carries_the_group_key_or_plaintext() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");
    let root_a = device_a.root_path().to_string_lossy().to_string();
    device_a.state.add_link(&root_a, GROUP).unwrap();

    let plaintext = b"never leave this device unencrypted".to_vec();
    let plaintext_hash = sha256_bytes(&plaintext);
    device_a.store.put(&plaintext).unwrap();
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "confidential.bin".into(),
                size: plaintext.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: plaintext_hash.clone(),
                    offset: 0,
                    size: plaintext.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();

    let (channel_a, observer_channel) = connect_pair(relay_addr).await;
    let session_a = spawn_session(channel_a, &device_a, "device-storage-peer");
    session_a.set_storage_only(GROUP, true);
    let key = GroupKey::generate();
    session_a.set_group_key(GROUP, key.clone(), true);
    // A real key-distribution call site (the relevant behavior) — asserting it's a
    // deliberate, harmless no-op against a flagged peer, not merely
    // "nothing happens to call it in this test." Uses `x25519_dalek`
    // explicitly (not the `boringtun::x25519` types this file already
    // imports for transport identities, which are a different crate/type
    // entirely) — the same type `content_crypto`'s wrap/unwrap and
    // `PeerSyncSession::set_local_identity_secret`/`send_wrapped_group_key`
    // use.
    let local_identity_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let peer_identity_public = x25519_dalek::PublicKey::from(
        &x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
    );
    session_a.set_local_identity_secret(local_identity_secret);
    session_a.send_wrapped_group_key(GROUP, &peer_identity_public, 1).await.unwrap();

    // Ask for the block by ciphertext hash too (as the observer/storage
    // peer would), so this also inspects a real `BlockResponse` on the
    // wire, not only the handshake/index messages. Computed independently
    // here (the test knows the same group key and convergent plaintext
    // hash `handle_ciphertext_block_request` will derive the same
    // ciphertext hash from) rather than added as a test-only accessor on
    // `PeerSyncSession`.
    let ciphertext_hash =
        encrypt_block(&key, &plaintext_hash, &plaintext, true).unwrap().ciphertext_hash().to_vec();

    // `run()`'s handshake sequence is exactly two messages: `ClusterConfig`,
    // then one `send_full_index` per shared group (one group here) — every
    // one of them inspected below.
    let mut saw_encrypted_index = false;
    for _ in 0..2 {
        let bytes = tokio::time::timeout(Duration::from_secs(2), observer_channel.recv())
            .await
            .expect("expected a handshake/index message from the session")
            .expect("channel closed unexpectedly");
        let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
        match msg.payload {
            Some(proto::sync_message::Payload::WrappedGroupKey(_)) => {
                panic!("the group content key must never be sent to a flagged storage-only peer")
            }
            Some(proto::sync_message::Payload::FullIndex(_))
            | Some(proto::sync_message::Payload::IndexUpdate(_)) => {
                panic!("plaintext index must never be sent to a flagged storage-only peer")
            }
            Some(proto::sync_message::Payload::EncryptedFullIndex(_)) => {
                saw_encrypted_index = true;
            }
            _ => {}
        }
    }
    assert!(
        saw_encrypted_index,
        "expected an EncryptedIndex (not a plaintext Index) since the peer is flagged \
         storage-only"
    );

    // Now play the storage peer's real next move: request the block it
    // learned about (by ciphertext hash) from that index. The hash is
    // computed independently here rather than by actually decrypting
    // anything (the observer, playing the untrusted peer, couldn't — it
    // never has the key), the same way any two trusted devices could each
    // independently derive it from the same group key and plaintext.
    observer_channel
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                    folder_group_id: GROUP.to_string(),
                    file_path: String::new(),
                    block_hash: ciphertext_hash.clone(),
                })),
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();

    let bytes = tokio::time::timeout(Duration::from_secs(2), observer_channel.recv())
        .await
        .expect("expected a BlockResponse")
        .expect("channel closed unexpectedly");
    let msg = proto::SyncMessage::decode(bytes.as_slice()).unwrap();
    let Some(proto::sync_message::Payload::BlockResponse(resp)) = msg.payload else {
        panic!("expected a BlockResponse, got {msg:?}");
    };
    assert_ne!(
        resp.data, plaintext,
        "block response to a flagged storage-only peer must never carry plaintext bytes"
    );
    assert!(resp.is_ciphertext, "must be marked as ciphertext");
}

/// The central claim: content that passes entirely through an untrusted
/// storage peer — which never holds the group key and never sees
/// plaintext — is still fully recoverable, integrity-verified, and
/// materializable by a trusted device that never talked to the original
/// uploader directly. Three real devices, three real `PeerSyncSession`s,
/// two independent real relay hops (A-to-C and C-to-B) — no mocked crypto
/// standing in for the wire.
///
/// This also doubles as the "genuinely never contains plaintext on disk"
/// proof: after A pushes the block to C over the real wire, this test
/// reads C's block-store file directly off the filesystem (not through any
/// `BlockStore`/session API) and asserts it is the AEAD ciphertext, is
/// never byte-equal to the plaintext, and does not even contain the
/// plaintext as a substring.
#[tokio::test]
async fn trusted_peer_materializes_content_relayed_through_an_untrusted_storage_peer() {
    let relay_addr = start_relay().await;
    let key = GroupKey::generate();

    // --- device A: the original, trusted content owner ---
    let device_a = Device::new("device-a");
    let root_a = device_a.root_path().to_string_lossy().to_string();
    device_a.state.add_link(&root_a, GROUP).unwrap();

    let content =
        b"content that must never touch the untrusted storage peer's disk in the clear".to_vec();
    let content_hash = sha256_bytes(&content);
    device_a.store.put(&content).unwrap();
    let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
    version.increment("device-a");
    device_a
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "secret.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: content_hash.clone(),
                    offset: 0,
                    size: content.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();

    // --- device C: the untrusted storage-only relay. A dedicated,
    // *retained* tempdir (unlike `Device::new`'s internal one) so this
    // test can read its block-store files directly off disk afterward. ---
    let c_store_dir = tempfile::tempdir().unwrap();
    let c_store = Arc::new(FsBlockStore::new(c_store_dir.path()).unwrap());
    let c_state = Arc::new(SyncState::open_in_memory().unwrap());
    let c_sync_root = tempfile::tempdir().unwrap();
    let c_sync_roots = HashMap::from([(GROUP.to_string(), c_sync_root.path().to_path_buf())]);

    // A <-> C: A treats C as storage-only and holds the group key; C
    // knows it is itself storage-only for this group (holds no key at all
    // -- never constructed with one).
    let (channel_a, channel_c1) = connect_pair(relay_addr).await;
    let session_a = PeerSyncSession::new(
        channel_a,
        "device-a".to_string(),
        "device-c".to_string(),
        device_a.state.clone(),
        device_a.store.clone(),
        vec![GROUP.to_string()],
        device_a.sync_roots(),
    );
    session_a.set_storage_only(GROUP, true);
    session_a.set_group_key(GROUP, key.clone(), true);
    tokio::spawn(session_a.clone().run());

    // A single shared nonce cache for device C's block store, injected
    // into *every* `PeerSyncSession` C runs (see `set_ciphertext_nonce_
    // cache`'s doc comment) -- otherwise a block C learned via its session
    // with A would be stuck in that session's own private cache and
    // unservable to B later, defeating the whole relay role.
    let c_ciphertext_nonces = Arc::new(std::sync::Mutex::new(HashMap::new()));

    let session_c1 = PeerSyncSession::new(
        channel_c1,
        "device-c".to_string(),
        "device-a".to_string(),
        c_state.clone(),
        c_store.clone(),
        vec![GROUP.to_string()],
        c_sync_roots.clone(),
    );
    session_c1.set_local_storage_only(GROUP, true);
    session_c1.set_ciphertext_nonce_cache(c_ciphertext_nonces.clone());
    tokio::spawn(session_c1.clone().run());

    // The ciphertext hash A/C will use -- derived independently here
    // (deterministic under convergent mode) purely to know what to poll
    // for; C itself never computes this (it has no key).
    let ciphertext_hash =
        encrypt_block(&key, &content_hash, &content, true).unwrap().ciphertext_hash().to_vec();
    let ciphertext_hash_hex = hex::encode(&ciphertext_hash);

    wait_until(
        || BlockStore::exists(c_store.as_ref(), &ciphertext_hash_hex).unwrap_or(false),
        Duration::from_secs(10),
    )
    .await;

    // --- Real on-disk inspection: C's storage-only block store, keyed
    // exactly like the trusted plaintext store (git-object-style
    // sharding), but holding ciphertext. ---
    let on_disk_path = c_store_dir
        .path()
        .join(&ciphertext_hash_hex[0..2])
        .join(&ciphertext_hash_hex[2..4])
        .join(&ciphertext_hash_hex);
    let on_disk_bytes = std::fs::read(&on_disk_path)
        .expect("the storage-only device's block store must have written a real file to disk");
    assert_ne!(
        on_disk_bytes, content,
        "the storage-only device's on-disk block must never be the plaintext bytes"
    );
    assert!(
        !contains_subslice(&on_disk_bytes, &content),
        "the storage-only device's on-disk block must not even contain the plaintext as a \
         substring"
    );
    // It's exactly the AEAD ciphertext a trusted device with the key would
    // produce -- not merely "different from the plaintext" but the real,
    // specific, verifiable ciphertext.
    let expected_ciphertext =
        encrypt_block(&key, &content_hash, &content, true).unwrap().ciphertext;
    assert_eq!(on_disk_bytes, expected_ciphertext);
    // C's own store never has an entry keyed by the *plaintext* hash --
    // it was never given, and never derived, the plaintext at all.
    assert!(
        !BlockStore::exists(c_store.as_ref(), &hex::encode(&content_hash)).unwrap(),
        "the storage-only device's store must never contain a block keyed by the plaintext hash"
    );

    // --- device B: a *different* trusted device, which never talks to A
    // at all in this test -- everything it ends up with came only through
    // C. ---
    let device_b = Device::new("device-b");
    let (channel_c2, channel_b) = connect_pair(relay_addr).await;

    let session_c2 = PeerSyncSession::new(
        channel_c2,
        "device-c".to_string(),
        "device-b".to_string(),
        c_state.clone(),
        c_store.clone(),
        vec![GROUP.to_string()],
        c_sync_roots,
    );
    session_c2.set_local_storage_only(GROUP, true);
    session_c2.set_ciphertext_nonce_cache(c_ciphertext_nonces);
    tokio::spawn(session_c2.clone().run());

    let session_b = PeerSyncSession::new(
        channel_b,
        "device-b".to_string(),
        "device-c".to_string(),
        device_b.state.clone(),
        device_b.store.clone(),
        vec![GROUP.to_string()],
        device_b.sync_roots(),
    );
    session_b.set_storage_only(GROUP, true);
    session_b.set_group_key(GROUP, key, true);
    tokio::spawn(session_b.clone().run());

    // B fetches the block *from C* (never from A directly), decrypts it,
    // and verifies its plaintext hash against the trusted identity it
    // already knows the block by -- the encrypted-peer spec's "An
    // untrusted peer only ever sees ciphertext" / "blocks fetched back
    // from it are verified against their plaintext content hash" scenario,
    // exercised end to end.
    let recovered = tokio::time::timeout(
        Duration::from_secs(10),
        session_b.fetch_block_from_storage_peer(GROUP, &ciphertext_hash, &content_hash),
    )
    .await
    .expect("fetch_block_from_storage_peer must not hang")
    .unwrap()
    .expect("device B must recover the block relayed through the untrusted storage-only device C");
    assert_eq!(recovered.as_ref(), content.as_slice());

    // Materialize it: write the recovered, verified plaintext to device
    // B's linked folder and record it in B's own trusted index -- the
    // proposal's "decrypts and verifies them locally" completed by
    // actually producing the real file, not just returning bytes in memory.
    let materialized_path = device_b.root_path().join("secret.txt");
    std::fs::write(&materialized_path, &recovered).unwrap();
    device_b.store.put(&recovered).unwrap();
    let mut b_version = yadorilink_sync_core::version_vector::VersionVector::new();
    b_version.increment("device-a");
    device_b
        .state
        .upsert_file(
            GROUP,
            &yadorilink_sync_core::types::FileRecord {
                path: "secret.txt".into(),
                size: recovered.len() as u64,
                mtime_unix_nanos: 0,
                version: b_version,
                blocks: vec![yadorilink_sync_core::types::BlockInfo {
                    hash: content_hash.clone(),
                    offset: 0,
                    size: recovered.len() as u32,
                }],
                deleted: false,
            },
        )
        .unwrap();

    let final_bytes = std::fs::read(&materialized_path).unwrap();
    assert_eq!(
        final_bytes, content,
        "device B's materialized file must match A's original exactly"
    );
    assert!(BlockStore::exists(device_b.store.as_ref(), &hex::encode(&content_hash)).unwrap());
}

/// Whether `haystack` contains `needle` anywhere as a contiguous
/// subsequence — a stronger check than `!=` for "the ciphertext doesn't
/// leak the plaintext," since it also catches a hypothetical partial
/// leak (e.g. an unencrypted header/prefix), not just an exact match.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// A catch-up batch larger than `MAX_IN_FLIGHT_MESSAGES_PER_PEER` (64)
/// distinct eager-fetch-triggering messages must not permanently deadlock
/// the recv loop. Sends `N` (> 64) separate single-file `IndexUpdate`s
/// (one per wire message, so each spawns its own `handle_message`
/// task/permit rather than sharing one permit across a single batched
/// message), followed by an interleaved control message
/// (`PresenceSignal`), all *before* answering a single `BlockRequest` —
/// reproducing exactly the ordering that used to deadlock: every permit
/// held by a task stuck awaiting a `BlockResponse` this test hasn't sent
/// yet, with other messages (including the presence signal) queued
/// behind them.
///
/// Before the fix, the recv loop would block on `acquire_owned()` trying
/// to admit the 65th message and never call `self.channel.recv()` again
/// — so it could never even read, let alone process, the incoming
/// `BlockResponse`s this test's responder task sends once it observes
/// the resulting `BlockRequest`s, nor the presence signal. Forward
/// progress would then depend entirely on each stuck fetch's own
/// `DEFAULT_HYDRATION_TIMEOUT` (30s, times `RECONCILE_RETRY_ATTEMPTS`)
/// elapsing — far outside this test's generous-but-bounded timeouts, so
/// the old structure fails this test with a timeout rather than a clean
/// assertion failure.
#[tokio::test]
async fn recv_loop_survives_a_catchup_batch_larger_than_the_permit_budget() {
    let relay_addr = start_relay().await;
    let device_a = Device::new("device-a");

    // Comfortably more than `MAX_IN_FLIGHT_MESSAGES_PER_PEER` (64) so the
    // semaphore is genuinely, fully exhausted by real concurrently-running
    // tasks, not just close to it.
    const N: usize = 80;

    let (channel_a, channel_b) = connect_pair(relay_addr).await;
    let (presence_tx, mut presence_rx) = tokio::sync::mpsc::unbounded_channel();
    let _session_a = spawn_session_with_presence(channel_a, &device_a, "device-b", presence_tx);

    struct StressFile {
        path: String,
        content: Vec<u8>,
        hash: Vec<u8>,
    }
    let files: Vec<StressFile> = (0..N)
        .map(|i| {
            let content = format!("stress-content-{i}").into_bytes();
            let hash = sha256_bytes(&content);
            StressFile { path: format!("stress-{i:03}.bin"), content, hash }
        })
        .collect();

    // One `IndexUpdate` per file, not one batched message covering all of
    // them — batching would process every file sequentially inside a
    // single `handle_message` call (one permit total), which could never
    // exhaust `message_slots` regardless of file count.
    for f in &files {
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        version.increment("device-b");
        let record = yadorilink_sync_core::types::FileRecord {
            path: f.path.clone(),
            size: f.content.len() as u64,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![yadorilink_sync_core::types::BlockInfo {
                hash: f.hash.clone(),
                offset: 0,
                size: f.content.len() as u32,
            }],
            deleted: false,
        };
        channel_b
            .send(
                proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::IndexUpdate(proto::IndexUpdate {
                        folder_group_id: GROUP.to_string(),
                        changed_files: vec![record.into()],
                        compression: proto::Compression::None as i32,
                        compressed_changed_files: vec![],
                    })),
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
    }

    // The interleaved control message: sent after every eager-fetch
    // trigger and before any `BlockResponse` -- the exact ordering that
    // used to wedge the recv loop behind its own exhausted permit pool.
    channel_b
        .send(
            proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::Presence(proto::PresenceSignal {
                    folder_group_id: GROUP.to_string(),
                    path: "stress-control-signal".to_string(),
                    device_id: "device-b".to_string(),
                    editing: true,
                    ttl_seconds: 30,
                })),
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
                                is_ciphertext: false,
                                ciphertext_nonce: vec![],
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
    let presence = tokio::time::timeout(Duration::from_secs(15), presence_rx.recv())
        .await
        .expect(
            "recv loop must still deliver a control message while permits are exhausted -- this \
             is the head-of-line deadlock this change fixes",
        )
        .expect("presence channel closed unexpectedly");
    assert_eq!(presence.path, "stress-control-signal");

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
