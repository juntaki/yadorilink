//! A daemon-restart integration test proving a local change already
//! committed to this device's `ReplicaCoordinator` (as it would be by
//! `LocalChangeProcessor` processing a real filesystem event) but never
//! yet broadcast to a connected peer — exactly what a crash right after
//! the DB commit but before the outbound `IndexUpdate`/broadcast would
//! leave behind — is durably re-offered to that peer, and re-admitted onto
//! its own DAG, once this device reconnects after "restarting", with no
//! separate persisted retry queue needed. This lives in its own
//! integration-test binary (new file, no edits to the existing
//! `tests/peer_session.rs`) specifically so it can be developed and run
//! independently of that file's own concurrent, unrelated in-flight
//! changes — it duplicates a small slice of that file's test harness
//! (`spawn_session`) rather than sharing code with it, deliberately, for
//! the same reason. The mechanism this proves already exists and needed no
//! new production code: reconciliation compares the two devices' durable
//! sets whenever they connect, independent of whatever the previous session
//! for the same peer did or didn't manage to send before it died. Combined with `yadorilink-daemon::main`'s startup resuming every
//! link's watcher (a full `scan_existing_files` rescan, which
//! independently catches any change made while the daemon was down
//! entirely), this is what closes the "pending local changes are retried
//! after restart" gap — this test is what turns that into a verified
//! guarantee instead of an assumption. Verifying THAT end-to-end belongs
//! in a `yadorilink-daemon` integration test that runs the real engine --
//! not simulated here via a single manually driven
//! `reconcile_local_materialization_audit` call, which can itself silently
//! swallow an internal projection failure and still report success.
//! `admit_change` refusing to admit a change whose referenced
//! `FileVersion` is missing (re-requesting it instead) is what makes
//! `dag_get_change` succeeding here already strong evidence both the
//! change and its content crossed, without needing to wait on
//! materialization at all.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};

use yadorilink_daemon::test_support::peer_session_fixture::dag_wire_support::{
    pinned_authenticator, DagProducer,
};

const GROUP: &str = "shared-photos";

/// A persistent device identity: state and block store survive across a
/// simulated crash/restart (only the `PeerSyncSession` pair
/// gets torn down and rebuilt), exactly as a real daemon's on-disk SQLite
/// DB and block store survive a process kill.
struct Device {
    device_id: String,
    root: tempfile::TempDir,
    store: Arc<SegmentBlockStore>,
    state: Arc<ReplicaCoordinator>,
    /// Held, not dropped: the store keeps its index and segments open in
    /// this directory for as long as the device lives.
    _store_dir: tempfile::TempDir,
    signing_key: SigningKey,
    block_serve_engine: Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
}

impl Device {
    fn new(device_id: &str) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // Link `GROUP` at this device's root and declare its startup finished —
        // the only state a real daemon presents to a peer session. Sync roots
        // are derived from the link table in production
        // (`sync_roots_for_groups` reads `list_links`), the apply path re-reads
        // that table for every write it makes, and `wait_group_ready` defers a
        // batch for a live link whose startup never registered a gate. The
        // daemon's link manager supplies both; these tests have no link
        // manager, so stand in for it.
        state.link_repository().add_link(&root.path().to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        Device {
            device_id: device_id.to_string(),
            root,
            store: Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap()),
            _store_dir: store_dir,
            state,
            signing_key: SigningKey::from_bytes(&[device_id.as_bytes()[device_id.len() - 1]; 32]),
            // Without this, every block request this device receives is
            // answered Rejected("source has no serving engine installed")
            // -- there is no more legacy direct-serve fallback for a
            // session with no engine set. A generous, effectively
            // unlimited engine here since this test isn't exercising
            // stage-2 credit/fairness behavior.
            block_serve_engine: yadorilink_peer_session::block_serve::BlockServeEngine::new(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                64,
            ),
        }
    }

    fn sync_roots(&self) -> std::collections::HashMap<String, std::path::PathBuf> {
        std::collections::HashMap::from([(GROUP.to_string(), self.root.path().to_path_buf())])
    }
}

async fn spawn_session(device: &Device, peer_device_id: &str) -> Arc<PeerSyncSession> {
    // `SessionTransports` is a required `PeerSyncSession` constructor
    // parameter now (A3/A4): a real substrate-backed pair, independent per
    // reconnect (like the real substrate connection production would
    // establish fresh each time) rather than shared across this test's two
    // successive `spawn_session` calls for the same device pair.
    let book = yadorilink_lane_ports::testing::TestAddressBook::new();
    let node_local =
        yadorilink_lane_ports::testing::TestPeerNode::start(&device.device_id, book.clone()).await;
    let _node_peer =
        yadorilink_lane_ports::testing::TestPeerNode::start(peer_device_id, book).await;
    let transports_local = node_local.transports_for(peer_device_id);
    let transports = yadorilink_peer_session::ports::SessionTransports {
        blocks: transports_local.clone(),
        service: transports_local.clone(),
        prepared_snapshots: Arc::new(yadorilink_lane_ports::PreparedSnapshots::new()),
        snapshot_fetch: transports_local,
    };
    let replica_engine =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &device.state,
            device.store.clone(),
        );
    let session = PeerSyncSession::over_substrate(
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        device.store.clone(),
        vec![GROUP.to_string()],
        device.sync_roots(),
        transports,
        None,
        PeerSyncSessionDeps {
            change_authenticator: pinned_authenticator(&[(
                peer_device_id,
                &SigningKey::from_bytes(&[peer_device_id.as_bytes()[peer_device_id.len() - 1]; 32]),
            )]),
            ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
        },
    );
    session.set_block_serve_engine(device.block_serve_engine.clone());
    session
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

/// the core restart-retry scenario. Device A commits a local
/// change directly to its own `ReplicaCoordinator`/block store/disk — simulating
/// exactly what `LocalChangeProcessor` would have already durably done
/// for a real filesystem event — but its first session with device B is
/// torn down (simulating a crash) before anything ever broadcasts that
/// change over the wire. A fresh session for the same two persistent
/// device identities (device B's state/store are also untouched by the
/// "crash", exactly like a peer that stayed running throughout) must
/// still deliver and admit it: device B's own DAG ends up with the
/// pre-crash change even though it was never told about it before the
/// "restart" -- see this module's own doc comment for why disk
/// materialization is deliberately out of scope here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_change_committed_before_a_crash_is_reoffered_and_admitted_on_reconnect() {
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // --- "pre-crash" session pair, up before any local edit happens. ---
    let session_a1 = spawn_session(&device_a, "device-b").await;
    let session_b1 = spawn_session(&device_b, "device-a").await;

    // Device A's local change: committed to its index and written to disk
    // and its block store — everything a real watcher-driven local change
    // would have already durably done — but note nothing here ever calls
    // any send/broadcast method on `session_a1`. This is the exact
    // "committed but never broadcast" state a crash immediately after the
    // DB commit would leave behind.
    let content = b"a change made just before the crash".to_vec();
    std::fs::write(device_a.root.path().join("new-file.txt"), &content).unwrap();
    let producer = DagProducer::new(
        device_a.state.clone(),
        device_a.store.clone(),
        &device_a.device_id,
        device_a.signing_key.clone(),
    );
    // The returned `FileVersion` itself isn't needed: this test's own scope
    // is durable DAG delivery, not disk materialization (see the reconnect
    // wait below) -- the version's content is verified structurally via
    // the admitted `Change`'s own hash instead.
    let _committed = producer.commit_create(GROUP, "new-file.txt", &content, 0);
    // A local commit is Pending (no authorization evidence) until
    // published; only a Published change is eligible for
    // `send_change_batch` to pick up over the real reconnect wire path this
    // test drives below -- see `DagProducer::publish_pending`'s own doc
    // comment.
    producer.publish_pending(GROUP);

    // Confirm the peer genuinely never received it pre-crash (the
    // baseline this test would otherwise be trivially true against).
    assert!(
        device_b.state.file_index_repository().get_file(GROUP, "new-file.txt").unwrap().is_none(),
        "sanity check: peer must not already have the file before the crash"
    );

    // --- simulate the crash: drop both sessions, exactly as a killed
    // daemon process would drop every in-memory connection while leaving
    // `device_a`/`device_b`'s ReplicaCoordinator and block store (their
    // on-disk, persisted state) untouched. ---
    drop(session_a1);
    drop(session_b1);

    // --- simulate the restart: a fresh session pair for the same two
    // persistent device identities, as `yadorilink-daemon::main` would
    // build on the next process start (new `PeerSyncSession`s wrapping
    // the same, restart-surviving `ReplicaCoordinator`/`SegmentBlockStore`). ---
    let _session_a2 = spawn_session(&device_a, "device-b").await;
    let _session_b2 = spawn_session(&device_b, "device-a").await;

    let committed_head =
        device_a.state.sqlite().dag_group_heads(GROUP).unwrap().into_iter().next().unwrap();

    // The device-local bookkeeping the local-change pipeline does for a
    // commit, which `DaemonState::note_local_commit_for_group` owns: record
    // this device's own published frontier. (It also raises the retirement
    // and hazard wakes, which have no consumer in this test -- neither loop
    // runs here.) Spelled out rather than borrowed from a session method:
    // none of it is per-peer, so no session is the owner of it.
    {
        use yadorilink_replica_engine::ports::{FrontierStorePort, ReplicaHistoryPort};
        let group = yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_string());
        let sqlite = device_a.state.sqlite();
        let heads = ReplicaHistoryPort::group_heads(sqlite, &group).unwrap();
        FrontierStorePort::record_acknowledged_frontier(
            sqlite,
            &group,
            &yadorilink_replica_domain::ids::DeviceId(device_a.device_id.clone()),
            &heads,
        )
        .unwrap();
    }

    // Changes cross by reconciliation, not by the session pair above, so the
    // restarted devices need their stacks back — which is exactly what a
    // restarted daemon does. Built on the same `ReplicaCoordinator` and block
    // store the crash left untouched, so what is being tested is that a
    // locally authored and published Change survives its author's restart and
    // is still servable afterwards.
    let stack_b = stand_up_reconciliation(&device_a, &device_b).await;
    stack_b
        .sync_with(
            &device_a.device_id,
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_string()),
        )
        .await
        .expect("the reconciliation must not error");

    // This test's own scope ends at durable DAG delivery -- the
    // reconnect's post-negotiation frontier announce re-offering the
    // pre-crash change, and device B admitting it (which requires the
    // change's referenced `FileVersion` to have been received and stored
    // too, not just the change envelope itself -- `admit_change` refuses
    // to admit a change whose referenced version is missing and
    // re-requests it instead, so reaching `dag_get_change` succeeding here
    // is already strong evidence both crossed).
    wait_until(
        || device_b.state.sqlite().dag_get_change(&committed_head).ok().flatten().is_some(),
        std::time::Duration::from_secs(10),
    )
    .await;

    let received_change = device_b
        .state
        .sqlite()
        .dag_get_change(&committed_head)
        .unwrap()
        .expect("pre-crash local change must be re-delivered after reconnect");
    assert_eq!(received_change.compute_hash(), committed_head);
}

/// Stands both devices' reconciliation stacks back up after the simulated
/// restart, and returns the receiving side's.
///
/// A `DaemonState` per device over the same `ReplicaCoordinator` and block
/// store the crash left on disk — the daemon-level wrapper a restarted
/// process would rebuild around exactly that surviving state. The netmap
/// facts are set by hand here because there is no coordination plane in this
/// test: each side pins the other's signing key, grants it the group, and is
/// told where it lives.
async fn stand_up_reconciliation(
    author: &Device,
    receiver: &Device,
) -> Arc<yadorilink_daemon::sync_adapter::SyncStack> {
    use yadorilink_daemon::daemon_state::DaemonState;

    let daemon_for = |device: &Device| {
        let state =
            DaemonState::new(device.device_id.clone(), device.state.clone(), device.store.clone());
        state.set_device_signing_key(device.signing_key.clone());
        state.authority.install_test_group_policy_bootstrap(GROUP);
        state
    };
    let daemon_a = daemon_for(author);
    let daemon_b = daemon_for(receiver);

    for (local, peer) in [(&daemon_a, receiver), (&daemon_b, author)] {
        local.record_peer_signing_key(&peer.device_id, peer.signing_key.verifying_key().to_bytes());
        local.set_peer_group_writer(&peer.device_id, GROUP, true);
    }

    let authenticator = pinned_authenticator(&[
        (author.device_id.as_str(), &author.signing_key),
        (receiver.device_id.as_str(), &receiver.signing_key),
    ]);

    let stack_a = Arc::new(
        yadorilink_daemon::sync_adapter::SyncStack::spawn(
            daemon_a.clone(),
            authenticator.clone(),
            yadorilink_daemon::sync_adapter::NetworkConfig::direct_only(),
        )
        .await
        .expect("the author's stack starts"),
    );
    let stack_b = Arc::new(
        yadorilink_daemon::sync_adapter::SyncStack::spawn(
            daemon_b.clone(),
            authenticator,
            yadorilink_daemon::sync_adapter::NetworkConfig::direct_only(),
        )
        .await
        .expect("the receiver's stack starts"),
    );

    // Into each other's substrate address directory, which is what
    // reconciliation's dial consults. This fixture used to fill
    // `record_peer_candidate_addresses` instead -- the LEGACY peer-session
    // transport's list, which no longer reaches reconciliation at all: the
    // two transports listen on different sockets under different ALPNs. The
    // addresses were there (11 direct each, measured), simply filed where
    // nothing asks, so the dial below had no addressing information for a
    // peer running on this same host.
    yadorilink_daemon::sync_adapter::SyncStack::teach_each_other_for_tests(&stack_a, &stack_b);

    // Held for the rest of the test: dropping either would close its endpoint.
    daemon_a.install_reconciliation_driver(
        yadorilink_daemon::sync_adapter::ReconciliationDriver::start(daemon_a.clone(), stack_a),
    );
    daemon_b.install_reconciliation_driver(
        yadorilink_daemon::sync_adapter::ReconciliationDriver::start(
            daemon_b.clone(),
            stack_b.clone(),
        ),
    );
    std::mem::forget((daemon_a, daemon_b));

    stack_b
}
