//! Network-fault scenarios, distinct from `chaos_coordination_unreachable.
//! rs`'s single existing case (an *already-established* peer session
//! surviving a coordination outage) and from `partition_reconnect_matrix.
//! rs`'s *application-level* pause/resume (`SyncState::set_paused`, never
//! touching real sockets). Every scenario here severs or restarts a real
//! network listener (coordination and/or relay) mid-test, matching this
//! session's own finding that a device's *first* connection attempt (a
//! "join") racing a control-plane outage is a real, production-relevant
//! timing class of bug, not just a test artifact -- see this file's
//! scenario 1.
//!
//! `TestDevice`/`setup_device`/`start_syncing` are intentionally
//! duplicated from `collision_matrix.rs`/`taguchi_collision_matrix.rs`
//! rather than shared -- matches this codebase's existing convention of
//! self-contained daemon integration test binaries.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use support::{open_file_backed_sync_state, wait_until, wait_until_with_context, TestAccount};
use yadorilink_coordination::db::Db;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::{link_manager, peer_orchestrator};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_transport::DeviceKeyPair;

struct TestDevice {
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // daemon-concurrency-tests-file-backed-wal: file-backed WAL (production's
    // concurrency model) instead of open_in_memory's shared-cache backend —
    // see open_file_backed_sync_state's doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let keypair = Arc::new(DeviceKeyPair::generate());
    let device_id = support::register_device(account, name, keypair.public_bytes()).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_sync_state();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    TestDevice {
        device_id,
        keypair,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_syncing(
    device: &TestDevice,
    coordination_addr: String,
    relay_addr: SocketAddr,
    access_token: String,
    group_id: &str,
) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.sync_state.add_link(&local_path, group_id).unwrap();
    link_manager::start_link_watch(device.state.clone(), local_path, group_id.to_string()).unwrap();

    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        relay_addr,
        access_token,
        device_id: device.device_id.clone(),
    };
    let keypair = device.keypair.clone();
    let state = device.state.clone();
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, keypair, state).await;
    });
}

// --- Scenario 1: a device's first-ever join races a coordination outage --

/// Directly exercises the production concern this session's row-8
/// investigation raised: is a device's very first connection attempt (a
/// "join," never yet successfully paired) resilient to the coordination
/// plane being briefly unreachable at exactly that moment, the same way
/// `chaos_coordination_unreachable.rs` already confirms an
/// *already-established* session survives a *later* outage? A device
/// that only ever backs off and retries (this test's own timeout is well
/// past several retry/backoff cycles) rather than giving up permanently
/// is the minimum bar; a real "warm up read-only, then go live" staged
/// join (as briefly discussed for the row-8 finding) would be a stronger,
/// but materially larger, follow-up on top of this passing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_join_during_coordination_outage_recovers_once_restored() {
    let db = Arc::new(Db::open_in_memory().unwrap());
    let (coordination_addr, coordination_handle) =
        support::start_coordination_server_with_db(db.clone(), "127.0.0.1:0".parse().unwrap())
            .await;
    let bind_addr: SocketAddr = coordination_addr
        .trim_start_matches("http://")
        .parse()
        .expect("coordination address is host:port");
    let relay_addr = support::start_relay_server().await;
    let account =
        support::register_and_login(&coordination_addr, "join-during-outage@example.com").await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "join-outage-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    // Device A joins normally, while coordination is healthy, and confirms
    // it can already see the (as yet empty) shared folder.
    start_syncing(
        &device_a,
        coordination_addr.clone(),
        relay_addr,
        account.access_token.clone(),
        &group_id,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Take coordination down *before* device B ever makes its first
    // connection attempt -- its very first `StreamNetmap` call (and, in
    // the real HTTP-coordination build, its first netmap-subscribe
    // handshake) hits a dead listener, not merely a later disconnect.
    coordination_handle.abort();
    wait_until(
        || std::net::TcpStream::connect_timeout(&bind_addr, Duration::from_millis(200)).is_err(),
        Duration::from_secs(5),
    )
    .await;

    start_syncing(
        &device_b,
        coordination_addr.clone(),
        relay_addr,
        account.access_token.clone(),
        &group_id,
    )
    .await;
    // Long enough to observe several of `peer_orchestrator`'s own
    // exponential-backoff reconnect attempts (visible in its `waiting
    // before next coordination reconnect attempt` debug logs) fail against
    // the still-down listener, without yet restoring it -- this is the
    // heart of the scenario: a join attempt genuinely racing a real outage,
    // not a join that merely happens sometime after one already ended.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Restore coordination against the *same* `Db` (device A/B's
    // registrations, the folder group, and both grants all still exist)
    // and, if the exact same port is still free, the same address too --
    // from a client's perspective this is indistinguishable from any other
    // coordination restart.
    let (restored_addr, _restored_handle) =
        support::start_coordination_server_with_db(db, bind_addr).await;
    assert_eq!(
        restored_addr, coordination_addr,
        "coordination did not come back on the same address; device B's already-configured \
         OrchestratorConfig would need updating to observe recovery, which this scenario \
         doesn't exercise"
    );

    std::fs::write(device_a.root.path().join("after-recovery.txt"), b"joined after outage cleared")
        .unwrap();
    wait_until_with_context(
        || device_b.root.path().join("after-recovery.txt").exists(),
        Duration::from_secs(30),
        || format!("device-b names={:?}", support::real_entry_names(device_b.root.path())),
    )
    .await;
    assert_eq!(
        std::fs::read(device_b.root.path().join("after-recovery.txt")).unwrap(),
        b"joined after outage cleared"
    );
}

// --- Scenario 2: relay outage severs an active session; recovery resumes -

/// Unlike coordination (only needed for discovery/handshake/ACL changes),
/// traffic between two devices that can't connect directly flows *through*
/// the relay for the whole session -- dropping it is a meaningfully
/// different, more severe fault than a coordination outage: it severs an
/// already-established peer session outright, not just blocks new
/// pairings. This scenario checks whether `peer_orchestrator`'s reconnect
/// loop actually recovers, since `RelayHub::connect`'s result is cached in
/// a `OnceCell` (`relay_hub_cell`) that a transient connect *error* leaves
/// uninitialized for the next attempt to retry -- but does NOT itself
/// re-validate an already-`Some` cached hub whose underlying connection
/// has since died out from under it, which is a real, open question this
/// test exists to answer empirically rather than assume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_outage_then_recovery_resumes_sync() {
    let coordination_addr = support::start_coordination_server().await;
    let (relay_addr, relay_handle) = support::start_relay_server_stoppable().await;
    let account = support::register_and_login(&coordination_addr, "relay-outage@example.com").await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "relay-outage-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    for device in [&device_a, &device_b] {
        start_syncing(
            device,
            coordination_addr.clone(),
            relay_addr,
            account.access_token.clone(),
            &group_id,
        )
        .await;
    }

    // Establish and confirm a real session before the outage, same
    // reasoning as `chaos_coordination_unreachable.rs`'s own first step.
    std::fs::write(device_a.root.path().join("before-outage.txt"), b"synced while healthy")
        .unwrap();
    wait_until(|| device_b.root.path().join("before-outage.txt").exists(), Duration::from_secs(20))
        .await;

    relay_handle.abort();
    wait_until(
        || std::net::TcpStream::connect_timeout(&relay_addr, Duration::from_millis(200)).is_err(),
        Duration::from_secs(5),
    )
    .await;

    // A write during the outage: with the relay actually down, this sits
    // unsynced until the relay comes back (and `peer_orchestrator` notices
    // and re-establishes) -- deliberately not asserted on yet, since
    // asserting "not synced during an outage" would itself be racy
    // (nothing prevents it from finishing in the brief moment before
    // `abort()` above actually took effect).
    std::fs::write(device_a.root.path().join("during-outage.txt"), b"written while relay down")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Restart the relay on the *exact same* address -- from an already-
    // running device's point of view, indistinguishable from any other
    // relay restart (a fresh process picking up where the last one left
    // off), never requiring a coordination-driven endpoint-candidate
    // refresh to notice.
    let (restored_addr, _restored_handle) = support::start_relay_server_at(relay_addr).await;
    assert_eq!(
        restored_addr, relay_addr,
        "relay did not come back on the same address; device A/B's already-configured \
         RelayHub would need a fresh endpoint candidate to recover, which this scenario \
         doesn't exercise"
    );

    wait_until_with_context(
        || device_b.root.path().join("during-outage.txt").exists(),
        Duration::from_secs(30),
        || format!("device-b names={:?}", support::real_entry_names(device_b.root.path())),
    )
    .await;
    assert_eq!(
        std::fs::read(device_b.root.path().join("during-outage.txt")).unwrap(),
        b"written while relay down"
    );

    // The recovered session must also work in the other direction, not
    // just "device A's already-queued backlog eventually drains" --
    // confirms this is a genuinely live, bidirectional session again, not
    // a one-shot artifact of whatever state happened to be pending at the
    // moment of recovery.
    std::fs::write(device_b.root.path().join("after-recovery-from-b.txt"), b"b syncs again too")
        .unwrap();
    wait_until(
        || device_a.root.path().join("after-recovery-from-b.txt").exists(),
        Duration::from_secs(20),
    )
    .await;
}
