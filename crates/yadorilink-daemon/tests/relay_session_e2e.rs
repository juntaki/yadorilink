//! M3 Pass 5 acceptance: the real, full A(source)->B(relay)->C(destination)
//! wire path -- real `PeerSyncSession`s, real `RelayOpen`/`RelayData`
//! protobuf messages, real `DaemonState`-backed admission (`relay_grant`::
//! `verify_relay_grant` + `relay_session::admit_relay_open`, using B's own
//! REAL netmap-derived group membership/relay-capability and a REAL
//! confirmed direct WireGuard path to C) -- not just `relay_forwarder.rs`'s
//! own unit tests (which drive `RelayForwarder` directly, never touching a
//! `PeerSyncSession` or the wire protocol at all) or `relay_grant.rs`/
//! `relay_session.rs`'s own unit tests (which drive pure functions with
//! synthetic contexts, never live daemon state).
//!
//! **What this file deliberately does NOT prove:** that C's own real
//! WireGuard stack meaningfully processes the relayed bytes -- the relay
//! forwards them opaquely, exactly as this whole mechanism's own design
//! requires (see `relay_forwarder`'s own doc comment), so this file
//! confirms the bytes actually reached the socket bound toward C's REAL
//! confirmed address, not that C's own tunnel decrypted them as valid
//! WireGuard traffic. Making A's own relayed traffic be genuine WireGuard
//! ciphertext C's tunnel actually understands is Pass 6's job (wiring
//! relay in as a real `PeerChannel` transport route), not this
//! "standalone primitive" pass's.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_wire::RelayOpenFrame;
use yadorilink_transport::DeviceKeyPair;

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    keypair: Arc<DeviceKeyPair>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon {
        device_id: device_id.to_string(),
        state,
        keypair: Arc::new(DeviceKeyPair::generate()),
        _root: tempfile::tempdir().unwrap(),
    }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(
    coordination_addr: String,
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
) {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, keypair, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
}

fn fully_connected(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    state
        .peers
        .session(peer_device_id)
        .is_some_and(|s| s.peer_handshake_received() && s.change_dag_negotiated())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn opaque_bytes_flow_from_a_through_b_to_cs_real_address_over_the_real_wire() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-e2e-group";

    let a = new_test_daemon("relay-e2e-a");
    let b = new_test_daemon("relay-e2e-b");
    let c = new_test_daemon("relay-e2e-c");
    for daemon in [&a, &b, &c] {
        register_with_fake(
            &fake,
            &daemon.state,
            &daemon.device_id,
            daemon.keypair.public_bytes(),
            &[group_id],
        )
        .await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    // B is the only relay-capable device -- see `RelayCapability`'s own
    // doc comment for why this is a separate, explicit local declaration
    // (not automatically true of every group member).
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.keypair.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.keypair.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.keypair.clone(), c.state.clone());

    // Both hops the relay needs -- A<->B (the channel `RelayOpen`/
    // `RelayData` travel over) and B<->C (the REAL confirmed direct path
    // B's own admission check requires and forwards toward) -- must be
    // genuine, fully-negotiated WireGuard sessions before the relay
    // protocol exchange below means anything.
    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &c.device_id),
        Duration::from_secs(60),
        || {
            format!(
                "required hops never connected: a<->b={} b<->c={}",
                fully_connected(&a.state, &b.device_id),
                fully_connected(&b.state, &c.device_id),
            )
        },
    )
    .await;

    let grant = fake
        .issue_relay_grant(&a.device_id, &c.device_id, 60)
        .expect("fake coordination should find B as an eligible relay candidate");
    assert_eq!(grant.relay_device_id, b.device_id);

    let session_a_to_b =
        a.state.peers.session(&b.device_id).expect("A must have a live session with B");

    let open = RelayOpenFrame {
        version: grant.version,
        grant_id: grant.grant_id.clone(),
        group_id: grant.group_id.clone(),
        source_device_id: grant.source_device_id.clone(),
        relay_device_id: grant.relay_device_id.clone(),
        destination_device_id: grant.destination_device_id.clone(),
        not_before_unix: grant.not_before_unix,
        expires_at_unix: grant.expires_at_unix,
        max_session_bytes: grant.max_session_bytes.unwrap_or(0),
        signature: grant.signature.clone(),
    };
    session_a_to_b.send_relay_open(open).await.expect("A must be able to send RelayOpen to B");

    // B's REAL admission pipeline (relay_grant::verify_relay_grant ->
    // relay_session::admit_relay_open, using B's own live group
    // membership/relay-capability/direct-route-to-C state) must have
    // admitted this and opened a real forwarder session.
    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 1,
        Duration::from_secs(10),
        || {
            format!(
                "B never admitted the relay session (active_session_count={})",
                b.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;
    let session_id = b
        .state
        .relay_forwarder
        .any_active_session_id()
        .expect("exactly one relay session should be active on B");

    // The actual opaque forward: A -> (RelayData, real wire message) -> B
    // -> (B's own dedicated ephemeral socket) -> C's REAL confirmed
    // address. See this file's own module doc comment for why this test
    // stops at "the bytes reached the socket toward C", not "C understood
    // them".
    let payload = b"opaque WireGuard-shaped bytes, never parsed by B".to_vec();
    session_a_to_b.send_relay_data(session_id, payload.clone());

    wait_until_with_context(
        || {
            b.state.relay_forwarder.session_bytes_forwarded(session_id)
                >= Some(payload.len() as u64)
        },
        Duration::from_secs(10),
        || {
            format!(
                "B never forwarded A's relayed bytes toward C (bytes_forwarded={:?}, expected>={})",
                b.state.relay_forwarder.session_bytes_forwarded(session_id),
                payload.len()
            )
        },
    )
    .await;

    // Full lifecycle: A closing the session must actually close it on B.
    session_a_to_b.send_relay_close(session_id, "test_complete");
    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 0,
        Duration::from_secs(10),
        || "B never closed the relay session after RelayClose".to_string(),
    )
    .await;
}

/// Security-boundary regression: a device NOT declared relay-capable must
/// have its `RelayOpen` refused, even with an otherwise-perfectly-valid
/// signed grant (a real coordination-plane bug or a compromised plane
/// issuing a grant naming a non-opted-in device) -- `relay_session::
/// admit_relay_open`'s own `RelayNotCapable` check, exercised here over
/// the real wire rather than only in that module's own synthetic-context
/// unit test.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn relay_open_is_refused_when_the_relay_never_declared_capability() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-e2e-refusal-group";

    let a = new_test_daemon("relay-e2e-refusal-a");
    let b = new_test_daemon("relay-e2e-refusal-b");
    let c = new_test_daemon("relay-e2e-refusal-c");
    for daemon in [&a, &b, &c] {
        register_with_fake(
            &fake,
            &daemon.state,
            &daemon.device_id,
            daemon.keypair.public_bytes(),
            &[group_id],
        )
        .await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    // Deliberately NOT called: b.state.set_local_relay_capable(true) /
    // fake.set_relay_capable(&b.device_id, true).

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.keypair.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.keypair.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.keypair.clone(), c.state.clone());

    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &c.device_id),
        Duration::from_secs(60),
        || "required hops never connected".to_string(),
    )
    .await;

    // `issue_relay_grant` itself would correctly find no eligible relay
    // (matching real coordination behavior) -- this test instead
    // constructs the grant DIRECTLY, simulating a plane that (bug, or
    // compromise) issued one anyway, so it's B's own independent
    // admission check under test here, not the fake's own candidate
    // search.
    let signing_key = fake.policy_signing_key().expect("signed policy must be enabled");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let grant = yadorilink_daemon::relay_grant::sign_relay_grant(
        yadorilink_daemon::relay_grant::RelayGrant {
            version: 1,
            grant_id: "refused-grant-1".to_string(),
            group_id: group_id.to_string(),
            source_device_id: a.device_id.clone(),
            relay_device_id: b.device_id.clone(),
            destination_device_id: c.device_id.clone(),
            not_before_unix: now - 5,
            expires_at_unix: now + 60,
            max_session_bytes: None,
            signature: Vec::new(),
        },
        &signing_key,
    );

    let session_a_to_b = a.state.peers.session(&b.device_id).unwrap();
    session_a_to_b
        .send_relay_open(RelayOpenFrame {
            version: grant.version,
            grant_id: grant.grant_id.clone(),
            group_id: grant.group_id.clone(),
            source_device_id: grant.source_device_id.clone(),
            relay_device_id: grant.relay_device_id.clone(),
            destination_device_id: grant.destination_device_id.clone(),
            not_before_unix: grant.not_before_unix,
            expires_at_unix: grant.expires_at_unix,
            max_session_bytes: grant.max_session_bytes.unwrap_or(0),
            signature: grant.signature.clone(),
        })
        .await
        .unwrap();

    // Give B's real dispatch pipeline a bounded window to (wrongly, if
    // this regression fired) admit the session, then assert it never did.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        b.state.relay_forwarder.active_session_count(),
        0,
        "a RelayOpen for a relay that never declared RelayCapability::Capable must never be admitted"
    );
}
