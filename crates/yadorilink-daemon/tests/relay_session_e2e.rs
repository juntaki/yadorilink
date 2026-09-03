//! M3 Pass 5 acceptance: the real, full A(source)->B(relay)->C(destination)
//! wire path -- real `PeerSyncSession`s, real `RelayOpen`/`RelayData`
//! protobuf messages, real `DaemonState`-backed admission (`relay_grant`::
//! `verify_relay_grant` + `relay_session::admit_relay_open`, using B's own
//! REAL netmap-derived group membership/relay-capability and a REAL
//! confirmed direct QUIC path to C) -- not just `relay_forwarder.rs`'s
//! own unit tests (which drive `RelayForwarder` directly, never touching a
//! `PeerSyncSession` or the wire protocol at all) or `relay_grant.rs`/
//! `relay_session.rs`'s own unit tests (which drive pure functions with
//! synthetic contexts, never live daemon state).
//!
//! **What this file deliberately does NOT prove:** that C's own real
//! QUIC connection meaningfully processes the relayed bytes -- the relay
//! forwards them opaquely, exactly as this whole mechanism's own design
//! requires (see `relay_forwarder`'s own doc comment), so this file
//! confirms the bytes actually reached the socket bound toward C's REAL
//! confirmed address, not that C's own connection decrypted them as
//! valid QUIC traffic. Making A's own relayed traffic be genuine QUIC
//! ciphertext C's connection actually understands is Pass 6's job (wiring
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

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { device_id: device_id.to_string(), state, _root: tempfile::tempdir().unwrap() }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
}

fn fully_connected(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    state.peers.session(peer_device_id).is_some_and(|s| s.peer_handshake_received())
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
        register_with_fake(&fake, &daemon.state, &daemon.device_id, &[group_id]).await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    // B is the only relay-capable device -- see `RelayCapability`'s own
    // doc comment for why this is a separate, explicit local declaration
    // (not automatically true of every group member).
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.state.clone());

    // Both hops the relay needs -- A<->B (the channel `RelayOpen`/
    // `RelayData` travel over) and B<->C (the REAL confirmed direct path
    // B's own admission check requires and forwards toward) -- must be
    // genuine, fully-negotiated QUIC sessions before the relay
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
    let payload = b"opaque QUIC-shaped bytes, never parsed by B".to_vec();
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

/// The requester ("A") side of the relay protocol, driven exactly the way
/// the connection supervisor drives it -- pick B as a relay candidate,
/// obtain a grant, open a path, and send -- over the SAME real
/// orchestrator-managed sessions and sockets the rest of this file already
/// proves the wire protocol and B's admission pipeline work over.
/// `opaque_bytes_flow_from_a_through_b_to_cs_real_address_over_the_real_
/// wire` above proves the provider ("B") side; together they cover the full
/// A<->B<->C round trip.
///
/// Opens the path directly rather than forcing A's real direct route to C
/// to fail, so what is under test is the requester mechanism itself:
/// candidate selection, grant issuance, admission, and forwarding.
/// `topology_relay_failover.rs` covers the natural trigger, and
/// `relay_path_quic.rs` covers a real QUIC connection running over the
/// resulting path.
struct TestGrantSource {
    fake: FakeCoordination,
    source_device_id: String,
}

impl yadorilink_daemon::relay_carrier::RelayGrantSource for TestGrantSource {
    fn request_relay_grant<'a>(
        &'a self,
        destination_device_id: &'a str,
        _relay_device_id: &'a str,
        _group_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<yadorilink_daemon::relay_grant::RelayGrant>>
                + Send
                + 'a,
        >,
    > {
        let grant = self.fake.issue_relay_grant(&self.source_device_id, destination_device_id, 60);
        Box::pin(async move { grant })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn requester_relay_carrier_opens_a_session_and_forwards_via_a_real_relay() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-carrier-e2e-group";

    let a = new_test_daemon("relay-carrier-a");
    let b = new_test_daemon("relay-carrier-b");
    let c = new_test_daemon("relay-carrier-c");
    for daemon in [&a, &b, &c] {
        register_with_fake(&fake, &daemon.state, &daemon.device_id, &[group_id]).await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.state.clone());

    // A<->B (what `RelayOpen`/`RelayData` travel over) and B<->C (what
    // B's admission requires and forwards toward) must both be real,
    // fully-negotiated sessions first -- same precondition as this
    // file's provider-side test above.
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

    a.state.set_relay_grant_source(Arc::new(TestGrantSource {
        fake: fake.clone(),
        source_device_id: a.device_id.clone(),
    }));

    // The peer key the relay layer routes by is C's Ed25519 device key --
    // a device has one key, and it is the one that authenticated C's
    // connection.
    let c_peer_public =
        c.state.device_signing_key().expect("C has a device key").verifying_key().to_bytes();
    // Shaped like a QUIC long-header packet (the fixed bit set in byte 0)
    // because that is what a relay path carries and what the destination's
    // demux requires of anything it will route to one. Opaque to B either
    // way -- it never looks at a payload.
    let mut payload = vec![0xC0u8];
    payload.extend_from_slice(b"real relay-path payload, opaque to B");
    let opened = yadorilink_daemon::relay_carrier::open_relay_path_for_test(
        &a.state,
        &c.device_id,
        &c_peer_public,
    )
    .await
    .expect("opening a relay path should have found B, obtained a grant, and been admitted");
    let hub = a.state.shared_socket().expect("A has a bound transport hub");
    hub.try_send_datagram(&payload, opened.path.synthetic_addr())
        .expect("A's hub accepts a datagram addressed to a live relay path");

    // The exact same admission/forwarding pipeline the provider-side test
    // above already proves in detail -- here just confirming THIS attempt
    // actually reached it, driven from the requester's own send_via_relay
    // rather than a hand-built RelayOpenFrame.
    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 1,
        Duration::from_secs(10),
        || {
            format!(
                "B never admitted the requester-opened relay session (active_session_count={})",
                b.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;
    let session_id = b.state.relay_forwarder.any_active_session_id().unwrap();
    wait_until_with_context(
        || {
            b.state.relay_forwarder.session_bytes_forwarded(session_id)
                >= Some(payload.len() as u64)
        },
        Duration::from_secs(10),
        || {
            format!(
                "B never forwarded A's requester-opened payload toward C (bytes_forwarded={:?}, \
                 expected>={})",
                b.state.relay_forwarder.session_bytes_forwarded(session_id),
                payload.len()
            )
        },
    )
    .await;

    // A relay path is a path, so every datagram addressed to it rides the
    // one session it opened -- a second send must not conjure a second
    // session on B, which would double the slots this pair occupies on a
    // device whose slots are a bounded resource it lends out.
    let mut second_payload = vec![0xC0u8];
    second_payload.extend_from_slice(b"second payload on the same relay path");
    hub.try_send_datagram(&second_payload, opened.path.synthetic_addr())
        .expect("A's hub accepts a second datagram on the same relay path");
    assert_eq!(
        b.state.relay_forwarder.active_session_count(),
        1,
        "a second datagram on the same path must ride the existing session, not open another"
    );
    wait_until_with_context(
        || {
            b.state.relay_forwarder.session_bytes_forwarded(session_id)
                >= Some((payload.len() + second_payload.len()) as u64)
        },
        Duration::from_secs(10),
        || "B never forwarded the second payload on the same relay path".to_string(),
    )
    .await;

    // Dropping the handle is what closes the path -- a relay route cannot
    // outlive the bookkeeping that describes it.
    drop(opened);
}

/// Cleanup regression: when B's own direct route to the DESTINATION is
/// lost (here, a netmap revoke tearing down B<->C), any relay session B
/// was forwarding toward it must close PROMPTLY -- not merely eventually
/// via the forwarder's own 60s idle timeout, which this test's own bound
/// (well under that) would catch a regression back to.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn relay_session_closes_promptly_when_the_destination_route_is_lost() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-e2e-route-loss-group";

    let a = new_test_daemon("relay-e2e-loss-a");
    let b = new_test_daemon("relay-e2e-loss-b");
    let c = new_test_daemon("relay-e2e-loss-c");
    for daemon in [&a, &b, &c] {
        register_with_fake(&fake, &daemon.state, &daemon.device_id, &[group_id]).await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.state.clone());

    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &c.device_id),
        Duration::from_secs(60),
        || "required hops never connected".to_string(),
    )
    .await;

    let grant = fake.issue_relay_grant(&a.device_id, &c.device_id, 120).unwrap();
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

    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 1,
        Duration::from_secs(10),
        || "B never admitted the relay session".to_string(),
    )
    .await;

    // B<->C's direct route goes away -- not A's own request, not an idle
    // timeout, not grant expiry: purely the destination becoming
    // unreachable out from under an already-open relay session.
    fake.revoke(&c.device_id, group_id);

    // Well under `RELAY_IDLE_TIMEOUT` (60s) -- if this regresses back to
    // "only the idle timeout ever closes it", this bound catches that.
    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 0,
        Duration::from_secs(15),
        || {
            format!(
                "relay session was not closed promptly after B's route to the destination was \
                 lost (active_session_count={})",
                b.state.relay_forwarder.active_session_count()
            )
        },
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
        register_with_fake(&fake, &daemon.state, &daemon.device_id, &[group_id]).await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    // Deliberately NOT called: b.state.set_local_relay_capable(true) /
    // fake.set_relay_capable(&b.device_id, true).

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.state.clone());

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
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
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

/// Independent-review finding H2, exactly as specified: revoking the
/// destination's membership in the grant's OWN group must close the
/// relay session PROMPTLY, even though B<->C's underlying channel stays
/// alive the whole time via a SECOND shared group they never lose --
/// proving the session closes because `revalidate_relay_session` (run on
/// every datagram, not just at open) actually re-checks group membership,
/// not merely because the channel itself happened to tear down.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn relay_session_closes_on_stale_group_authorization_while_the_channel_stays_alive() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_relay = "relay-e2e-h2-relay-group";
    let group_keepalive = "relay-e2e-h2-keepalive-group";

    let a = new_test_daemon("relay-e2e-h2-a");
    let b = new_test_daemon("relay-e2e-h2-b");
    let c = new_test_daemon("relay-e2e-h2-c");
    // Kept alive for the test's duration -- each device needs a SEPARATE
    // local root per group it links.
    let mut keepalive_roots = Vec::new();
    for daemon in [&a, &b, &c] {
        register_with_fake(
            &fake,
            &daemon.state,
            &daemon.device_id,
            &[group_relay, group_keepalive],
        )
        .await;
        link(&daemon.state, daemon._root.path(), group_relay);
        // `issue_relay_grant`'s own group selection is non-deterministic
        // (`HashSet` intersection) when a device shares MULTIPLE groups
        // with both the grant's source and destination -- it could pick
        // EITHER `group_relay` or `group_keepalive`. Every device must be
        // genuinely (locally) linked to BOTH, or admission fails for the
        // wrong reason (this device never linked to whichever group the
        // grant happened to land on) instead of the one this test
        // actually exercises.
        let keepalive_root = tempfile::tempdir().unwrap();
        link(&daemon.state, keepalive_root.path(), group_keepalive);
        keepalive_roots.push(keepalive_root);
    }
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.state.clone());
    spawn_orchestrator(fake.addr(), c.device_id.clone(), c.state.clone());

    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &c.device_id),
        Duration::from_secs(60),
        || "required hops never connected".to_string(),
    )
    .await;

    let grant = fake.issue_relay_grant(&a.device_id, &c.device_id, 120).unwrap();
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

    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 1,
        Duration::from_secs(10),
        || "B never admitted the relay session".to_string(),
    )
    .await;
    let session_id = b.state.relay_forwarder.any_active_session_id().unwrap();

    // Sanity: forwarding works before the revoke.
    session_a_to_b.send_relay_data(session_id, b"before revoke".to_vec());
    wait_until_with_context(
        || b.state.relay_forwarder.session_bytes_forwarded(session_id) >= Some(13),
        Duration::from_secs(10),
        || "pre-revoke forward never landed".to_string(),
    )
    .await;

    // Revoke exactly the group the grant was scoped to, for the
    // DESTINATION -- but C keeps `group_keepalive`, so B<->C's channel
    // itself must NOT tear down.
    fake.revoke(&c.device_id, &grant.group_id);
    wait_until_with_context(
        || !b.state.peer_is_writer(&c.device_id, &grant.group_id),
        Duration::from_secs(10),
        || "B never observed C's group revoke".to_string(),
    )
    .await;
    assert!(
        fully_connected(&b.state, &c.device_id),
        "the channel must stay alive via the second shared group -- this test is only \
         meaningful if the session closes due to revalidation, not because the channel itself \
         tore down"
    );

    // The next datagram must fail revalidation and close the session --
    // not "eventually, at grant expiry in 120s".
    session_a_to_b.send_relay_data(session_id, b"after revoke".to_vec());
    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 0,
        Duration::from_secs(10),
        || {
            format!(
                "relay session was not closed after stale group authorization \
                 (active_session_count={})",
                b.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;
}
