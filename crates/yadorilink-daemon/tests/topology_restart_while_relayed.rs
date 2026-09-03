//! M5-A Pass 5 regression-matrix item E: a node restart while its active
//! route to a peer is RELAY (not direct) must follow the same
//! fresh-session-epoch rule the plain direct-path restart tests
//! (`topology_restart_convergence.rs`) already prove -- relay
//! reachability must never let an obsolete session epoch
//! survive a restart just because the traffic happens to be arriving via
//! a relay hop instead of directly. Reuses `topology_relay_failover.rs`'s
//! own established technique for forcing a relay route (`Fake
//! Coordination::update_endpoint` pointed at a real, immediately-refused
//! `127.0.0.1:1`) and `topology_restart_convergence.rs`'s own
//! session-identity-first restart methodology (test files cannot `use`
//! each other directly, so the small relay-grant-source glue both files
//! need is duplicated here rather than factored into `support/`, matching
//! this crate's existing convention for small per-file-only helpers).

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{fully_connected, restart_node, stand_up_canonical_topology, TopologyNode};
use support::{register_with_fake_at, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;
use yadorilink_peer_session::peer_session::PeerSyncSession;

struct FakeGrantSource {
    fake: FakeCoordination,
    source_device_id: String,
}

impl yadorilink_daemon::relay_carrier::RelayGrantSource for FakeGrantSource {
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

fn wire_relay_grant_source(fake: &FakeCoordination, node: &TopologyNode) {
    node.state.set_relay_grant_source(Arc::new(FakeGrantSource {
        fake: fake.clone(),
        source_device_id: node.device_id.clone(),
    }));
}

fn routed_via_relay(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    matches!(
        state.peers.reachability(peer_device_id),
        Some(PeerReachability::Connected(RouteKind::Relay))
    )
}

fn route_debug(state: &Arc<DaemonState>, peer_device_id: &str) -> &'static str {
    state.peers.reachability(peer_device_id).map(|r| r.route_str()).unwrap_or("no-session")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn w_restart_while_relayed_gets_a_fresh_epoch_not_a_stale_one() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-restart-while-relayed-group";

    let (n, m, mut w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m);
    wire_relay_grant_source(&fake, &w);

    // Force W's direct path to fail (every peer, per this technique's own
    // established constraint -- `topology_relay_failover.rs`'s module
    // doc comment) and wait for a real relay-routed session to form,
    // exactly like that file's own baseline.
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    wait_until_with_context(
        || routed_via_relay(&m.state, &w.device_id) || routed_via_relay(&n.state, &w.device_id),
        Duration::from_secs(90),
        || {
            format!(
                "W's direct failure never produced a relay-routed session anywhere: \
                 m->w route={:?} n->w route={:?}",
                route_debug(&m.state, &w.device_id),
                route_debug(&n.state, &w.device_id),
            )
        },
    )
    .await;

    // Real content authored by W over the relay route, before restart --
    // establishes a genuine relay-carried baseline both peers must still
    // hold after W comes back.
    let before_name = "before-restart-while-relayed.txt";
    std::fs::write(w.root.path().join(before_name), b"authored while relayed, before restart")
        .unwrap();
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join(before_name)).ok().as_deref()
                == Some(b"authored while relayed, before restart" as &[u8])
        },
        Duration::from_secs(60),
        || "N never converged on W's pre-restart content over the relay route".to_string(),
    )
    .await;

    // Capture pre-restart session identity from both remaining peers --
    // same oracle discipline as `topology_restart_convergence.rs`.
    let n_session_before: Arc<PeerSyncSession> = n
        .state
        .peers
        .session(&w.device_id)
        .expect("N must have an established (relay-routed) session with W before restart");
    let m_session_before: Arc<PeerSyncSession> = m
        .state
        .peers
        .session(&w.device_id)
        .expect("M must have an established (relay-routed) session with W before restart");

    // Restart W. Its direct endpoint is STILL the forced-broken one at
    // this point (never restored), so its ONLY possible path back is
    // relay again -- proving relay reachability does not let a restarted
    // peer's obsolete session epoch survive just because the
    // traffic keeps arriving via the same relay hop as before, and does
    // not somehow bypass the ordinary fresh-generation reconnect rule.
    handles.take_and_shutdown(&w.device_id).await;
    w = restart_node(w).await;
    // Registered with the broken address directly, never with W's own
    // freshly-bound real one.
    //
    // Registering the real address and breaking it a moment later is two
    // netmap pushes, and that is a race this test loses intermittently: a
    // peer that reads the first push has a working address for W and
    // connects on it, and the second push does not take that back, because
    // a connection is not torn down merely for being on an address the
    // plane has stopped advertising while it still works. When that
    // happened, W came back DIRECT and the scenario -- a restart while
    // relayed -- silently stopped being the scenario.
    register_with_fake_at(
        &fake,
        &w.state,
        &w.device_id,
        &[group_id],
        "127.0.0.1:1".to_string(),
    )
    .await;
    let w_runtime = support::topology::spawn_orchestrator(fake.addr(), &w);
    handles.insert(w.device_id.clone(), w_runtime);

    // Step 1: fresh session identity on BOTH remaining peers -- not
    // merely "a session exists" (a stale relay-routed session object
    // sitting in the registry would pass that trivially).
    wait_until_with_context(
        || {
            let n_replaced = n
                .state
                .peers
                .session(&w.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_before));
            let m_replaced = m
                .state
                .peers
                .session(&w.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &m_session_before));
            n_replaced && m_replaced
        },
        Duration::from_secs(180),
        || {
            "N and/or M never got a FRESH session identity for restarted, still-relayed W"
                .to_string()
        },
    )
    .await;

    // Step 2: the fresh session must actually negotiate, AND it must
    // still be relay-routed (W's direct endpoint remains broken) -- a
    // fresh epoch, not a resurrection of the old one, reached over the
    // same route kind as before restart.
    wait_until_with_context(
        || {
            fully_connected(&n.state, &w.device_id)
                && fully_connected(&m.state, &w.device_id)
                && (routed_via_relay(&n.state, &w.device_id)
                    || routed_via_relay(&m.state, &w.device_id))
        },
        Duration::from_secs(90),
        || {
            format!(
                "restarted W never re-established a negotiated, relay-routed session: \
                 n->w route={:?} m->w route={:?}",
                route_debug(&n.state, &w.device_id),
                route_debug(&m.state, &w.device_id),
            )
        },
    )
    .await;

    // Step 3: real post-restart traffic over the fresh relay-routed
    // session, exact content verified.
    let after_name = "after-restart-while-relayed.txt";
    std::fs::write(w.root.path().join(after_name), b"authored after restart, still relayed")
        .unwrap();
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join(after_name)).ok().as_deref()
                == Some(b"authored after restart, still relayed" as &[u8])
        },
        Duration::from_secs(90),
        || {
            "N never converged on restarted W's post-restart content over the fresh relay route"
                .to_string()
        },
    )
    .await;

    // Finally, restore W's real endpoint -- direct recovery must still
    // work normally after a restart-while-relayed cycle, proving no
    // obsolete relay-only state was left pinned that would prevent
    // direct promotion.
    let real_endpoint = w.state.shared_socket().unwrap().local_addr().to_string();
    fake.update_endpoint(&w.device_id, real_endpoint);
    wait_until_with_context(
        || {
            matches!(
                n.state.peers.reachability(&w.device_id),
                Some(PeerReachability::Connected(RouteKind::Direct))
            )
        },
        Duration::from_secs(90),
        || {
            format!(
                "direct never recovered after restore: n->w route={:?}",
                route_debug(&n.state, &w.device_id)
            )
        },
    )
    .await;

    handles.shutdown();
}
