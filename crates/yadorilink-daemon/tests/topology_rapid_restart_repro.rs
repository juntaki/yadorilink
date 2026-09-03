//! M5-A soak-closure deterministic regression, extracted from
//! `topology_soak_lane.rs`'s randomized session-leak invariant (seed
//! `12552500466593081697`, reproduced 8/8 on this file's isolated shape
//! before the fix below). A burst of rapid same-peer restarts left the
//! observer's `PeerSyncSession` for the restarted peer un-replaced
//! (`Arc::ptr_eq` still true against the pre-restart session) for the
//! entire settle window -- confirmed by direct trace, NOT a slow-but-
//! healthy recovery that just needed a longer timeout, and NOT a
//! permanently-stuck session either: `peer_handshake_received()` and
//! its handshake had arrived and both sides' reachability
//! was `Connected(Direct)` the whole time. `PeerChannel`'s own
//! `DIRECT_LIVENESS_TIMEOUT` re-race re-handshakes an EXISTING channel/
//! session in place once the restarted peer's new endpoint is learned --
//! no new `PeerSyncSession` is ever created, because none is needed. The
//! soak lane's original invariant assumed recovery always means Arc
//! replacement (Classification B: real production behavior, wrong test
//! oracle) and has been fixed to check functional health instead; this
//! file is that fix's extracted deterministic regression, and doubles as
//! a fast (~15s) iteration harness for this restart-burst shape, with
//! `peer_orchestrator` tracing on by default (unlike the soak lane, which
//! needs an explicit `RUST_LOG` to see anything from its own module).
//!
//! `rapid_restart_while_relayed_converges_route_kind` below is a second,
//! independent soak-closure finding (invariant 4, stale route):
//! restoring w's endpoint after breaking it (forcing relay) used a value
//! captured ONCE at stand-up, but `restart_node` binds a fresh ephemeral
//! port every time -- any `RestartNode` op between breaking and restoring
//! w's route left the soak lane restoring w's coordination-plane entry
//! to a stale, dead port from a prior generation. Every OTHER node's
//! channel to w correctly stayed on Relay forever (that port genuinely
//! doesn't work), while w's own view of n/m (never restarted, stable
//! addresses) stayed Direct -- exactly the soak's observed asymmetry.
//! Reproduced 5/5 before the fix, confirmed Classification C (test-
//! harness artifact, not reachable in production: a real restart always
//! re-registers its own current endpoint with the coordination plane).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::fake_coordination::FakeCoordination;
use support::register_with_fake;
use support::topology::{
    fully_connected, hydrate_with_retries, restart_node, routed_via_relay, spawn_orchestrator,
    stand_up_canonical_topology, stand_up_relay_forced_topology, wire_relay_grant_source_with_ttl,
    TopologyNode,
};
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "topology_rapid_restart_repro=debug,yadorilink_daemon::peer_orchestrator=debug,\
             yadorilink_daemon::daemon_state=debug",
        ))
        .with_test_writer()
        .try_init();
}

/// Restarts `w` `restarts` times, `gap` apart, then returns the final
/// generation -- mirrors `topology_soak_lane.rs`'s `op_restart_node` "w"
/// arm exactly (same helper calls, same order), just without the rest of
/// the soak's random op mix around it.
async fn rapid_restart(
    fake: &FakeCoordination,
    mut w: TopologyNode,
    handles: &mut support::topology::TopologyHandles,
    group_id: &str,
    restarts: u32,
    gap: Duration,
) -> TopologyNode {
    for i in 0..restarts {
        tracing::info!(i, device_id = %w.device_id, "repro: restarting w");
        handles.take_and_shutdown(&w.device_id).await;
        let restarted = restart_node(w).await;
        register_with_fake(
            fake,
            &restarted.state,
            &restarted.device_id,
            &[group_id],
        )
        .await;
        let runtime = spawn_orchestrator(fake.addr(), &restarted);
        handles.insert(restarted.device_id.clone(), runtime);
        w = restarted;
        tokio::time::sleep(gap).await;
    }
    w
}

#[tokio::test]
async fn rapid_restart_recovers_within_bound() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    let group_id = "repro-group".to_string();
    let (n, m, mut w, mut handles) = stand_up_canonical_topology(&fake, &group_id).await;

    let pre_restart_session =
        n.state.peers.session(&w.device_id).expect("n must have a session with w before restart");

    w = rapid_restart(&fake, w, &mut handles, &group_id, 6, Duration::from_millis(1500)).await;

    // Matches the fixed `topology_soak_lane.rs` invariant 2 exactly:
    // recovered means either a NEW session was registered, or the SAME
    // session is currently healthy (fresh handshake, DAG negotiated,
    // reachability connected) -- not merely "the Arc changed".
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut recovered = false;
    loop {
        if let Some(current) = n.state.peers.session(&w.device_id) {
            let replaced = !Arc::ptr_eq(&current, &pre_restart_session);
            let healthy = current.peer_handshake_received()
                && matches!(
                    n.state.peers.reachability(&w.device_id),
                    Some(PeerReachability::Connected(_))
                );
            if replaced || healthy {
                recovered = true;
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    if !recovered {
        let current = n.state.peers.session(&w.device_id);
        tracing::error!(
            recovered,
            same_arc = current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &pre_restart_session)),
            current_handshake_received = current.as_ref().map(|s| s.peer_handshake_received()),
            n_reachability = ?n.state.peers.reachability(&w.device_id),
            w_reachability = ?w.state.peers.reachability(&n.device_id),
            "repro: session never replaced AND never became healthy in place"
        );
    }
    tracing::info!(recovered, "repro: final state");
    assert!(
        recovered,
        "n's session with w was neither replaced nor healed healthy in place within 120s \
         after a burst of 6 rapid restarts 1.5s apart"
    );

    // Also confirm the OTHER direction and full-mesh reachability, since
    // the soak lane's failures have appeared on either side of a pair.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(fully_connected(&n.state, &w.device_id) && fully_connected(&w.state, &n.device_id)) {
        if Instant::now() >= deadline {
            panic!(
                "n<->w did not reach full mesh connectivity within 60s after recovery: \
                 n sees w: {:?}, w sees n: {:?}",
                n.state.peers.session(&w.device_id).map(|s| s.peer_handshake_received()),
                w.state.peers.session(&n.device_id).map(|s| s.peer_handshake_received())
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = m;

    // Also confirm both sides agree on RouteKind (Direct vs Relay), not
    // just reachability -- `topology_soak_lane.rs`'s invariant 4 has
    // found this asymmetric after a restart burst too.
    let route_kind =
        |peers: &yadorilink_daemon::peer_registry::PeerRegistry, peer_id: &str| match peers
            .reachability(peer_id)
        {
            Some(PeerReachability::Connected(kind)) => Some(kind),
            _ => None,
        };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let n_view = route_kind(&n.state.peers, &w.device_id);
        let w_view = route_kind(&w.state.peers, &n.device_id);
        if n_view == w_view && n_view.is_some() {
            tracing::info!(?n_view, ?w_view, "repro: route kinds agree");
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "n<->w route kinds never agreed within 60s after recovery: n sees {n_view:?}, \
                 w sees {w_view:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    handles.shutdown();
}

/// Waits for N<->W to agree Direct AND M<->W to agree Relay-via-N,
/// checking both sides of each pair -- not just one node's own view, and
/// not just reachability. Used both as an initial sanity check and after
/// every restart in the burst below.
async fn wait_for_mixed_route_reconvergence(
    n: &TopologyNode,
    m: &TopologyNode,
    w: &TopologyNode,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let n_view_w = n.state.peers.reachability(&w.device_id);
        let w_view_n = w.state.peers.reachability(&n.device_id);
        let m_view_w = m.state.peers.reachability(&w.device_id);
        let w_view_m = w.state.peers.reachability(&m.device_id);
        let n_w_direct = n_view_w == Some(PeerReachability::Connected(RouteKind::Direct))
            && w_view_n == Some(PeerReachability::Connected(RouteKind::Direct));
        let m_w_relay = m_view_w == Some(PeerReachability::Connected(RouteKind::Relay))
            && w_view_m == Some(PeerReachability::Connected(RouteKind::Relay));
        if n_w_direct && m_w_relay {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "n<->w (want both Direct) and m<->w (want both Relay) never both reconverged \
                 within {timeout:?}: n_view_w={n_view_w:?} w_view_n={w_view_n:?} \
                 m_view_w={m_view_w:?} w_view_m={w_view_m:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The soak lane's actual failure shape (invariant 4, stale route): W
/// restarts repeatedly while simultaneously holding a Direct session with
/// N and a Relay-via-N session with M, checking that both routes
/// re-converge to their correct kind after every restart -- not just
/// reachability, and not just once at the very end.
///
/// This function used to wait for N's own view of W to become
/// `RouteKind::Relay`, which cannot happen under ANY topology where N is
/// the sole relay-capable device: `RouteKind::Relay` means routed through
/// a THIRD peer (`route.rs`'s own doc comment), and a relay-capable
/// device never relays for its own pairing. That was a wrong-pairing test
/// bug -- confirmed by the observed failure itself, N seeing W as
/// `Direct` the whole time, never `Relay` -- not the "stale broken-
/// endpoint restore" finding this file's own module doc comment
/// describes (that one is what the original version of this function
/// actually reproduced and fixed, and is still covered by
/// `rapid_restart_recovers_within_bound` above). The pair that CAN
/// genuinely go Relay is M<->W (through N); this version checks that one,
/// and checks N<->W (the pair that stays Direct throughout) for
/// stale/un-reconverged state under the SAME restart burst, using the
/// relay-forced topology's permanent M<->W peer-view block
/// (`stand_up_relay_forced_topology`) rather than a device-global
/// endpoint break that an already-live connection can simply ignore.
// The relay-forced topology's M is eager/full-replica, whose
// materialization path hits `tokio::task::block_in_place` -- which
// panics off the multi-threaded runtime. Matches the flavor every other
// relay-forced restart test in this suite already uses
// (`topology_relay_role_restart_matrix.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rapid_restart_while_relayed_converges_route_kind() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    let group_id = "repro-relay-group".to_string();
    let (n, m, mut w, mut handles) = stand_up_relay_forced_topology(&fake, &group_id).await;
    // A generous TTL, not the fixture's 60s default: six restarts each
    // waited out to full reconvergence can comfortably approach that
    // default -- same rationale the R3 relay-recovery tests settled on.
    wire_relay_grant_source_with_ttl(&fake, &m.state, &m.device_id, 900);
    wire_relay_grant_source_with_ttl(&fake, &w.state, &w.device_id, 900);

    wait_for_mixed_route_reconvergence(&n, &m, &w, Duration::from_secs(30)).await;

    for i in 0..6 {
        tracing::info!(i, device_id = %w.device_id, "repro: restarting w while relayed to m");
        handles.take_and_shutdown(&w.device_id).await;
        let restarted = restart_node(w).await;
        register_with_fake(&fake, &restarted.state, &restarted.device_id, &[&group_id]).await;
        // The relay-forced topology's M<->W peer-view block survives
        // `register_with_fake` re-registering W's fresh endpoint (see
        // `FakeCoordination::set_peer_view_endpoints`'s own doc comment),
        // so unlike the old endpoint-break technique this needs no manual
        // re-block after each restart.
        wire_relay_grant_source_with_ttl(&fake, &restarted.state, &restarted.device_id, 900);
        let runtime = spawn_orchestrator(fake.addr(), &restarted);
        handles.insert(restarted.device_id.clone(), runtime);
        w = restarted;
        wait_for_mixed_route_reconvergence(&n, &m, &w, Duration::from_secs(60)).await;
        tracing::info!(i, "repro: n<->w direct and m<->w relay both reconverged after restart");
    }

    assert_eq!(
        n.state.peers.reachability(&w.device_id),
        Some(PeerReachability::Connected(RouteKind::Direct)),
        "n<->w must still be Direct after the restart burst"
    );
    assert_eq!(
        m.state.peers.reachability(&w.device_id),
        Some(PeerReachability::Connected(RouteKind::Relay)),
        "m<->w must still be Relay-via-n after the restart burst"
    );

    // Route kind alone is a connectivity signal, not proof the relay path
    // actually carries data -- push one real file through it. M is the
    // relay-forced topology's eager/full-replica source; W is On-Demand.
    let payload = b"rapid-restart-while-relayed post-burst relay payload";
    std::fs::write(m.root.path().join("post-burst-relay-probe.bin"), payload).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !w
        .state
        .replica_coordinator
        .file_index_repository()
        .has_real_current_row(&group_id, "post-burst-relay-probe.bin")
        .unwrap_or(false)
    {
        if Instant::now() >= deadline {
            panic!("w never saw post-burst-relay-probe.bin's real DAG record over m<->w relay");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    hydrate_with_retries(&w.state, &group_id, "post-burst-relay-probe.bin").await;
    let w_bytes = std::fs::read(w.root.path().join("post-burst-relay-probe.bin"))
        .expect("w must hold the relay-hydrated probe file");
    assert_eq!(
        w_bytes, payload,
        "w's relay-hydrated copy of the post-burst probe file must be byte-exact"
    );

    assert!(routed_via_relay(&m.state, &w.device_id), "m<->w must still be relay-routed");

    handles.shutdown();
}
