//! M5-A soak-closure deterministic regression, extracted from
//! `topology_soak_lane.rs`'s randomized session-leak invariant (seed
//! `12552500466593081697`, reproduced 8/8 on this file's isolated shape
//! before the fix below). A burst of rapid same-peer restarts left the
//! observer's `PeerSyncSession` for the restarted peer un-replaced
//! (`Arc::ptr_eq` still true against the pre-restart session) for the
//! entire settle window -- confirmed by direct trace, NOT a slow-but-
//! healthy recovery that just needed a longer timeout, and NOT a
//! permanently-stuck session either: `peer_handshake_received()` and
//! `change_dag_negotiated()` were both true and both sides' reachability
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
    fully_connected, restart_node, spawn_orchestrator, stand_up_canonical_topology, TopologyNode,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;

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

fn wire_relay_grant_source(fake: &FakeCoordination, state: &Arc<DaemonState>, device_id: &str) {
    state.set_relay_grant_source(Arc::new(FakeGrantSource {
        fake: fake.clone(),
        source_device_id: device_id.to_string(),
    }));
}

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
            restarted.keypair.public_bytes(),
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
                && current.change_dag_negotiated()
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
            current_dag_negotiated = current.as_ref().map(|s| s.change_dag_negotiated()),
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

/// The soak lane's actual failure shape (invariant 4, stale route): W's
/// route is forced through relay (its advertised endpoint broken, same
/// technique as `topology_soak_lane.rs`'s `op_break_w_route`/`topology_
/// relay_failover.rs`), then W is restarted rapidly WHILE still broken,
/// then restored -- checking whether N's and W's own `RouteKind` views
/// of each other re-converge, not just reachability.
#[tokio::test]
async fn rapid_restart_while_relayed_converges_route_kind() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    let group_id = "repro-relay-group".to_string();
    let (n, m, mut w, mut handles) = stand_up_canonical_topology(&fake, &group_id).await;
    wire_relay_grant_source(&fake, &m.state, &m.device_id);
    wire_relay_grant_source(&fake, &w.state, &w.device_id);

    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());

    // Wait for the route to actually settle on Relay before restarting --
    // restarting mid-race would just repro the OTHER (already-fixed)
    // finding, not this one.
    let deadline = Instant::now() + Duration::from_secs(60);
    while n.state.peers.reachability(&w.device_id)
        != Some(PeerReachability::Connected(RouteKind::Relay))
    {
        if Instant::now() >= deadline {
            panic!(
                "n never saw w routed via relay within 60s of breaking w's endpoint: {:?}",
                n.state.peers.reachability(&w.device_id)
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    for i in 0..6 {
        tracing::info!(i, device_id = %w.device_id, "repro: restarting w while relayed");
        handles.take_and_shutdown(&w.device_id).await;
        let restarted = restart_node(w).await;
        register_with_fake(
            &fake,
            &restarted.state,
            &restarted.device_id,
            restarted.keypair.public_bytes(),
            &[&group_id],
        )
        .await;
        fake.update_endpoint(&restarted.device_id, "127.0.0.1:1".to_string());
        wire_relay_grant_source(&fake, &restarted.state, &restarted.device_id);
        let runtime = spawn_orchestrator(fake.addr(), &restarted);
        handles.insert(restarted.device_id.clone(), runtime);
        w = restarted;
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }

    // Read w's CURRENT real endpoint live, not a value captured before
    // the restart loop -- see this file's own module doc comment for why
    // a pre-captured endpoint is stale after any restart (fresh ephemeral
    // port every time) and was the soak lane's actual root cause.
    let current_w_endpoint = w.state.shared_socket().unwrap().local_addr().to_string();
    fake.update_endpoint(&w.device_id, current_w_endpoint);

    let route_kind =
        |peers: &yadorilink_daemon::peer_registry::PeerRegistry, peer_id: &str| match peers
            .reachability(peer_id)
        {
            Some(PeerReachability::Connected(kind)) => Some(kind),
            _ => None,
        };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let n_view = route_kind(&n.state.peers, &w.device_id);
        let w_view = route_kind(&w.state.peers, &n.device_id);
        if n_view == w_view && n_view == Some(RouteKind::Direct) {
            tracing::info!(?n_view, ?w_view, "repro: route kinds converged to direct");
            break;
        }
        if Instant::now() >= deadline {
            tracing::error!(
                ?n_view,
                ?w_view,
                n_reachability = ?n.state.peers.reachability(&w.device_id),
                w_reachability = ?w.state.peers.reachability(&n.device_id),
                "repro: route kinds never converged to direct after restoring w's endpoint"
            );
            panic!(
                "n<->w route kinds never converged to Direct within 120s after restoring w's \
                 endpoint post rapid-restart-while-relayed: n sees {n_view:?}, w sees {w_view:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = m;

    handles.shutdown();
}
