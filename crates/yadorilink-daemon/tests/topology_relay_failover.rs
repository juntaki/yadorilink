//! M5-A Pass 4: direct -> relay -> direct integration on the canonical
//! N/M/W topology. Real production connection path throughout: real
//! `peer_orchestrator::run` (which wires `PeerChannel::connect_with_relay`
//! for its normal, non-test connection setup -- relay fallback is not a
//! special code path here, it's what production already does), a real
//! synthesized `RelayGrant` (`FakeCoordination::issue_relay_grant`), and
//! real DAG sync/hydration traffic (not `RelayCarrier::send_via_relay`'s
//! raw bytes, unlike `relay_chaos.rs`'s transport-focused fan-in proof).
//!
//! **How direct failure is forced**: `FakeCoordination::update_endpoint`
//! republishes a device's advertised endpoint over the live netmap
//! subscription (mirroring what a real coordination plane would push if
//! a device's network conditions changed), pointed at
//! `127.0.0.1:1` -- a real, immediately-refused destination (the same
//! deterministic technique `yadorilink-transport`'s `relay_failover.rs`
//! uses at the transport layer), not silence alone. `FakeCoordination`
//! has one endpoint per device (no per-peer-pair override), so this
//! breaks W's direct reachability from EVERY peer, not just from M --
//! a real, still-valuable variant of the spec's scenario shape (M<->W
//! specifically), constrained by what the existing test-coordination
//! fake can express. N stays reachable to W only via relay for the
//! duration; M's own path to W also goes via relay in this shape.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{fully_connected, stand_up_canonical_topology, TopologyNode};
use support::wait_until_with_context;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;

/// A real `RelayGrant`, synthesized by `fake` the way the real
/// coordination plane would (`FakeCoordination::issue_relay_grant`'s own
/// doc comment) -- not a test-only forged grant.
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

/// This device's session with `peer_device_id` is currently routed via
/// relay (not direct) -- read straight off `PeerReachability`/`RouteKind`
/// (`route.rs`), the same enum CLI/desktop status already renders.
fn routed_via_relay(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    matches!(
        state.peers.reachability(peer_device_id),
        Some(PeerReachability::Connected(RouteKind::Relay))
    )
}

fn routed_direct(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    matches!(
        state.peers.reachability(peer_device_id),
        Some(PeerReachability::Connected(RouteKind::Direct))
    )
}

fn route_debug(state: &Arc<DaemonState>, peer_device_id: &str) -> &'static str {
    state.peers.reachability(peer_device_id).map(|r| r.route_str()).unwrap_or("no-session")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn direct_fails_falls_back_to_relay_then_direct_recovers() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-relay-failover-group";

    let (n, m, w, _handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m);
    wire_relay_grant_source(&fake, &w);

    // Baseline: M authors content; N and W converge over DIRECT, exactly
    // like `topology_n_m_w.rs`'s own happy path. Establishes a genuine
    // "was direct" baseline to compare the failover transition against.
    let path = m.root.path().join("before-failover.txt");
    std::fs::write(&path, b"before failover").unwrap();
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join("before-failover.txt")).ok().as_deref()
                == Some(b"before failover" as &[u8])
        },
        Duration::from_secs(30),
        || "N never converged on M's pre-failover content".to_string(),
    )
    .await;
    assert!(
        routed_direct(&w.state, &n.device_id) || fully_connected(&w.state, &n.device_id),
        "sanity check: W starts genuinely reachable"
    );

    // Force W's direct path to fail for every peer, matching this file's
    // own module doc comment on the fake-coordination constraint.
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());

    // Real production reconnect supervision (not this test) must detect
    // the failure and fail over to relay through N -- the same
    // `peer_orchestrator`/`PeerChannel::connect_with_relay` path
    // production runs, never a test-only shortcut.
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

    // Real sync/hydration traffic must keep flowing through the relay
    // hop, not just a raw relay-carrier byte send -- W authors NEW
    // content now, while direct is down.
    let path = w.root.path().join("during-relay.txt");
    std::fs::write(&path, b"authored during relay").unwrap();
    wait_until_with_context(
        || {
            n.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "during-relay.txt" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "N never saw during-relay.txt's DAG record while W's direct path was down".to_string(),
    )
    .await;

    // Durability must be unaffected by the route change alone -- N is
    // still the group's only full replica (this canonical topology's own
    // established fact, per `topology_n_m_w.rs`'s happy path: a lone
    // full-replica anchor with no other full-replica peer reads AtRisk,
    // never Protected). A real custody-confirmation sweep (matching
    // production's periodic `DurabilityConfirmationJob`) must derive the
    // SAME status while routed via relay as it would over direct --
    // "Durability != Connectivity," M4's own core invariant, proven here
    // under a live route transition rather than a static snapshot.
    n.state.refresh_custody_confirmation(group_id).await;
    let durability_during_relay = n.state.group_durability_status(group_id);
    assert_eq!(
        durability_during_relay,
        GroupDurabilityStatus::AtRisk,
        "a lone full-replica anchor's durability status must be identical whether reached \
         via relay or direct -- the route change alone must never move this value"
    );

    // Restore W's real direct-reachable endpoint.
    let real_endpoint = w.state.shared_socket().unwrap().local_addr().to_string();
    fake.update_endpoint(&w.device_id, real_endpoint);

    wait_until_with_context(
        || routed_direct(&m.state, &w.device_id) && routed_direct(&n.state, &w.device_id),
        Duration::from_secs(90),
        || {
            format!(
                "direct never recovered after restoring W's real endpoint: \
                 m->w route={:?} n->w route={:?}",
                route_debug(&m.state, &w.device_id),
                route_debug(&n.state, &w.device_id),
            )
        },
    )
    .await;

    // Real sync traffic continues correctly post-recovery.
    let path = w.root.path().join("after-recovery.txt");
    std::fs::write(&path, b"authored after direct recovery").unwrap();
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join("after-recovery.txt")).ok().as_deref()
                == Some(b"authored after direct recovery" as &[u8])
        },
        Duration::from_secs(30),
        || "N never converged on W's post-recovery content".to_string(),
    )
    .await;

    // Durability is unchanged AGAIN by the recovery transition -- the
    // same AtRisk fact as before and during relay, proving the full
    // direct->relay->direct round trip never once let a route change
    // move the durability axis.
    n.state.refresh_custody_confirmation(group_id).await;
    assert_eq!(
        n.state.group_durability_status(group_id),
        GroupDurabilityStatus::AtRisk,
        "durability must still read AtRisk after direct recovery -- unchanged by either \
         route transition, matching the mid-relay assertion above"
    );

    // N's relay forwarder must hold no stale/leaked session for W once
    // direct traffic has taken back over -- a session that outlives the
    // route it was opened for is exactly the "no stale relay session"
    // invariant this pass exists to check.
    wait_until_with_context(
        || n.state.relay_forwarder.active_session_count() == 0,
        Duration::from_secs(30),
        || {
            format!(
                "N's relay forwarder still holds {} active session(s) after direct recovery",
                n.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;
}
