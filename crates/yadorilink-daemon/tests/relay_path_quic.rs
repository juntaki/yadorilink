//! A relay path is a *transport* path, not a message-level fallback: the
//! peer connection running over it is an ordinary authenticated QUIC
//! connection that happens to have a synthetic remote address. These two
//! tests pin the two consequences that matters most.
//!
//! 1. **It carries real bytes.** Not a control frame round trip -- a file's
//!    actual content, fetched over a block stream, byte-exact at the far
//!    end. A relay that carried only small control messages would pass a
//!    weaker test and still be useless.
//! 2. **Promotion back to direct closes the relay channel.** quinn exposes
//!    no way to move a live connection to a new remote address, so
//!    returning to a direct path is a generation replacement: a new
//!    authenticated connection is published and the superseded relayed one
//!    is closed explicitly, releasing the relaying device's session slot at
//!    once rather than leaving it to an idle timeout.
//!
//! Both run on the canonical N/M/W topology, where N is the relay-capable
//! anchor. Direct reachability is broken the same way
//! `topology_relay_failover.rs` breaks it -- republishing W's advertised
//! endpoint as `127.0.0.1:1`, a real, immediately-refused destination --
//! because that is what a coordination plane pushes when a device's network
//! conditions change, and it is the only lever the test coordination fake
//! offers.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{stand_up_canonical_topology, TopologyNode};
use support::wait_until_with_context;
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

fn routed_direct(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    matches!(
        state.peers.reachability(peer_device_id),
        Some(PeerReachability::Connected(RouteKind::Direct))
    )
}

fn route_debug(state: &Arc<DaemonState>, peer_device_id: &str) -> &'static str {
    state.peers.reachability(peer_device_id).map(|r| r.route_str()).unwrap_or("no-session")
}

/// Waits until M's session with W is running over a relay path.
async fn wait_for_relay_route(m: &TopologyNode, w: &TopologyNode) {
    wait_until_with_context(
        || routed_via_relay(&m.state, &w.device_id),
        Duration::from_secs(90),
        || {
            format!(
                "M never fell back to a relay path for W: m->w route={:?}",
                route_debug(&m.state, &w.device_id)
            )
        },
    )
    .await;
}

/// Content authored on one side of a relay path and read byte-exact on the
/// other, through the ordinary sync path -- DAG record over the control
/// stream, block content over a block stream, both inside a QUIC connection
/// whose only route to the peer is the relay.
///
/// A relayed connection that only carried small control frames would look
/// healthy and still be unable to move a file, which is why the assertion
/// is on the bytes rather than on the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_relayed_connection_carries_real_bytes_end_to_end() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-path-bytes-group";

    let (n, m, w, handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m);
    wire_relay_grant_source(&fake, &w);

    // Break W's advertised endpoint so no peer can dial it directly. N keeps
    // the direct session it already has -- a working path is never torn down
    // for one that has not been proven to exist -- which is what leaves it
    // able to forward for M.
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    wait_for_relay_route(&m, &w).await;

    // Authored on W, whose only route to M is now the relay through N. Big
    // enough to be fetched as block content rather than riding along with
    // the record.
    let content: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(w.root.path().join("relayed.bin"), &content).unwrap();

    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "relayed.bin" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "M never saw the DAG record for content authored over the relay path".to_string(),
    )
    .await;

    // M is On-Demand, so the content itself only moves when asked for --
    // which is the point: this is a block-stream fetch over the relayed
    // connection, not a record that happened to fit in a control frame.
    let mut attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(&m.state, group_id, "relayed.bin").await {
            Ok(()) => break,
            Err(error) if attempts < 8 => {
                attempts += 1;
                tracing::warn!(%error, attempts, "hydration over the relay path failed, retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!("hydration over a relay path must succeed: {error}"),
        }
    }

    assert_eq!(
        std::fs::read(m.root.path().join("relayed.bin")).ok(),
        Some(content),
        "content fetched over a relay path must be byte-exact"
    );
    assert!(
        routed_via_relay(&m.state, &w.device_id),
        "the transfer must have happened over the relay path, not a direct one that recovered \
         mid-test: m->w route={:?}",
        route_debug(&m.state, &w.device_id)
    );

    // The relay really did carry it, rather than the bytes finding some
    // other way across.
    assert!(
        n.state.relay_forwarder.active_session_count() > 0,
        "N must still be relaying for M at this point"
    );

    handles.shutdown();
}

/// Returning to a direct path is a generation replacement, and the
/// superseded relay channel is closed as part of it.
///
/// The relaying device's session slots are a bounded resource it lends out,
/// so "closed" has to mean promptly and explicitly. Leaving the session for
/// the relay's own idle timeout to reap would hold a slot for up to a minute
/// after the route it existed for is gone -- which is exactly the stale
/// state that makes a relay unavailable to the next peer that needs it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn promoting_back_to_direct_closes_the_relay_channel() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-path-promotion-group";

    let (n, m, w, handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m);
    wire_relay_grant_source(&fake, &w);

    let real_w_endpoint = w.state.shared_socket().unwrap().local_addr().to_string();

    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    wait_for_relay_route(&m, &w).await;

    let relayed_channel = m
        .state
        .peers
        .session(&w.device_id)
        .expect("M has a session with W over the relay path");

    wait_until_with_context(
        || n.state.relay_forwarder.active_session_count() > 0,
        Duration::from_secs(30),
        || "N never opened a forwarding session for M's relay path".to_string(),
    )
    .await;

    // W is reachable again. Nothing tears the relayed connection down on a
    // timer: it is replaced only once a direct connection has actually been
    // authenticated, so there is no window with no path at all.
    fake.update_endpoint(&w.device_id, real_w_endpoint);

    wait_until_with_context(
        || routed_direct(&m.state, &w.device_id),
        Duration::from_secs(90),
        || {
            format!(
                "M never promoted back to a direct path for W: m->w route={:?}",
                route_debug(&m.state, &w.device_id)
            )
        },
    )
    .await;

    // The superseded generation is a different session object, which is what
    // makes this a replacement rather than a migration of the old one.
    let direct_session = m
        .state
        .peers
        .session(&w.device_id)
        .expect("M has a session with W over the direct path");
    assert!(
        !Arc::ptr_eq(&relayed_channel, &direct_session),
        "promotion must publish a NEW connection, not re-point the relayed one -- quinn has no \
         API to change a peer's remote address"
    );

    // And the relay stops carrying anything for this pair, promptly.
    wait_until_with_context(
        || n.state.relay_forwarder.active_session_count() == 0,
        Duration::from_secs(30),
        || {
            format!(
                "N still holds {} relay session(s) after M promoted back to a direct path -- a \
                 superseded relay channel must be closed explicitly, not left to idle out",
                n.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;

    handles.shutdown();
}
