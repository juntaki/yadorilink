//! A peer advertises every address it might be reachable at, and a dialer
//! has no way to know in advance which of them work. This pins what has to
//! happen when the first one does not.
//!
//! ## Why this is a test and not a comment
//!
//! A dial to an address nothing answers on does not fail fast: it costs the
//! full QUIC handshake timeout, because silence is indistinguishable from a
//! slow path until the timer runs out. So trying candidates one after
//! another does not merely make connecting slower -- it makes every
//! candidate after the first dead one unreachable, on that attempt and on
//! every retry after it, because each attempt is itself bounded at roughly
//! one handshake timeout and starts from the same list in the same order. A
//! peer whose first advertised endpoint happens not to work is then
//! permanently stuck "connecting", with a perfectly good address second in
//! its own list.
//!
//! Nothing in the in-process suite caught that, because the test
//! coordination fake used to advertise exactly one endpoint per device --
//! always the working one. That is why the fake grew
//! `update_endpoints`, and why this file exists: the failure needs a peer
//! with MORE THAN ONE advertised address to appear at all.

mod support;

use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{fully_connected, link_eager, new_node, spawn_orchestrator, TopologyNode};
use support::{register_with_fake, wait_until_with_context};

/// A real, immediately-refused destination -- the same deterministic
/// stand-in for an unusable candidate the relay topology tests use. Nothing
/// listens here, so a dial to it can only end by timing out.
const DEAD_ENDPOINT: &str = "127.0.0.1:1";

/// What one dial to an address nothing answers on costs. Read from the
/// transport rather than restated, because the whole point of these tests is
/// the relation between this number and how long connecting takes.
const HANDSHAKE_TIMEOUT: Duration = yadorilink_transport::PEER_IDLE_TIMEOUT;

/// Releases the orchestrator runtimes at the end of a test.
///
/// `shutdown_background`, never a plain drop: dropping a `Runtime` from
/// inside an async context panics, which is a test-harness detail rather
/// than anything about the daemon, but it fails the test just as loudly.
fn shutdown_orchestrators(runtimes: [tokio::runtime::Runtime; 2]) {
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

fn real_endpoint(node: &TopologyNode) -> String {
    node.state.shared_socket().expect("node has a bound transport hub").local_addr().to_string()
}

/// Two devices connect even though the dialled peer advertises an unusable
/// address first.
///
/// The bound matters as much as the assertion. It is set below two handshake
/// timeouts on purpose: a dialer that walks its candidate list in order
/// cannot pass this no matter how long it is given, and one that spends a
/// whole handshake timeout on the dead address before starting the real one
/// would only scrape past a much looser bound. Connecting promptly is the
/// property; connecting eventually is not enough to distinguish the two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_is_reachable_when_its_first_advertised_endpoint_is_not() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "candidate-race-group";

    // "a" sorts before "b", so a dials b -- the dialling side is the one
    // whose candidate handling is under test here.
    let dialer = new_node("candidate-race-a-dialer");
    let target = new_node("candidate-race-b-target");

    for node in [&dialer, &target] {
        register_with_fake(&fake, &node.state, &node.device_id, &[group_id]).await;
        link_eager(node, group_id);
    }

    // The target advertises a dead address FIRST and its real one second --
    // the ordinary shape of a device with more than one interface, where the
    // dialer cannot tell which entry will work.
    fake.update_endpoints(
        &target.device_id,
        vec![DEAD_ENDPOINT.to_string(), real_endpoint(&target)],
    );

    // `shutdown_background`, not a plain drop: dropping a `Runtime` inside
    // an async context panics, and these outlive the assertions below.
    let runtimes =
        [spawn_orchestrator(fake.addr(), &dialer), spawn_orchestrator(fake.addr(), &target)];
    let connecting_since = std::time::Instant::now();

    wait_until_with_context(
        || {
            fully_connected(&dialer.state, &target.device_id)
                && fully_connected(&target.state, &dialer.device_id)
        },
        Duration::from_secs(45),
        || {
            format!(
                "a peer whose first advertised endpoint is dead never connected: \
                 dialer->target={} target->dialer={}",
                fully_connected(&dialer.state, &target.device_id),
                fully_connected(&target.state, &dialer.device_id),
            )
        },
    )
    .await;

    let connect_elapsed = connecting_since.elapsed();
    println!("connected through a dead first candidate in {connect_elapsed:?}");
    assert!(
        connect_elapsed < HANDSHAKE_TIMEOUT,
        "the dead candidate's cost must be paid CONCURRENTLY with the working one, not before \
         it: connecting took {connect_elapsed:?}, which is at least one whole handshake timeout"
    );

    // And it is a working connection, not merely a handshake: real content
    // crosses it.
    std::fs::write(dialer.root.path().join("over-the-second-candidate.txt"), b"reached anyway")
        .unwrap();
    wait_until_with_context(
        || {
            std::fs::read(target.root.path().join("over-the-second-candidate.txt")).ok().as_deref()
                == Some(b"reached anyway" as &[u8])
        },
        Duration::from_secs(60),
        || "content never converged over the connection made on the second candidate".to_string(),
    )
    .await;

    shutdown_orchestrators(runtimes);
}

/// Several dead addresses ahead of the working one, which is the case a
/// per-candidate ordering fix would still get wrong: the cost of the dead
/// entries has to be paid concurrently, not one after another, or the
/// attempt budget runs out before the real address is ever tried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_dead_endpoints_ahead_of_the_working_one_still_connect() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "candidate-race-many-group";

    let dialer = new_node("candidate-race-many-a-dialer");
    let target = new_node("candidate-race-many-b-target");

    for node in [&dialer, &target] {
        register_with_fake(&fake, &node.state, &node.device_id, &[group_id]).await;
        link_eager(node, group_id);
    }

    fake.update_endpoints(
        &target.device_id,
        vec![
            "127.0.0.1:1".to_string(),
            "127.0.0.1:2".to_string(),
            "127.0.0.1:3".to_string(),
            real_endpoint(&target),
        ],
    );

    // `shutdown_background`, not a plain drop: dropping a `Runtime` inside
    // an async context panics, and these outlive the assertions below.
    let runtimes =
        [spawn_orchestrator(fake.addr(), &dialer), spawn_orchestrator(fake.addr(), &target)];
    let connecting_since = std::time::Instant::now();

    wait_until_with_context(
        || {
            fully_connected(&dialer.state, &target.device_id)
                && fully_connected(&target.state, &dialer.device_id)
        },
        Duration::from_secs(45),
        || {
            format!(
                "a peer behind three dead advertised endpoints never connected: \
                 dialer->target={} target->dialer={}",
                fully_connected(&dialer.state, &target.device_id),
                fully_connected(&target.state, &dialer.device_id),
            )
        },
    )
    .await;
    let connect_elapsed = connecting_since.elapsed();
    println!("connected through three dead candidates in {connect_elapsed:?}");
    assert!(
        connect_elapsed < HANDSHAKE_TIMEOUT,
        "three dead candidates must cost one concurrent handshake timeout between them, not \
         three in series: connecting took {connect_elapsed:?}"
    );

    shutdown_orchestrators(runtimes);
}
