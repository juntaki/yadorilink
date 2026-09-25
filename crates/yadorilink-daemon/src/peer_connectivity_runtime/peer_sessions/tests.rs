//! When a peer session exists: authorized, and reachable over the iroh
//! substrate -- and never because a legacy QUIC channel came up.
//!
//! Two devices, each a `SyncStack` and a `ReconciliationDriver` over real
//! iroh endpoints, exactly the pieces a daemon assembles. No legacy endpoint
//! is bound and no session is registered by hand.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_substrate::NetworkConfig;

use crate::daemon_state::DaemonState;
use crate::sync_adapter::driver::ReconciliationDriver;
use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin, FixtureAuthenticator, GROUP};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";

/// Long enough for a dial, a reconnect backoff step and a registration.
const STEP: Duration = Duration::from_secs(20);

async fn within(budget: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

struct Pair {
    alice: Arc<DaemonState>,
    bob: Arc<DaemonState>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// Two devices that pin each other, each with a running driver. When
/// `introduce` is false neither knows where the other answers.
async fn pair(introduce: bool) -> Pair {
    let (alice, alice_dir) = device(ALICE, 11);
    let (bob, bob_dir) = device(BOB, 22);
    pin(&alice, BOB, 22);
    pin(&bob, ALICE, 11);
    let alice_stack = Arc::new(
        SyncStack::spawn(
            alice.clone(),
            Arc::new(FixtureAuthenticator),
            NetworkConfig::direct_only(),
        )
        .await
        .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    if introduce {
        SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    }
    alice.install_reconciliation_driver(ReconciliationDriver::start(alice.clone(), alice_stack));
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));
    Pair { alice, bob, _dirs: (alice_dir, bob_dir) }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authorized_peer_the_substrate_reaches_gets_a_session_on_both_sides() {
    let pair = pair(true).await;

    assert!(
        within(STEP, || pair.alice.peers.has_session(BOB) && pair.bob.peers.has_session(ALICE))
            .await,
        "each device must hold a session for the other once their endpoints connect"
    );
    let session = pair.alice.peers.session(BOB).expect("alice's session for bob");
    assert!(session.shares_group(GROUP), "the session serves the group the netmap authorizes");
    assert!(
        !pair.alice.peers.convergence_for_group(GROUP).is_empty(),
        "the session is a content source for the group, with its convergence executor beside it"
    );
    assert_eq!(
        pair.alice.peer_connectivity.connected_peer_count(),
        1,
        "the connection the session lives on keeps the peer reading connected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_the_substrate_cannot_reach_gets_no_session_until_it_can() {
    let pair = pair(false).await;

    assert!(
        !within(Duration::from_secs(3), || pair.alice.peers.has_session(BOB)).await,
        "authorization alone is not a session: with nowhere to dial, there is none"
    );

    let alice_stack = pair.alice.reconciliation_driver().unwrap().stack().clone();
    let bob_stack = pair.bob.reconciliation_driver().unwrap().stack().clone();
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    assert!(
        within(Duration::from_secs(60), || pair.alice.peers.has_session(BOB)).await,
        "once the peer can be reached, the session follows without anything else happening"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_the_netmap_withdraws_loses_its_session() {
    let pair = pair(true).await;
    assert!(within(STEP, || pair.alice.peers.has_session(BOB)).await, "precondition");

    let key = pair.alice.authority.peer_signing_key(BOB);
    pair.alice.clear_peer_netmap_metadata(BOB);
    pair.alice.peer_connectivity.revoke_device(BOB, key);

    assert!(
        within(STEP, || !pair.alice.peers.has_session(BOB)).await,
        "a device the netmap no longer pins must not keep a session"
    );
    assert!(
        !within(Duration::from_secs(3), || pair.alice.peers.has_session(BOB)).await,
        "and must not get one back while it stays withdrawn"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_ends_with_its_connection_and_with_its_driver() {
    let pair = pair(true).await;
    assert!(
        within(STEP, || pair.alice.peers.has_session(BOB) && pair.bob.peers.has_session(ALICE))
            .await,
        "precondition"
    );

    // Bob stops answering: his endpoint closes. Alice's connection to him
    // ends, and her session with it.
    let bob_driver = pair.bob.take_reconciliation_driver().expect("bob's driver");
    bob_driver.stack().shutdown().await;
    drop(bob_driver);

    assert!(
        within(STEP, || !pair.alice.peers.has_session(BOB)).await,
        "a session must not outlive the only connection it had to its peer"
    );
    assert!(
        within(STEP, || !pair.bob.peers.has_session(ALICE)).await,
        "and a device whose driver is gone keeps no session over the endpoint it had"
    );
}

/// A keeper that connects while another session for its peer is still
/// registered must take over once that session goes, not wait for its
/// connection to change. A replaced keeper removes its session only as it
/// stops, which can be after its replacement has already looked; without
/// this the peer stays connected with no session at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keeper_that_finds_another_session_standing_takes_over_once_it_goes() {
    let pair = pair(true).await;
    assert!(
        within(STEP, || pair.alice.peers.has_session(BOB) && pair.bob.peers.has_session(ALICE))
            .await,
        "precondition"
    );
    let alice_stack = pair.alice.reconciliation_driver().unwrap().stack().clone();

    // Stand a session the keeper did not register in its place -- what a
    // replaced keeper's session looks like to its successor.
    let kept = pair.alice.peers.session(BOB).unwrap();
    assert!(pair.alice.peers.remove_if_current(BOB, &kept));
    let standing = super::open_session(&Arc::downgrade(&pair.alice), &alice_stack, BOB)
        .expect("a session can be opened in the keeper's place");

    // End the connection: the keeper reconnects, and finds that session.
    alice_stack.link_to(BOB).await.expect("the live link").close();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        pair.alice.peers.session(BOB).is_some_and(|current| Arc::ptr_eq(&current, &standing)),
        "precondition: the standing session is still the registered one"
    );

    assert!(pair.alice.peers.remove_if_current(BOB, &standing));
    assert!(
        within(STEP, || pair
            .alice
            .peers
            .session(BOB)
            .is_some_and(|current| !Arc::ptr_eq(&current, &standing)))
        .await,
        "once the standing session goes, the keeper must open its own over the live connection"
    );
}

/// Reachability is read from live iroh connections only, so a peer this
/// device is not currently exchanging anything with reads connected only if
/// some connection to it stays up. The keeper's is that connection: a
/// pinned, authorized peer with nothing in flight reads connected, and a
/// confirmation it gave stays "available now", for as long as it is up --
/// not only while a reconciliation pass happens to hold a dial open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quiet_authorized_peer_stays_connected_and_available_while_its_keeper_holds_a_connection()
{
    use crate::background_custody::BackgroundCustodyEvidence;
    use crate::peer_registry::PeerReachability;
    use crate::route::RouteKind;

    let pair = pair(true).await;
    assert!(within(STEP, || pair.alice.peers.has_session(BOB)).await, "precondition");
    let digest = pair
        .alice
        .local_root_set_summary(GROUP)
        .expect("the group's current root set can be summarised")
        .current_digest;
    pair.alice.publish_background_custody(
        GROUP,
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some(BOB.into()),
            current_digest: digest,
            roots_digest_matched: true,
        },
        pair.alice.authority.membership_generation(),
        0,
    );

    // Nothing is written on either side, so nothing else dials. Sampled over
    // several reconnect backoffs, well past any one pass's dial.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < deadline {
        assert_eq!(
            pair.alice.peer_connectivity.reachability(BOB),
            Some(PeerReachability::Connected(RouteKind::Direct)),
            "a quiet authorized peer must read connected while its keeper's connection is up"
        );
        assert_eq!(pair.alice.peer_connectivity.connected_peer_count(), 1);
        assert!(
            pair.alice.fetch_available_via_confirmed_peer(GROUP),
            "the peer that confirmed the group must count as available now"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
