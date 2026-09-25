//! Two real nodes converging over QUIC.
//!
//! This is the first point at which the whole stack runs together: iroh
//! transport, three lane classes, RBSR reconciliation, proof-bundle transfer
//! and verified possession. Everything below is a property of the system, not
//! of any one layer.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use support::{group, id, MockReplica};
use yadorilink_rbsr::ItemId;
use yadorilink_sync_runtime::SyncRuntime;
use yadorilink_sync_substrate::{NetworkConfig, SubstrateNode};

async fn node(
    ids: impl IntoIterator<Item = ItemId>,
) -> (SyncRuntime<MockReplica>, Arc<MockReplica>, tokio::task::JoinHandle<()>) {
    node_with(MockReplica::with(ids)).await
}

/// Every node in this test binary publishes into, and resolves out of, one
/// book -- the stand-in for the coordination plane, which is what answers
/// "where is this endpoint" now that `connect` takes only an identity.
fn shared_book() -> yadorilink_sync_substrate::testing::SharedAddressBook {
    static BOOK: std::sync::OnceLock<yadorilink_sync_substrate::testing::SharedAddressBook> =
        std::sync::OnceLock::new();
    BOOK.get_or_init(yadorilink_sync_substrate::testing::SharedAddressBook::new).clone()
}

async fn node_with(
    replica: MockReplica,
) -> (SyncRuntime<MockReplica>, Arc<MockReplica>, tokio::task::JoinHandle<()>) {
    let (substrate, inbound) = SubstrateNode::spawn(
        iroh::SecretKey::generate(),
        NetworkConfig::direct_only().with_directory(Arc::new(shared_book())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .expect("substrate starts");

    let replica = Arc::new(replica);
    let runtime = SyncRuntime::new(substrate, replica.clone());
    let serving = runtime.serve(inbound);
    (runtime, replica, serving)
}

/// A peer that is not entitled to the group learns nothing from asking.
///
/// It does not learn the size of the set, or whether the group exists here at
/// all: the refusal happens before a fingerprint is computed, so what comes
/// back is indistinguishable from a peer that holds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unentitled_peer_learns_nothing() {
    let (alice, alice_replica, alice_serving) =
        node_with(MockReplica::with((0..500).map(id)).undisclosable()).await;
    let (bob, bob_replica, bob_serving) = node([]).await;

    let summary = bob
        .sync_with(alice.local_address().peer(), &group())
        .await
        .unwrap()
        .unwrap()
        .expect_synced("same base");

    assert_eq!(summary.wanted, 0, "no difference may be revealed");
    assert_eq!(summary.staged, 0);
    assert!(bob_replica.possessed().is_empty());
    assert_eq!(
        alice_replica.serve_calls.load(Ordering::SeqCst),
        0,
        "nothing may even be loaded for an unentitled peer"
    );

    alice_serving.abort();
    bob_serving.abort();
}

/// A delivery that fails verification stages none of itself, across the real
/// transport as well as in the protocol's own tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delivery_that_fails_verification_leaves_the_receiver_unchanged() {
    let (alice, _alice_replica, alice_serving) = node((0..40).map(id)).await;
    let (bob, bob_replica, bob_serving) =
        node_with(MockReplica::with([]).rejecting_staging()).await;

    let result = bob.sync_with(alice.local_address().peer(), &group()).await;

    assert!(result.is_err(), "a delivery that fails verification must fail the sync");
    assert!(bob_replica.possessed().is_empty(), "and must leave nothing behind");

    alice_serving.abort();
    bob_serving.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_converge_over_quic() {
    let (alice, alice_replica, alice_serving) = node((0..60).map(id)).await;
    let (bob, bob_replica, bob_serving) = node((30..100).map(id)).await;

    let alice_address = alice.local_address();

    // Bob pulls from Alice.
    let summary = bob
        .sync_with(alice_address.peer(), &group())
        .await
        .expect("sync succeeds")
        .expect("this call ran the sync rather than coalescing")
        .expect_synced("same base");

    assert_eq!(summary.wanted, 30, "the identifiers only Alice held");
    assert_eq!(summary.staged, 30, "and all of them were staged");

    let after = bob_replica.possessed();
    assert!(
        (0..100).map(id).all(|hash| after.contains(&hash)),
        "Bob now holds everything either node held"
    );

    // Alice pulls from Bob to close the loop.
    let alice_summary = alice
        .sync_with(bob.local_address().peer(), &group())
        .await
        .expect("sync succeeds")
        .expect("ran")
        .expect_synced("same base");
    assert_eq!(alice_summary.staged, 40);
    assert_eq!(alice_replica.possessed(), bob_replica.possessed());

    // Converged: a further sync moves nothing.
    let quiet = bob
        .sync_with(alice_address.peer(), &group())
        .await
        .unwrap()
        .unwrap()
        .expect_synced("same base");
    assert_eq!(quiet.wanted, 0);
    assert_eq!(quiet.staged, 0);
    assert_eq!(quiet.rounds, 1, "one fingerprint settles an agreed pair");

    alice_serving.abort();
    bob_serving.abort();
}

/// Repeated syncing against a converged peer must not keep re-delivering.
///
/// The failure this rules out is the measured 560-676x retransmission storm:
/// work has to be proportional to the actual difference, so a peer that is
/// already up to date costs one fingerprint each time and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_converged_peer_costs_one_fingerprint_per_sync_and_no_transfers() {
    let (alice, _alice_replica, alice_serving) = node((0..200).map(id)).await;
    let (bob, bob_replica, bob_serving) = node((0..200).map(id)).await;

    let alice_address = alice.local_address();

    for round in 0..10 {
        let summary = bob
            .sync_with(alice_address.peer(), &group())
            .await
            .unwrap()
            .unwrap()
            .expect_synced("same base");
        assert_eq!(summary.wanted, 0, "sync {round} found a difference that is not there");
        assert_eq!(summary.rounds, 1);
    }

    assert_eq!(
        bob_replica.stage_calls.load(Ordering::SeqCst),
        0,
        "ten syncs against an identical peer must stage nothing"
    );
    assert_eq!(bob_replica.possessed().len(), 200, "and must not have changed what is held");

    alice_serving.abort();
    bob_serving.abort();
}

/// Reconnecting after the link is gone resumes from durable possession alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_reconnects_resumes_from_its_durable_set() {
    let (alice, _alice_replica, alice_serving) = node((0..80).map(id)).await;
    let (bob, bob_replica, bob_serving) = node([]).await;

    let alice_address = alice.local_address();

    // A first sync brings Bob part of the way, then the runtime is discarded
    // entirely — connection, lanes, in-flight reconciliation state and all.
    let first = bob
        .sync_with(alice_address.peer(), &group())
        .await
        .unwrap()
        .unwrap()
        .expect_synced("same base");
    assert_eq!(first.staged, 80);
    drop(bob);
    bob_serving.abort();

    // A brand new runtime over the same durable set. Nothing survived from
    // the previous session; nothing needed to.
    let (substrate, inbound) = SubstrateNode::spawn(
        iroh::SecretKey::generate(),
        NetworkConfig::direct_only().with_directory(Arc::new(shared_book())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();
    let reborn = SyncRuntime::new(substrate, bob_replica.clone());
    let reborn_serving = reborn.serve(inbound);

    let second = reborn
        .sync_with(alice_address.peer(), &group())
        .await
        .unwrap()
        .unwrap()
        .expect_synced("same base");
    assert_eq!(second.wanted, 0, "the durable set alone is enough to know we are current");
    assert_eq!(second.staged, 0);

    alice_serving.abort();
    reborn_serving.abort();
}
