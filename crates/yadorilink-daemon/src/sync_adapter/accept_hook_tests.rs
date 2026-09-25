//! `PathWitnessSink::install` must see connections this stack only accepts.
//!
//! Found live during the 1 GiB direct-path canary: the side that already
//! holds a group's content never dials the bulk-fetch connection the other
//! side pulls it over -- it only accepts it. A witness that watches dials
//! alone (`when_link_dialed` used to be the only hook `install` wired up)
//! saw the sender's handful of small reconciliation dials and none of the
//! ~1 GiB the receiver actually pulled, and reported `not_direct` for a
//! transfer that was, in fact, entirely direct. See
//! `yadorilink_sync_runtime::AcceptedLinkHook`'s own doc comment for the
//! full story, and `relay_equivalence_tests::a_daemon_writes_out_which_
//! carrier_its_transfer_used` for the dial-side half of this same contract.

use std::sync::Arc;

use yadorilink_sync_substrate::NetworkConfig;

use super::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin, FixtureAuthenticator};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_witness_installed_on_the_accepting_side_sees_the_connection_it_never_dialled() {
    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);

    let alice_stack = Arc::new(
        SyncStack::spawn(
            alice.clone(),
            Arc::new(FixtureAuthenticator),
            NetworkConfig::direct_only(),
        )
        .await
        .unwrap(),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .unwrap(),
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);

    let dir = tempfile::tempdir().expect("a place to write the evidence");
    let report = dir.path().join("paths.json");
    let sink = crate::path_witness_sink::PathWitnessSink::new(report.clone(), 1);
    // Installed on ALICE -- the side that, below, will only ever ACCEPT a
    // dial, exactly the content-holding sender's role in the live canary.
    sink.install(&alice_stack);

    // Bob dials alice through the same `link_to` a bulk-content fetch uses
    // from whichever side is behind. Alice never dials anything in this
    // test -- if the accepting side's own witness stayed empty, that would
    // reproduce the exact blind spot this test exists to close.
    bob_stack.link_to("device-alice").await.expect("bob must be able to dial alice");

    // `link_to` returning only means bob's own dial succeeded; alice's
    // accept-side plumbing (the inbound channel, then `serve`'s loop that
    // fires the accepted-link hook) runs on its own task and is not
    // synchronized with that return. A short, generous margin for a
    // same-process loopback connection, not a real network round trip.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    sink.flush().await;
    let written = std::fs::read_to_string(&report).expect("the sink wrote a report");
    assert!(
        !written.contains("\"connections\":[]"),
        "a witness installed on the accepting side must see a connection it only \
         accepted, not one it dialled: {written}"
    );
}
