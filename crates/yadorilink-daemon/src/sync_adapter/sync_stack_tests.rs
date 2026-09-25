//! Two devices reconciling through the assembled stack.
//!
//! Everything below this test has its own coverage. What this pins is the
//! assembly: that the netmap really does answer both questions a session needs
//! about its peer, that the endpoint identity a peer dials is the one the
//! netmap pinned, and that a Change possessed by one device becomes possessed
//! by the other with no configuration beyond what a netmap already carries.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_substrate::NetworkConfig;

use super::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{
    change_touching, device, endpoint_of, honest_bundle, init_staging_schema, pin, possessed,
    stage, FixtureAuthenticator, GROUP,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_one_device_possesses_reaches_the_other_through_the_stack() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }

    // Each device's netmap pins the other's signing key and authorizes it.
    // That single fact is what makes the peer both recognisable (the endpoint
    // identity is that key) and disclosable-to.
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);

    let alice_stack = SyncStack::spawn(
        alice.clone(),
        Arc::new(FixtureAuthenticator),
        NetworkConfig::direct_only(),
    )
    .await
    .expect("alice's stack starts");
    let bob_stack =
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts");

    // The transport identity a peer dials is the key its netmap pinned.
    assert_eq!(
        alice_stack.peer_id().as_bytes(),
        endpoint_of(11).as_bytes(),
        "the endpoint identity must be the device signing key the netmap publishes"
    );

    // Bob learns where Alice actually is, the way a netmap entry supplies it.
    {
        let peer = alice_stack.local_address();
        bob_stack.address_directory().record(
            peer.peer(),
            peer.direct_addrs().copied().collect(),
            peer.relay_urls().map(ToString::to_string).collect(),
        );
    }

    // Alice possesses one verified Change; Bob possesses nothing.
    let change = change_touching(&["shared.txt"]);
    let bundle = honest_bundle(change.clone());
    stage(&alice, bundle.clone(), 1);

    assert_eq!(possessed(&alice, &group), vec![change.compute_hash()]);
    assert!(possessed(&bob, &group).is_empty());

    let summary =
        tokio::time::timeout(Duration::from_secs(30), bob_stack.sync_with("device-alice", &group))
            .await
            .expect("the sync must not hang")
            .expect("the sync must succeed")
            .expect_ran("this call ran the sync rather than coalescing");

    assert_eq!(summary.wanted, 1, "bob should have found exactly the one Change he lacked");
    assert_eq!(summary.staged, 1);
    assert_eq!(
        possessed(&bob, &group),
        vec![change.compute_hash()],
        "bob must now possess what alice possessed"
    );

    // Converged: a second sync moves nothing.
    let quiet = bob_stack
        .sync_with("device-alice", &group)
        .await
        .unwrap()
        .expect_ran("a converged second sync still runs");
    assert_eq!(quiet.wanted, 0);
    assert_eq!(quiet.staged, 0);
}

/// A peer the netmap has not authorized is told nothing, even though its
/// signing key is pinned and it can reach us.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unauthorized_peer_learns_nothing_through_the_stack() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }

    // Alice pins Bob's key but authorizes him for nothing.
    alice.record_peer_signing_key("device-bob", *endpoint_of(22).as_bytes());
    pin(&bob, "device-alice", 11);

    let alice_stack = SyncStack::spawn(
        alice.clone(),
        Arc::new(FixtureAuthenticator),
        NetworkConfig::direct_only(),
    )
    .await
    .unwrap();
    let bob_stack =
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .unwrap();

    {
        let peer = alice_stack.local_address();
        bob_stack.address_directory().record(
            peer.peer(),
            peer.direct_addrs().copied().collect(),
            peer.relay_urls().map(ToString::to_string).collect(),
        );
    }

    let bundle = honest_bundle(change_touching(&["secret.txt"]));
    stage(&alice, bundle.clone(), 1);

    let summary =
        tokio::time::timeout(Duration::from_secs(30), bob_stack.sync_with("device-alice", &group))
            .await
            .expect("the sync must not hang")
            .expect("the sync must not error")
            .expect_ran("ran");

    assert_eq!(summary.wanted, 0, "an unauthorized peer must learn no difference");
    assert!(possessed(&bob, &group).is_empty());
}

/// A group this device cannot currently vouch for is disclosed to nobody —
/// not even a peer the netmap fully authorizes.
///
/// This is the half of the disclosure predicate that is about us rather than
/// about the peer. It matters most in the window it describes: a policy that
/// has gone stale, or has not loaded yet this run, leaves `peer_is_writer`
/// perfectly happy while this device has nothing it can honestly serve
/// against. A fingerprint is already a disclosure — it reveals that a set
/// exists and how large it is — so the refusal has to happen before the first
/// round, not after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_this_device_cannot_vouch_for_is_disclosed_to_nobody() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }

    // Fully authorized in both directions: the peer half of the predicate is
    // satisfied, so anything that stops disclosure here is the local half.
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);

    // Alice's policy for the group goes stale. She may still hold Changes for
    // it; she may no longer serve them.
    alice.mark_group_policy_stale(GROUP);
    assert!(
        alice.authority.peer_is_writer("device-bob", GROUP),
        "the peer half must still hold, or this test would prove nothing"
    );
    assert!(!alice.group_is_servable(GROUP));

    let alice_stack = SyncStack::spawn(
        alice.clone(),
        Arc::new(FixtureAuthenticator),
        NetworkConfig::direct_only(),
    )
    .await
    .unwrap();
    let bob_stack =
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .unwrap();

    {
        let peer = alice_stack.local_address();
        bob_stack.address_directory().record(
            peer.peer(),
            peer.direct_addrs().copied().collect(),
            peer.relay_urls().map(ToString::to_string).collect(),
        );
    }

    let bundle = honest_bundle(change_touching(&["withheld.txt"]));
    stage(&alice, bundle.clone(), 1);

    let summary =
        tokio::time::timeout(Duration::from_secs(30), bob_stack.sync_with("device-alice", &group))
            .await
            .expect("the sync must not hang")
            .expect("the sync must not error")
            .expect_ran("ran");

    assert_eq!(summary.wanted, 0, "a withheld group must yield no difference at all");
    assert!(possessed(&bob, &group).is_empty());

    // And symmetrically: Bob, whose own policy is fine, still refuses to
    // disclose his set once his own policy goes stale.
    bob.mark_group_policy_stale(GROUP);
    let refused = bob_stack.sync_with("device-alice", &group).await;
    assert!(
        matches!(
            refused,
            Err(crate::sync_adapter::sync_stack::SyncStackError::Runtime(
                yadorilink_sync_runtime::SyncRuntimeError::Protocol(
                    yadorilink_sync_protocol::ProtocolError::NotDisclosable { .. }
                )
            ))
        ),
        "expected a refusal to disclose, got {refused:?}"
    );
}

/// A staged Change blocked by a local capture barrier must become canonical
/// once that barrier settles, with no retransmission, timer, or polling.
///
/// The barrier is correct: promoting a remote Change across an observed but
/// not-yet-captured local edit would order it after content this device has
/// not expressed as history. The defect is what happens when the barrier
/// clears. Admission is scheduled from exactly one production site -- a
/// delivery that staged something new -- so a dependency going from blocked
/// to admissible raised nothing at all, and the drain that would promote it
/// never ran again.
///
/// Nothing rescues it either: `servable_change_hashes` advertises staged
/// objects, so the peer sees this device as already holding the Change and
/// never re-sends it, which means no further delivery ever occurs to
/// schedule the drain. The Change stays staged forever while the device
/// sits at a divergent frontier -- observed as `STAGED_NOT_CANONICAL` with
/// complete ancestry and no stuck flight.
///
/// This asserts the transition, not a timer: the barrier is settled through
/// the real local-commit hook and the test then only yields.
#[tokio::test]
async fn a_settled_capture_barrier_schedules_admission_without_retransmission() {
    use super::tests::{change_touching, honest_bundle, is_canonical, set_barrier, settles};
    use crate::sync_adapter::ReconciliationDriver;

    let (state, _dir) = device("device-alice", 11);
    init_staging_schema(&state);
    let group = FolderGroupId(GROUP.into());

    let stack = Arc::new(
        SyncStack::spawn(
            state.clone(),
            Arc::new(FixtureAuthenticator),
            NetworkConfig::direct_only(),
        )
        .await
        .unwrap(),
    );
    state.install_reconciliation_driver(ReconciliationDriver::start(state.clone(), stack.clone()));

    // A local edit to "a.txt" is observed but not yet captured.
    let db = state.replica_coordinator.database().clone();
    let db = db.as_ref();
    set_barrier(db, "a.txt", true);

    // A verified remote Change for that same path arrives and is staged.
    let change = change_touching(&["a.txt"]);
    let now = 1_700_000_000_000_000_000i64;
    db.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
        yadorilink_sync_sqlite::verified_change_store::stage_verified_bundles(
            conn,
            std::slice::from_ref(&honest_bundle(change.clone())),
            now,
        )
        .map(|_| ())
    })
    .unwrap();

    // The barrier holds it back, as it should.
    let blocked = stack.admission().drain(&group).await.unwrap().unwrap();
    assert!(blocked.promoted.is_empty(), "an open capture barrier must block promotion");
    assert!(!is_canonical(db, &change), "sanity: it must not be canonical yet");

    // The barrier settles, and the local commit is announced through the
    // ordinary production hook. Nothing below asks for a drain, stages
    // anything further, or waits on a clock.
    set_barrier(db, "a.txt", false);
    state.note_local_commit_for_group(GROUP).await;

    assert!(
        settles(|| is_canonical(db, &change)).await,
        "a Change whose blocking barrier has settled must be promoted without \
         needing the peer to send it again"
    );
}

/// A Change authored by the fixture author at an explicit position, for
/// scenarios where the author chain itself is what refuses something.
fn authored_at(seq: u64, prev: Option<&Change>, parents: &[&Change], path: &str) -> Change {
    use yadorilink_replica_domain::change::Op;
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
    use yadorilink_replica_domain::rebootstrap::HistoryEpoch;

    let mut parent_hashes: Vec<_> = parents.iter().map(|p| p.compute_hash()).collect();
    parent_hashes.sort();
    Change::create_signed(
        parent_hashes,
        parents.iter().map(|p| p.lamport).max().unwrap_or(0),
        DeviceId(crate::test_support::sync_stack_fixture::DEVICE.into()),
        AuthorSeq(seq),
        prev.map(Change::compute_hash),
        FolderGroupId(GROUP.into()),
        HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath(path.into()) }],
        &crate::test_support::sync_stack_fixture::author_key(),
    )
}

/// Stages `parent`, a child of it and a grandchild of that child together,
/// where `parent` is a permanent refusal, then runs one drain.
///
/// The refusal of `parent` is only recorded inside the pass that refuses
/// it, so the child is not among that pass's candidates. A drain that
/// counted only promotions as progress stopped right there, and the child
/// and grandchild stayed staged, servable and possessed until some
/// unrelated delivery or local commit happened to schedule another drain --
/// one such wake per level of the chain.
async fn one_drain_settles_every_staged_change_behind_a_refused_parent(
    prelude: &[Change],
    parent: Change,
) {
    use super::tests::is_canonical;

    let (state, _dir) = device("device-alice", 11);
    init_staging_schema(&state);
    let group = FolderGroupId(GROUP.into());
    let stack = SyncStack::spawn(
        state.clone(),
        Arc::new(FixtureAuthenticator),
        NetworkConfig::direct_only(),
    )
    .await
    .unwrap();
    let db = state.replica_coordinator.database().clone();

    let mut seq = 1;
    for change in prelude {
        stage(&state, honest_bundle(change.clone()), seq);
        seq += 1;
    }
    if !prelude.is_empty() {
        stack.admission().drain(&group).await.unwrap().unwrap();
        assert!(prelude.iter().all(|change| is_canonical(&db, change)), "sanity: prelude admits");
    }

    let next = parent.author_seq.0 + 1;
    let child = authored_at(next, Some(&parent), &[&parent], "child.txt");
    let grandchild = authored_at(next + 1, Some(&child), &[&child], "grandchild.txt");
    let chain = [parent, child, grandchild];
    for change in &chain {
        stage(&state, honest_bundle(change.clone()), seq);
        seq += 1;
    }
    let hashes: Vec<_> = chain.iter().map(Change::compute_hash).collect();
    assert!(hashes.iter().all(|hash| possessed(&state, &group).contains(hash)));

    let outcome = stack.admission().drain(&group).await.unwrap().unwrap();

    assert!(outcome.promoted.is_empty(), "nothing in the chain may be promoted: {outcome:?}");
    let still_possessed = possessed(&state, &group);
    for (change, hash) in chain.iter().zip(&hashes) {
        assert!(!is_canonical(&db, change));
        assert!(
            !still_possessed.contains(hash),
            "one drain must settle every staged Change behind a refused parent; \
             {} is still possessed",
            hex::encode(hash.0)
        );
    }
    let staged: i64 = db
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn
                .query_row("SELECT count(*) FROM verified_change_objects", [], |row| row.get(0))?)
        })
        .unwrap();
    assert_eq!(staged, 0, "nothing may be left in the staging area");
}

#[tokio::test]
async fn one_drain_settles_staged_descendants_of_a_path_refused_parent() {
    let parent = authored_at(1, None, &[], "notes:draft.txt");
    one_drain_settles_every_staged_change_behind_a_refused_parent(&[], parent).await;
}

#[tokio::test]
async fn one_drain_settles_staged_descendants_of_an_author_chain_refused_parent() {
    let first = authored_at(1, None, &[], "first.txt");
    // Position 3 naming nothing before it: a gap nothing can close.
    let parent = authored_at(3, None, &[&first], "gap.txt");
    one_drain_settles_every_staged_change_behind_a_refused_parent(&[first], parent).await;
}
