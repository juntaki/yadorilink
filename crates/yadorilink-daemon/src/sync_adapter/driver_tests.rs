//! What actually makes a Change move in production.
//!
//! `sync_stack_tests` proves the stack converges when someone calls
//! `sync_with`. Nothing in a running daemon calls that. These tests use only
//! the events the daemon itself raises, because "green when driven by hand,
//! silent in the daemon" is the specific failure this cutover could
//! plausibly ship.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::verified_change_store;
use yadorilink_sync_substrate::{NetworkConfig, PeerId};

use super::driver::{set_default_reconciliation_backstop_interval_for_tests, ReconciliationDriver};
use super::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{
    change_putting, device, file_version, honest_bundle_carrying, init_staging_schema, pin,
    possessed, FixtureAuthenticator, GROUP,
};

/// Poll until `check` holds, or fail. No sleep of a fixed length anywhere:
/// a test that passes because it waited long enough tells you nothing about
/// whether an event drove the work or a timer did.
async fn within(seconds: u64, mut check: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false)
}

/// A Change authored on one device reaches the other because of the event
/// the author raises — not because anything polled, and not because the test
/// asked for a sync.
///
/// The author is the one that notices, but the author is not the one that
/// needs anything: reconciliation tells both sides the whole difference, and
/// the side that is behind schedules its own pull. That second half is easy
/// to leave out and impossible to notice without a test like this, because
/// every hand-driven test pulls in the direction it already wanted.
/// A driver that starts after everything is already in place still converges.
///
/// Every event this driver reacts to fires on a *change*, and by the time a
/// stack finishes starting the changes have happened: the netmap arrived
/// during startup and raised its grants and addresses against a device that
/// had no driver yet, and a steady netmap afterwards is silent. Without a
/// driver acting on the state it finds, a device could sit authorized,
/// reachable, holding a Change its peer lacks, and never reconcile — until
/// some unrelated later edit happened to wake it.
///
/// Nothing in this test raises an event after the driver exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_driver_reconciles_what_was_already_there_when_it_started() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }
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
    // The Change is authored and staged before either driver exists, so the
    // one event a local commit would have raised is raised against nothing.
    let version = file_version(4096, 0x22);
    let change = change_putting("already-here.bin", &version);
    alice
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                1,
            )
        })
        .unwrap();

    alice.install_reconciliation_driver(ReconciliationDriver::start(alice.clone(), alice_stack));
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));

    let converged = within(30, || possessed(&bob, &group) == vec![change.compute_hash()]).await;
    assert!(
        converged,
        "a driver that starts with work already waiting must do it, not wait for another event"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_change_reaches_an_authorized_peer_from_the_event_alone() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }
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

    // Each side records where the other is, exactly as an applied netmap
    // push does.
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));

    // A Change that writes content, not a bare delete. This is the standard
    // fixture for the stack from here on: a delete refers to no file version,
    // so a delete-only suite exercises none of the metadata a real edit
    // depends on — which is how a bundle missing its versions reached a scale
    // run with every unit test green.
    let version = file_version(4096, 0x11);
    let change = change_putting("authored.bin", &version);
    alice
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                1,
            )
        })
        .unwrap();

    // The one event a real local commit raises, and nothing else.
    alice_driver.note_local_change(&group);

    let converged = within(30, || possessed(&bob, &group) == vec![change.compute_hash()]).await;
    assert!(converged, "the authoring device's own event must be enough to move the Change");

    // And it arrived admissible: the version metadata crossed the wire with
    // it, so promotion needs nothing further from the network.
    let promoted = within(30, || {
        bob.replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::dag_store::get_file_version(
                    conn,
                    GROUP,
                    &version.version_hash,
                )
            })
            .unwrap()
            .is_some()
    })
    .await;
    assert!(
        promoted,
        "the file version the Change refers to must have travelled with it and been installed"
    );
}

/// The same event reaches nobody it should not. A peer this device holds a
/// key for, but authorizes for nothing, is never dialled and learns nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_event_reaches_only_peers_the_netmap_authorizes() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }

    // Alice knows Bob's key and where he is, and authorizes him for nothing.
    alice.record_peer_signing_key(
        "device-bob",
        ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]).verifying_key().to_bytes(),
    );
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
    {
        let peer = bob_stack.local_address();
        alice_stack.address_directory().record(
            peer.peer(),
            peer.direct_addrs().copied().collect(),
            peer.relay_urls().map(ToString::to_string).collect(),
        );
    }

    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));

    alice
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change_putting("secret.bin", &file_version(2048, 0x33)),
                    vec![file_version(2048, 0x33)],
                )),
                1,
            )
        })
        .unwrap();

    alice_driver.note_local_change(&group);

    // Long enough that a wrongly-scheduled reconciliation would have
    // completed several times over.
    let leaked = within(5, || !possessed(&bob, &group).is_empty()).await;
    assert!(!leaked, "an unauthorized peer must not be reconciled with at all");
}

/// A Change reaches a device that never talks to its author.
///
/// Two devices cannot show this and neither can any pairwise test: with A and
/// B only, one hop is the whole distance. It takes a third device, reachable
/// from B but not from A, to ask whether propagation continues past the first
/// pull.
///
/// It did not. A pulled Change landed on B and stopped there — B's own
/// possession had grown and nothing said so, so B never offered it onward.
/// Row14 caught this as six devices agreeing on almost everything, with the
/// last edits stranded one hop from where they were authored, and no timer to
/// rescue them because the design has none by intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_travels_past_the_first_device_that_pulls_it() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _a) = device("device-alice", 11);
    let (bob, _b) = device("device-bob", 22);
    let (carol, _c) = device("device-carol", 33);
    for state in [&alice, &bob, &carol] {
        init_staging_schema(state);
    }

    // A line, not a mesh: alice and carol are authorized for bob, and for
    // each other only in the netmap's eyes — never given an address, so
    // neither can dial the other at all.
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);
    pin(&bob, "device-carol", 33);
    pin(&carol, "device-bob", 22);

    let mut stacks = Vec::new();
    for state in [&alice, &bob, &carol] {
        stacks.push(Arc::new(
            SyncStack::spawn(
                state.clone(),
                Arc::new(FixtureAuthenticator),
                NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        ));
    }

    // Addresses only along the line: alice <-> bob <-> carol, and alice and
    // carol never learn where the other answers. That is the whole point of
    // this test -- the Change has to travel THROUGH bob.
    SyncStack::teach_each_other_for_tests(&stacks[0], &stacks[1]);
    SyncStack::teach_each_other_for_tests(&stacks[1], &stacks[2]);

    let alice_driver = ReconciliationDriver::start(alice.clone(), stacks[0].clone());
    alice.install_reconciliation_driver(alice_driver.clone());
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), stacks[1].clone()));
    carol.install_reconciliation_driver(ReconciliationDriver::start(
        carol.clone(),
        stacks[2].clone(),
    ));

    let version = file_version(4096, 0x44);
    let change = change_putting("relayed.bin", &version);
    alice
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                1,
            )
        })
        .unwrap();

    // One event, on the author, and nothing else for the rest of the test.
    alice_driver.note_local_change(&group);

    let reached = within(60, || possessed(&carol, &group) == vec![change.compute_hash()]).await;
    assert!(
        reached,
        "a Change must keep travelling past the first device that pulls it; carol holds {:?}",
        possessed(&carol, &group)
    );
}

/// Many unreachable (peer, group) pairs must not starve a healthy one.
///
/// Found live during the 1 GiB direct-path canary: a device that had
/// accumulated a few abandoned full-replica group memberships (each still
/// authorized by the netmap, none locally linked any more) saw its real
/// transfer's own reconciliation dial time out alongside the dead ones,
/// because every wake -- including [`super::driver::Wake::All`]'s own 30s
/// backstop -- re-dispatched every authorized pair unconditionally, with no
/// memory of a pair having just failed. A dead pair's `connect` occupies a
/// concurrency slot for the full connect deadline, every single cycle,
/// forever; enough of them compete with a healthy pair for the same bounded
/// concurrency and the same scheduler attention.
///
/// This pins a bogus peer authorized for far more groups than
/// `MAX_CONCURRENT_SYNCS`, each one truly unreachable (a bound UDP socket
/// that never speaks the protocol, so the dial genuinely hangs rather than
/// being refused instantly) -- and one real, healthy peer with a Change
/// waiting. The healthy pair must converge quickly regardless.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_healthy_group_converges_promptly_despite_many_dead_groups() {
    // Short enough that the test finishes in seconds, not real production
    // minutes. The backstop interval is a process-wide override (read once
    // when `pump` starts), but the connect deadline is set per-instance on
    // `alice_stack` below, once it exists -- see
    // `SyncStack::set_connect_deadline_for_tests`'s own doc comment for why
    // that one specifically must not be process-wide: shortening it out from
    // under some unrelated, concurrently-running test's real network
    // operation would make this test a source of flakiness elsewhere.
    set_default_reconciliation_backstop_interval_for_tests(Duration::from_millis(150));

    let group = FolderGroupId(GROUP.into());
    let (alice, _alice_dir) = device("device-alice", 11);
    let (bob, _bob_dir) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);

    // One bogus peer, authorized for far more groups than
    // `MAX_CONCURRENT_SYNCS` (8) -- accumulated exactly the way the live
    // canary did: a device that keeps creating a fresh group without ever
    // being able to fully leave the old ones.
    let dead_key = SigningKey::from_bytes(&[99u8; 32]).verifying_key().to_bytes();
    let dead_groups: HashSet<String> = (0..20).map(|i| format!("dead-group-{i}")).collect();
    for gid in &dead_groups {
        alice.authority.install_test_group_policy_bootstrap(gid);
    }
    alice.record_peer_signing_key("device-dead", dead_key);
    alice.replace_peer_netmap_metadata(
        "device-dead",
        Some(dead_key),
        &dead_groups,
        &Default::default(),
    );

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
    alice_stack.set_connect_deadline_for_tests(Duration::from_millis(200));

    // A real, bound socket that never answers: sending to it truly hangs
    // (no ICMP port-unreachable the way a closed port would give), so the
    // dial exercises the actual connect-deadline path rather than failing
    // instantly -- exactly what made the dead groups expensive in the field.
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    let dead_peer_id = PeerId::from_bytes(dead_key);
    alice_stack.address_directory().record(dead_peer_id, vec![blackhole_addr], Vec::new());

    // Count dials against the dead peer directly, rather than inferring
    // starvation from the healthy pair's own wall-clock convergence time:
    // whether the healthy pair happens to win a scheduler race in any given
    // window is exactly the kind of thing that makes a timing assertion
    // flaky both ways. How many times the dead peer gets re-dialled at all
    // is not -- with no backoff, a `(peer, group)` pair that just failed is
    // exactly as eligible on the very next backstop tick as one that never
    // ran, so every one of the 20 dead groups gets re-attempted every ~150ms
    // cycle for as long as the test runs.
    let dead_dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let dead_dials = dead_dials.clone();
        alice_stack.when_dial_attempted(Arc::new(move |peer: PeerId| {
            if peer == dead_peer_id {
                dead_dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }

    // Staged before either driver exists -- like
    // `a_driver_reconciles_what_was_already_there_when_it_started`, and
    // deliberately so: the point is what the driver's OWN startup and
    // periodic `Wake::All` do with it, bundled together with the 20 dead
    // pairs in the very same expansion, not a `note_local_change` shortcut
    // that would only ever wake the one (peer, group) pair that matters and
    // never exercise the shared scheduler at all.
    let version = file_version(4096, 0x55);
    let change = change_putting("amid-dead-groups.bin", &version);
    alice
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                1,
            )
        })
        .unwrap();

    alice.install_reconciliation_driver(ReconciliationDriver::start(alice.clone(), alice_stack));
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));

    // A handful of backstop cycles' worth (150ms each), not dozens: with
    // per-pair backoff a dead pair drops out of contention after its first
    // failure, so the healthy pair is essentially uncontested from the
    // second cycle on. Without it, every `Wake::All` cycle re-dispatches all
    // 20 dead pairs alongside the healthy one, and at `MAX_CONCURRENT_SYNCS`
    // == 8 concurrent slots the healthy one is not guaranteed a slot for
    // many cycles running.
    let converged = within(5, || possessed(&bob, &group) == vec![change.compute_hash()]).await;
    assert!(
        converged,
        "a healthy group must not be starved by many dead ones sharing the same scheduler"
    );

    // The deterministic half of this test: not "did the healthy pair happen
    // to win a scheduling race in time" (a timing assertion that can pass by
    // luck either way), but "did the dead peer keep getting re-dialled at
    // all". With per-pair backoff every one of the 20 dead groups is dialled
    // once, fails once, and then sits out the rest of this window; without
    // it, `Wake::All`'s ~150ms backstop re-dispatches all 20 again and again
    // for as long as the daemon runs. Two seconds is over a dozen backstop
    // cycles -- more than enough separation between "dialled ~20 times,
    // total" and "dialled 20 times per cycle".
    tokio::time::sleep(Duration::from_secs(2)).await;
    let dials = dead_dials.load(std::sync::atomic::Ordering::SeqCst);
    // The bound is a multiple of the group count, not `+ 5`. Backoff is a
    // delay, not a permanent exclusion, so a pair whose backoff expires
    // inside this two-second window is *supposed* to be dialled again -- and
    // a fixed five-dial allowance assumed none ever would. It flaked at 26
    // and 27 against a limit of 25, which is not the failure this guards:
    // that one is ~260, one dial per dead group per backstop cycle. Anything
    // within a small multiple of the group count is backoff working.
    assert!(
        dials < dead_groups.len() * 2,
        "dead groups must back off instead of being re-dialled every backstop cycle; \
         saw {dials} dials against {} dead groups over ~13 backstop cycles, where being \
         re-dialled every cycle would be about {}",
        dead_groups.len(),
        dead_groups.len() * 13
    );

    drop(blackhole);
}
