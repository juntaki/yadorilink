//! A file written on one device, reaching the other as a Change it signed
//! itself.
//!
//! `sync_stack_tests` and `driver_tests` stage a Change the fixture built and
//! signed, which answers "does the assembled stack carry a Change". It does
//! not answer "does the product notice a file", and a `Case`'s `Op` is a
//! filesystem operation -- so every scenario the retirement ledger wants to
//! move needs the pipeline production actually runs:
//!
//! ```text
//! a real file on disk
//!   -> LocalChangeProcessor + ChangeEmitter   (a Change this device signed)
//!   -> Pending
//!   -> flush_pending_checkpoint               (Pending -> Published)
//!   -> note_local_change
//!   -> ReconciliationDriver -> SyncStack -> RBSR
//!   -> the peer possesses it
//! ```
//!
//! Two layers, in that order, because they answer different questions and a
//! test that asked both at once would fail pointing at both:
//!
//! * `a_file_written_on_one_device_...` drives the processor once, by hand,
//!   with the event a watcher would have delivered. It covers the capture and
//!   everything after it.
//! * `a_case_shaped_write_converges_...` writes a file and stops. The real
//!   debouncer decides when to flush and the executor publishes and raises
//!   the commit, so nothing in the test body calls `process_flush`,
//!   `flush_pending_checkpoint` or `note_local_change`. That is the shape a
//!   `Case` needs: its `Op::Write` is a filesystem operation and nothing
//!   else.
//!
//! Each has its own control, and neither is decoration. Without them, "a
//! captured Change is servable" would be satisfied by a Change that was
//! already servable, and "the watcher carried it" would be satisfied by any
//! background scan that happened to pick the file up.
//!
//! # Why `Pending` is a step and not a detail
//!
//! A Pending Change is not servable over RBSR. A scenario that captures a
//! local write and goes straight to `note_local_change` has built something
//! the peer can never receive, and it fails as a timeout -- which reads like
//! a network problem. Production does not skip it either: `broadcast_change`
//! flushes the pending checkpoint before it raises the local commit.
//!
//! The flush here goes through the production `flush_pending_checkpoint`,
//! with a stand-in issuer. That primitive verifies every leaf against the
//! checkpoint before attaching anything, so calling it is what exercises the
//! Pending-to-Published transition; attaching evidence directly would skip
//! precisely the code this file exists to cover.

#![cfg(not(turmoil))]

use std::sync::Arc;
use std::time::Duration;

use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_substrate::NetworkConfig;

use super::driver::ReconciliationDriver;
use super::sync_stack::SyncStack;
use crate::checkpoint_source::FlushOutcome;
use crate::daemon_state::DaemonState;
use crate::test_support::layer_probe::{Layer, LayerProbe};
use crate::test_support::sync_stack_fixture::{
    device, init_staging_schema, link_folder, local_capture, pin, possessed, publish_local_pending,
    watch_folder, watch_folder_at, watch_folder_with_pending_flush, FixtureAuthenticator,
    FixtureCheckpointSource, GROUP,
};

/// Writes `contents` into `root` and hands the processor the event a watcher
/// would have produced for it, returning what the capture decided.
///
/// One `process_event`, not a scan: the point is to drive the same entry
/// point the watcher boundary calls, with nothing between the disk write and
/// the capture that could substitute for it.
async fn write_and_capture(
    state: &Arc<DaemonState>,
    root: &std::path::Path,
    relative: &str,
    contents: &[u8],
) -> usize {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the file's parent directory");
    }
    std::fs::write(&path, contents).expect("write the file the device is about to notice");

    let processor = local_capture(state);
    let event = FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified };
    match processor
        .process_event(GROUP, root, &event)
        .await
        .expect("the capture must not error on an ordinary file")
    {
        yadorilink_local_capture::LocalChangeOutcome::FileChanged(_) => 1,
        yadorilink_local_capture::LocalChangeOutcome::FilesChanged(records) => records.len(),
        yadorilink_local_capture::LocalChangeOutcome::None
        | yadorilink_local_capture::LocalChangeOutcome::RetryLater => 0,
    }
}

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

/// The whole chain, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_written_on_one_device_reaches_the_other_as_a_change_it_signed() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);

    let folder = tempfile::tempdir().expect("alice's linked folder");
    // The path the link was made under, which is not necessarily the one the
    // TempDir hands out -- see `link_folder`.
    let alice_root = link_folder(&alice, folder.path());

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
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());

    // 1. A file exists, and the device notices it.
    let captured = write_and_capture(&alice, &alice_root, "notes.txt", b"written on alice").await;
    assert_eq!(
        captured, 1,
        "the local capture did not produce a Change for a file that was written, so nothing \
         below could reach the peer regardless of the network"
    );

    // 2. Pending -> Published, through the production primitive. Until this
    //    happens the Change exists and RBSR will not serve it.
    let before_publish = possessed(&alice, &group);
    let source = FixtureCheckpointSource::for_device(&alice);
    let outcome = publish_local_pending(&alice, &source, GROUP).await;
    assert!(
        matches!(outcome, FlushOutcome::Flushed { batch_size: 1, .. }),
        "the pending checkpoint flush did not publish exactly the one captured Change: \
         {outcome:?}"
    );
    let published = possessed(&alice, &group);
    assert_eq!(
        published.len(),
        before_publish.len() + 1,
        "publishing did not make the captured Change servable, so the peer could never \
         receive it and a convergence failure below would point at the network instead"
    );

    // 3. The one push production makes, and nothing else.
    alice_driver.note_local_change(&group);
    let authored = published
        .iter()
        .find(|hash| !before_publish.contains(hash))
        .copied()
        .expect("the newly published Change");
    assert!(
        within(Duration::from_secs(30), || possessed(&bob, &group).contains(&authored)).await,
        "a Change the device authored from its own filesystem never reached the peer"
    );
}

/// A Change that is captured but never published stays where it is.
///
/// The control for step 2 above. Without it, that assertion would be
/// satisfied by any arrangement in which the Change happened to be servable
/// already, and the claim that the flush is what makes it servable would rest
/// on reading the production code rather than on this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_captured_change_is_not_servable_until_it_is_published() {
    let group = FolderGroupId(GROUP.into());
    let (alice, _alice_store) = device("device-alice", 11);
    init_staging_schema(&alice);
    let folder = tempfile::tempdir().expect("alice's linked folder");
    let alice_root = link_folder(&alice, folder.path());

    let captured = write_and_capture(&alice, &alice_root, "notes.txt", b"written on alice").await;
    assert_eq!(captured, 1);

    assert!(
        possessed(&alice, &group).is_empty(),
        "a captured but unpublished Change was already servable, so the publish step below \
         proves nothing"
    );

    let source = FixtureCheckpointSource::for_device(&alice);
    assert!(matches!(
        publish_local_pending(&alice, &source, GROUP).await,
        FlushOutcome::Flushed { batch_size: 1, .. }
    ));
    assert_eq!(
        possessed(&alice, &group).len(),
        1,
        "publishing is what makes a captured Change servable"
    );
}

/// The same chain, with nothing driven by hand.
///
/// The test above calls `process_event` itself, which proves the capture and
/// everything after it. This one writes a file and stops: the watcher event
/// goes to the real debouncer, which decides when to flush, and the executor
/// publishes and raises the local commit the way `broadcast_change` does.
/// Nothing here calls `process_flush`, `flush_pending_checkpoint` or
/// `note_local_change`.
///
/// That is the shape a `Case` needs. Its `Op::Write` is a filesystem
/// operation and nothing else, so a runner that had to also call the capture
/// would be running a workload the `Case` does not describe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_case_shaped_write_converges_through_the_real_debounce_boundary() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
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
        .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());

    let folder = watch_folder(&alice, &alice_driver);

    // A `Case`'s `Op::Write`, and nothing else.
    folder.write("first.txt", b"the first write").await;
    assert!(
        within(Duration::from_secs(30), || possessed(&bob, &group).len() == 1).await,
        "a file written into a watched folder never reached the peer: the debounce boundary, \
         the capture, the publish or the driver did not carry it"
    );

    // A second write on a second path, so the first is not a one-off that
    // some startup pass happened to sweep up.
    folder.write("second.txt", b"the second write").await;
    assert!(
        within(Duration::from_secs(30), || possessed(&bob, &group).len() == 2).await,
        "a second write did not reach the peer, so the pipeline carries one file rather \
         than running"
    );

    // And a delete, which is the op that reaches the peer as a tombstone
    // rather than as content -- a pipeline that only carried writes would
    // pass everything above.
    // Alice projects her own two Changes too, and that projection must be
    // done before the delete. It is a check of disk against the head, and a
    // head whose file has just been removed looks like a file to write back.
    // Production closes that window with the link's pending-change flush --
    // the projection first forces a queued local event through capture --
    // but this folder is not a registered link runtime, so the flush finds
    // nothing to force. Waiting here keeps the delete what this step
    // measures; the race itself is the next test's.
    assert!(
        within(Duration::from_secs(30), || {
            alice
                .replica_coordinator
                .sqlite()
                .dag_count_pending_projection_obligations(GROUP)
                .unwrap_or(1)
                == 0
        })
        .await,
        "alice never finished projecting her own writes"
    );
    folder.remove("first.txt").await;
    assert!(
        within(Duration::from_secs(30), || possessed(&bob, &group).len() == 3).await,
        "a delete did not reach the peer, so this pipeline carries writes only"
    );
}

/// A delete still waiting out the debounce window when the author's own
/// projection reaches that path is captured first, not written back.
///
/// The test above waits for that projection to finish before deleting, so
/// the delete it measures is only ever the settled case. This one deletes
/// while Alice still owes the projection of her write, and runs the
/// obligation driver inside the delete's debounce quiet period. Her folder
/// is her group's registered link runtime, so the projection's
/// pending-change flush reaches the debouncer holding the delete, as it
/// does in production. Without that flush the head still names content,
/// the file is missing, and the projection writes it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_inside_the_debounce_window_is_captured_before_the_author_projects_over_it() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
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
        .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());
    assert!(
        within(Duration::from_secs(30), || alice.peers.has_session("device-bob")).await,
        "precondition: alice has a content source, so she projects her own writes"
    );

    let folder = watch_folder_with_pending_flush(&alice, &alice_driver);
    let written = folder.path().join("first.txt");

    folder.write("first.txt", b"the first write").await;
    assert!(
        within(Duration::from_secs(30), || possessed(&alice, &group).len() == 1).await,
        "precondition: the write was captured and published"
    );
    assert!(
        alice
            .replica_coordinator
            .sqlite()
            .dag_count_pending_projection_obligations(GROUP)
            .unwrap_or(0)
            > 0,
        "precondition: alice still owes the projection of her own write"
    );
    folder.remove("first.txt").await;
    // The production obligation driver, run now: the delete is still inside
    // its debounce quiet period, so nothing but the pending-change flush can
    // capture it before the projection looks at the path.
    let engine = crate::convergence::engine::ConvergenceEngine::new(alice.clone());
    crate::convergence::engine::drive_obligations_once_for_test(&engine, 128, 256).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        assert!(!written.exists(), "alice's own projection wrote back a file she had just deleted");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Whichever path captured the delete, it reaches the peer once published.
    let source = FixtureCheckpointSource::for_device(&alice);
    publish_local_pending(&alice, &source, GROUP).await;
    alice_driver.note_local_change(&group);
    assert!(
        within(Duration::from_secs(30), || possessed(&bob, &group).len() == 2).await,
        "the delete never reached the peer"
    );
}

/// A file that appears on disk without the watcher saying so does not
/// propagate.
///
/// The control for the test above, and it is not a formality. If a startup
/// scan, a periodic sweep or the driver's own backstop were picking files up,
/// every assertion there would pass with the debounce boundary disconnected
/// and the test would be measuring something other than what it names. This
/// says the event is load-bearing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_the_watcher_never_reported_does_not_propagate() {
    let group = FolderGroupId(GROUP.into());

    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
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
        .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    bob.install_reconciliation_driver(ReconciliationDriver::start(bob.clone(), bob_stack));
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());

    let folder = watch_folder(&alice, &alice_driver);

    // Straight to disk. No event.
    std::fs::write(folder.path().join("unseen.txt"), b"nobody reported this")
        .expect("write the file the watcher will not mention");

    assert!(
        !within(Duration::from_secs(5), || !possessed(&bob, &group).is_empty()).await,
        "a file the watcher never reported reached the peer anyway, so something other than \
         the debounce boundary is picking files up and the sibling test is not measuring what \
         it names"
    );

    // And the same file, once reported, does propagate -- so the negative
    // above is about the missing event and not about the file.
    folder.write("unseen.txt", b"nobody reported this").await;
    assert!(
        within(Duration::from_secs(30), || possessed(&bob, &group).len() == 1).await,
        "the same write propagated once the watcher reported it, which is what makes the \
         assertion above attributable to the missing event"
    );
}

/// Where a Change stops, measured at every layer between RBSR and disk.
///
/// A single "the file did not appear" assertion cannot say which component
/// is at fault, and guessing from it cost a wrong conclusion once already: I
/// read an empty `file_index` on an *unlinked* device as evidence that the
/// apply path was missing from the architecture. It was evidence that the
/// device had no link, which is correct store-and-forward behaviour.
///
/// So this walks the path and reports the first layer that did not advance:
///
/// ```text
/// 1 RBSR possession      verified staging holds the hash
/// 2 Admission            the canonical DAG holds it
/// 3 Projection scheduled a projection obligation exists
/// 4 Projection closed    no obligation is left pending
/// 5 Local projection     file_index has the path
/// 6 Content              the bytes on disk match
/// ```
///
/// Both devices are fully linked here -- link row, adopted root token,
/// startup readiness and a live root-commit authority -- because a device
/// missing any of those is not a device that should project, and a scenario
/// built on one measures the fixture rather than the product.
///
/// # Where the content comes from
///
/// Layer 4 is closed by the convergence engine fetching the file's blocks
/// from a peer session. Neither device here has a legacy QUIC transport at
/// all -- no legacy endpoint, no legacy channel, no session registered by
/// the test. Each device's session for the other exists because the peer is
/// pinned and its own iroh endpoint reaches it, which is the only rule
/// production has. A device assembled from `SyncStack` and its driver is
/// therefore a whole device, not a fixture short of one.
///
/// When this was first written the sessions could only come from a legacy
/// dial, and it stopped at layer 4 with the obligation raised and never
/// closed. It must not be made to pass by registering a session in the
/// fixture: that would test the fixture, and hide a regression back to a
/// transport that decides whether content can flow.
///
/// Measured before landing on the relay-only path too: see
/// [`a_written_file_reaches_the_peers_disk_through_a_relay_alone`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_written_file_advances_through_every_layer_to_the_peers_disk() {
    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
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
        .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    let bob_driver = ReconciliationDriver::start(bob.clone(), bob_stack);
    bob.install_reconciliation_driver(bob_driver.clone());
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());

    // Both devices are linked. Bob is the one that has to project, and a Bob
    // without a link would hold and serve the Change and write nothing --
    // correct store-and-forward, and not what this test is about.
    let alice_folder = watch_folder(&alice, &alice_driver);
    let bob_folder = watch_folder(&bob, &bob_driver);

    let contents = b"written on alice, expected on bob";
    alice_folder.write("notes.txt", contents).await;

    // One probe, read repeatedly, so the transient layer-3 obligation is
    // latched rather than sampled once after the fact.
    let probe = LayerProbe::new(&bob, GROUP).with_root(bob_folder.path());

    assert!(
        within(Duration::from_secs(60), || !probe.servable().is_empty()).await,
        "layer 1: the Change never reached the peer's verified staging"
    );
    let hash = probe.servable()[0];
    let report = |probe: &LayerProbe| probe.report(&hash, "notes.txt");

    assert!(
        within(Duration::from_secs(60), || report(&probe).in_canonical_dag).await,
        "{}",
        report(&probe)
    );
    assert!(
        within(Duration::from_secs(30), || probe.report(&hash, "notes.txt").was_scheduled()).await,
        "{}",
        report(&probe)
    );
    assert!(
        within(Duration::from_secs(90), || probe.pending_obligations() == 0).await,
        "{}",
        report(&probe)
    );
    assert!(
        within(Duration::from_secs(60), || matches!(report(&probe).disk, Some(Some(_)))).await,
        "{}",
        report(&probe)
    );
    assert_eq!(
        report(&probe).disk,
        Some(Some(contents.to_vec())),
        "layer 6: the file appeared on the peer with the wrong bytes, which is worse than not \
         appearing"
    );
}

/// A peer with no content source still receives the Change, admits it, and
/// schedules its projection.
///
/// Layers 1-3 of the walk above, on their own.
///
/// Not a lesser copy of it: these are the layers a test about a *gate*
/// (pause, authorization, a partition) has to be able to assert on
/// positively, because "nothing arrived" and "it arrived and was held" are
/// different verdicts and only the second one says a gate did anything.
/// Keeping them in a test of their own means a gate test can cite a layer
/// without also depending on projection having run.
///
/// Deliberately stops at layer 3 rather than asserting that the obligation
/// stays pending. It does not stay pending: since G2 a device with a session
/// projects, so an assertion that it waits would have been a test of the
/// pre-cutover structure with a short life. This asserts only what holds on
/// both sides of the cutover, which is why it needed no change when G2
/// landed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_admits_a_change_and_schedules_its_projection() {
    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
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
        .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), NetworkConfig::direct_only())
            .await
            .expect("bob's stack starts"),
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    let bob_driver = ReconciliationDriver::start(bob.clone(), bob_stack);
    bob.install_reconciliation_driver(bob_driver.clone());
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());

    let alice_folder = watch_folder(&alice, &alice_driver);
    let bob_folder = watch_folder(&bob, &bob_driver);
    alice_folder.write("notes.txt", b"written on alice").await;

    let probe = LayerProbe::new(&bob, GROUP).with_root(bob_folder.path());
    assert!(
        within(Duration::from_secs(60), || !probe.servable().is_empty()).await,
        "layer 1: the Change never reached the peer's verified staging"
    );
    let hash = probe.servable()[0];

    assert!(
        within(Duration::from_secs(60), || probe.in_canonical_dag(&hash)).await,
        "{}",
        probe.report(&hash, "notes.txt")
    );
    assert!(
        within(Duration::from_secs(60), || probe.report(&hash, "notes.txt").was_scheduled()).await,
        "{}",
        probe.report(&hash, "notes.txt")
    );

    let reached = probe.report(&hash, "notes.txt").deepest();
    assert!(
        reached >= Some(Layer::ObligationRaised),
        "the peer got no further than {reached:?}\n{}",
        probe.report(&hash, "notes.txt")
    );
}

/// The same walk, with a relay as the only carrier between the two devices.
///
/// Bob's endpoint has no IP transport at all, so the connection his session
/// lives on, the reconciliation that delivers the Change and the block fetch
/// that delivers the file's bytes can each only go through the relay. The
/// relay is a real iroh relay server running in this process -- the same
/// server software a deployment runs, reached over loopback -- so the
/// relayed path is iroh's own, not a stand-in for it.
///
/// Content, not just metadata: the file is larger than anything a Change
/// carries, and Bob's session must have received its bytes as block content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_written_file_reaches_the_peers_disk_through_a_relay_alone() {
    use yadorilink_sync_substrate::testing::InProcessRelay;

    use crate::peer_registry::PeerReachability;
    use crate::route::RouteKind;

    let group = FolderGroupId(GROUP.into());
    let relay = InProcessRelay::start().await.expect("the in-process relay starts");

    let (alice, _alice_store) = device("device-alice", 11);
    let (bob, _bob_store) = device("device-bob", 22);
    for state in [&alice, &bob] {
        init_staging_schema(state);
    }
    pin(&alice, "device-bob", 22);
    pin(&bob, "device-alice", 11);

    let alice_stack = Arc::new(
        SyncStack::spawn(alice.clone(), Arc::new(FixtureAuthenticator), relay.direct_or_relay())
            .await
            .expect("alice's stack starts"),
    );
    let bob_stack = Arc::new(
        SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), relay.relay_only())
            .await
            .expect("bob's stack starts"),
    );
    // Each side's address as it will be published: only once both have
    // registered with the relay does it include the relay at all.
    assert!(
        within(Duration::from_secs(30), || {
            alice_stack.local_address().relay_urls().next().is_some()
                && bob_stack.local_address().relay_urls().next().is_some()
        })
        .await,
        "both devices register with the relay"
    );
    assert_eq!(
        bob_stack.local_address().direct_addrs().count(),
        0,
        "precondition: bob has no direct address to offer, so nothing can reach him but the relay"
    );
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    let bob_driver = ReconciliationDriver::start(bob.clone(), bob_stack);
    bob.install_reconciliation_driver(bob_driver.clone());
    let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
    alice.install_reconciliation_driver(alice_driver.clone());

    let alice_folder = watch_folder(&alice, &alice_driver);
    let bob_folder = watch_folder(&bob, &bob_driver);

    // Several blocks' worth, and no two blocks alike.
    let contents: Vec<u8> =
        (0..300 * 1024u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    alice_folder.write("relayed.bin", &contents).await;

    assert!(
        within(Duration::from_secs(60), || !possessed(&bob, &group).is_empty()).await,
        "the Change never reached the peer's verified staging over the relay"
    );
    let on_bobs_disk = bob_folder.path().join("relayed.bin");
    assert!(
        within(Duration::from_secs(90), || {
            std::fs::read(&on_bobs_disk).is_ok_and(|bytes| bytes == contents)
        })
        .await,
        "the file never appeared on the peer's disk with the author's bytes"
    );

    let session = bob.peers.session("device-alice").expect("bob's session for alice");
    assert!(
        session.content_bytes_received() > 0,
        "the bytes must have arrived as block content from the peer's session"
    );
    assert_eq!(
        bob.peer_connectivity.reachability("device-alice"),
        Some(PeerReachability::Connected(RouteKind::Relay)),
        "and the only connection bob has to alice is the relayed one"
    );
}

/// A folder reached through a symlink is still the folder the capture watches.
///
/// This is the macOS tempdir, reproduced on any Unix. There,
/// `tempfile::tempdir()` returns `/var/folders/...`, and `/var` is a symlink
/// to `/private/var` -- so the path the test holds and the path the capture
/// canonicalises are different strings naming one directory. `process_flush`
/// resolves each event relative to the root it was given, so an event carrying
/// the uncanonical path lands outside that root and is dropped, and the device
/// produces no Change at all.
///
/// The symptom is indistinguishable from a broken capture pipeline: four tests
/// in this file failed on macOS with "the local capture did not produce a
/// Change ... left: 0 right: 1" while passing here, because `/tmp` on Linux is
/// already canonical and the two strings coincide. Found by the macOS lane,
/// not locally, which is the only way this class gets found -- so it gets a
/// test that does not need a Mac to fail.
///
/// [`WatchedFolder::path`] now returns the canonical path and the uncanonical
/// one is not reachable, which is the actual fix; this holds that in place.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folder_reached_through_a_symlink_is_still_captured() {
    let group = FolderGroupId(GROUP.into());
    let (alice, _alice_store) = device("device-alice", 11);
    init_staging_schema(&alice);

    let stack = Arc::new(
        SyncStack::spawn(
            alice.clone(),
            Arc::new(FixtureAuthenticator),
            NetworkConfig::direct_only(),
        )
        .await
        .expect("alice's stack starts"),
    );
    let driver = ReconciliationDriver::start(alice.clone(), stack);
    alice.install_reconciliation_driver(driver.clone());

    // The real directory, and a second name for it that is not canonical.
    let real = tempfile::tempdir().expect("the real folder");
    let elsewhere = tempfile::tempdir().expect("somewhere to put the link");
    let linked = elsewhere.path().join("by-another-name");
    std::os::unix::fs::symlink(real.path(), &linked).expect("link the folder");
    assert_ne!(
        linked,
        linked.canonicalize().expect("the link resolves"),
        "this test needs a root whose path is not its own canonical path"
    );

    let folder = watch_folder_at(&alice, &driver, &linked);
    folder.write("through-the-link.txt", b"captured or not").await;

    assert!(
        within(Duration::from_secs(30), || !possessed(&alice, &group).is_empty()).await,
        "a file written through a symlinked root produced no Change: the capture is rooted at \
         the canonical path, so an event naming the file any other way falls outside it"
    );
}

/// The same trap on the hand-driven route: the root a test keeps must be the
/// root the link was made under.
///
/// Two routes into the capture, and the first fix only closed one. `link_folder`
/// registers the link row, the adopted root token and the readiness gate under
/// the *canonical* path, while `process_event` resolves an event against
/// whatever root its caller hands it. A test that linked `/var/...` and then
/// captured against `/var/...` is describing a folder the daemon has no link
/// for, and captures nothing -- even though its own two paths agree with each
/// other, which is what makes it look right.
///
/// So this is not the same test as the `WatchedFolder` one above: that one is
/// about the event path disagreeing with the watch root, this one is about the
/// capture root disagreeing with the link. Both show up on macOS as "left: 0,
/// right: 1" and neither shows up on Linux without a symlink.
///
/// `link_folder` returning the canonical path, `#[must_use]`, is the fix; this
/// holds it in place.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hand_driven_capture_uses_the_root_the_link_was_made_under() {
    let (alice, _alice_store) = device("device-alice", 11);
    init_staging_schema(&alice);

    let real = tempfile::tempdir().expect("the real folder");
    let elsewhere = tempfile::tempdir().expect("somewhere to put the link");
    let linked = elsewhere.path().join("by-another-name");
    std::os::unix::fs::symlink(real.path(), &linked).expect("link the folder");

    let root = link_folder(&alice, &linked);
    assert_ne!(root, linked, "this test needs a root that is not its own canonical path");

    assert_eq!(
        write_and_capture(&alice, &root, "notes.txt", b"written on alice").await,
        1,
        "the capture produced no Change for a file that was written: the root it was given is \
         not the one the link was made under, so there is no link for the folder it describes"
    );
}
