//! Two devices that stand on different history bases, reconciling through
//! the assembled stack.
//!
//! A change is only meaningful on the history it was written on: its
//! author position, its Lamport value and its parents all describe that
//! history and nothing else. Two peers that do not share a base therefore
//! have nothing to reconcile change by change -- what they have is two
//! summaries to merge, and that is a different operation with a different
//! trust boundary.
//!
//! What these tests pin is what a peer's *claim* about its base is allowed
//! to cause. It may stop ordinary exchange. It may not move this device
//! onto another base, install anything, or start a merge.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId};
use yadorilink_replica_engine::compaction::Checkpoint;
use yadorilink_replica_engine::rebootstrap::{HistoryBase, HistoryEpoch};
use yadorilink_replica_engine::rebootstrap_snapshot::{RebootstrapSnapshot, SnapshotAuthorState};
use yadorilink_sync_sqlite::rebootstrap_store::{self, RebootstrapStoreRepository};
use yadorilink_sync_substrate::NetworkConfig;

use super::sync_stack::{SyncAttempt, SyncStack};
use crate::daemon_state::DaemonState;
use crate::test_support::sync_stack_fixture::{
    author_key, device, honest_bundle, init_staging_schema, pin, possessed, stage,
    FixtureAuthenticator, DEVICE, GROUP,
};

/// Seals a history base on `state` the way a local compaction commits one,
/// over an empty frontier, carrying `author_state` as its summary.
///
/// `lamport_ceiling` distinguishes one base from another: two calls with
/// different ceilings seal two different bases of the same group.
fn seal_base(
    state: &DaemonState,
    author_state: Vec<SnapshotAuthorState>,
    lamport_ceiling: u64,
) -> HistoryBase {
    let group = FolderGroupId(GROUP.into());
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        author_state,
        Vec::new(),
        lamport_ceiling,
    )
    .expect("an empty snapshot is well formed");
    let checkpoint = Checkpoint::new(group, Vec::new(), snapshot.snapshot_hash());
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            rebootstrap_store::commit_compaction_snapshot(tx, &checkpoint, &snapshot, &[])
        })
        .expect("the base commits");
    HistoryBase::from_checkpoint(&checkpoint)
}

/// The author positions the sealed bases carry. A base that cannot say
/// where its authors stand is not a base this device will advertise.
fn base_authors() -> Vec<SnapshotAuthorState> {
    vec![SnapshotAuthorState {
        device_id: "device-base-author".into(),
        watermark: AuthorSeq(1),
        tip_change_hash: yadorilink_replica_domain::ids::ChangeHash([0x11; 32]),
    }]
}

fn installed_base(state: &DaemonState) -> Option<HistoryBase> {
    RebootstrapStoreRepository::new(state.replica_coordinator.database().clone())
        .history_base(GROUP)
        .expect("the base is readable")
}

/// A change written on `epoch`, signed by the fixture author.
fn change_on(epoch: HistoryEpoch, seq: u64) -> Change {
    Change::create_signed(
        Vec::new(),
        0,
        DeviceId(DEVICE.into()),
        AuthorSeq(seq),
        None,
        FolderGroupId(GROUP.into()),
        epoch,
        vec![yadorilink_replica_domain::change::Op::Delete {
            path: yadorilink_replica_domain::ids::SyncPath(format!("file-{seq}.txt")),
        }],
        &author_key(),
    )
}

struct Pair {
    alice: Arc<DaemonState>,
    bob: Arc<DaemonState>,
    alice_stack: Arc<SyncStack>,
    bob_stack: Arc<SyncStack>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn pair() -> Pair {
    let (alice, alice_dir) = device("device-alice", 11);
    let (bob, bob_dir) = device("device-bob", 22);
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
    {
        let peer = alice_stack.local_address();
        bob_stack.address_directory().record(
            peer.peer(),
            peer.direct_addrs().copied().collect(),
            peer.relay_urls().map(ToString::to_string).collect(),
        );
    }
    Pair { alice, bob, alice_stack, bob_stack, _dirs: (alice_dir, bob_dir) }
}

async fn bob_syncs_with_alice(pair: &Pair) -> SyncAttempt {
    tokio::time::timeout(
        Duration::from_secs(30),
        pair.bob_stack.sync_with("device-alice", &FolderGroupId(GROUP.into())),
    )
    .await
    .expect("the sync must not hang")
    .expect("a differing base is an outcome, not a transport failure")
}

/// Alice has sealed a base and written on it. Bob is still on the group's
/// original history. Nothing Alice holds is a change Bob could admit, and
/// nothing about the session may move either of them off their own base.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_on_a_foreign_history_base_exchanges_no_changes() {
    let pair = pair().await;
    let group = FolderGroupId(GROUP.into());

    let alice_base = seal_base(&pair.alice, base_authors(), 7);
    let alice_change = change_on(HistoryEpoch::Base(alice_base), 1);
    stage(&pair.alice, honest_bundle(alice_change.clone()), 1);
    assert_eq!(possessed(&pair.alice, &group), vec![alice_change.compute_hash()]);

    let attempt = bob_syncs_with_alice(&pair).await;

    assert!(
        possessed(&pair.bob, &group).is_empty(),
        "a change written on a base bob does not hold must not reach him as an ordinary \
         change; the session ended as {attempt:?}"
    );
    assert_eq!(installed_base(&pair.bob), None, "bob must still stand on his own history");
    assert_eq!(installed_base(&pair.alice), Some(alice_base), "alice must keep her own base");

    // The outcome says so explicitly, rather than passing for a quiet sync.
    assert!(matches!(attempt, SyncAttempt::MergeRequired), "{attempt:?}");

    // Both sides hold the other's claim as merge-required state, measured
    // against the base each stands on now.
    let bob_sees = pair.bob_stack.foreign_bases().merge_required(&group, HistoryEpoch::Genesis);
    assert_eq!(bob_sees.len(), 1, "{bob_sees:?}");
    assert_eq!(bob_sees[0].peer_device, "device-alice");
    assert_eq!(bob_sees[0].claim.epoch(), HistoryEpoch::Base(alice_base));

    let alice_sees =
        pair.alice_stack.foreign_bases().merge_required(&group, HistoryEpoch::Base(alice_base));
    assert_eq!(alice_sees.len(), 1, "{alice_sees:?}");
    assert_eq!(alice_sees[0].peer_device, "device-bob");
    assert_eq!(alice_sees[0].claim.epoch(), HistoryEpoch::Genesis);

    // Asking again changes nothing: the claim is never promoted into an
    // install or a switch, however often it is heard.
    let again = bob_syncs_with_alice(&pair).await;
    assert!(matches!(again, SyncAttempt::MergeRequired), "{again:?}");
    assert!(possessed(&pair.bob, &group).is_empty());
    assert_eq!(installed_base(&pair.bob), None);
}

/// Once both devices stand on the same base, the earlier claim no longer
/// describes the peer: ordinary reconciliation resumes and the
/// merge-required state is cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_that_come_to_share_a_base_reconcile_and_drop_the_claim() {
    let pair = pair().await;
    let group = FolderGroupId(GROUP.into());

    let alice_base = seal_base(&pair.alice, base_authors(), 7);
    let alice_change = change_on(HistoryEpoch::Base(alice_base), 1);
    stage(&pair.alice, honest_bundle(alice_change.clone()), 1);

    let first = bob_syncs_with_alice(&pair).await;
    assert!(matches!(first, SyncAttempt::MergeRequired), "{first:?}");

    // Bob comes to stand on the very same base.
    assert_eq!(seal_base(&pair.bob, base_authors(), 7), alice_base);

    let summary =
        bob_syncs_with_alice(&pair).await.expect_ran("same base: ordinary reconciliation");
    assert_eq!(summary.wanted, 1);
    assert_eq!(possessed(&pair.bob, &group), vec![alice_change.compute_hash()]);
    assert!(
        pair.bob_stack
            .foreign_bases()
            .merge_required(&group, HistoryEpoch::Base(alice_base))
            .is_empty(),
        "a peer found on this device's base is no longer merge-required"
    );
    assert!(
        pair.bob_stack.foreign_bases().merge_required(&group, HistoryEpoch::Genesis).is_empty(),
        "and the claim heard before the switch is gone, not merely filtered"
    );
}

/// The same base with two different summaries is a contradiction: one
/// side is corrupt or lying. The session is refused, nothing is
/// exchanged, and nothing is recorded as merge-required.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_base_with_two_summaries_is_refused_and_records_nothing() {
    let pair = pair().await;
    let group = FolderGroupId(GROUP.into());

    let base = seal_base(&pair.alice, base_authors(), 7);
    assert_eq!(seal_base(&pair.bob, base_authors(), 7), base);
    stage(&pair.alice, honest_bundle(change_on(HistoryEpoch::Base(base), 1)), 1);

    // Bob's copy of the base's summary is altered in place.
    corrupt_base_summary(&pair.bob);

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        pair.bob_stack.sync_with("device-alice", &group),
    )
    .await
    .expect("the sync must not hang");
    let error = match result {
        Err(error) => error.to_string(),
        Ok(attempt) => panic!("a contradictory base must be refused, got {attempt:?}"),
    };
    assert!(error.contains("different summaries"), "{error}");

    assert!(possessed(&pair.bob, &group).is_empty(), "nothing was exchanged");
    for stack in [&pair.alice_stack, &pair.bob_stack] {
        assert!(stack.foreign_bases().merge_required(&group, HistoryEpoch::Base(base)).is_empty());
    }
    assert_eq!(installed_base(&pair.bob), Some(base));
}

/// Alters `state`'s copy of its base's summary in place, so the same base
/// is advertised with a summary no honest peer holds.
fn corrupt_base_summary(state: &DaemonState) {
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE history_base_meta SET lamport_ceiling = lamport_ceiling + 1 \
                 WHERE group_id = ?1",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
}

/// A refused negotiation is the latest word on the peer, and it says
/// nothing about which base the peer stands on. Whatever the peer claimed
/// before must not outlive it as merge-required state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_negotiation_drops_the_peers_earlier_claim() {
    let pair = pair().await;
    let group = FolderGroupId(GROUP.into());

    // Bob stands on a base whose summary is not the honest one; Alice is
    // still on the original history.
    let base = seal_base(&pair.bob, base_authors(), 7);
    corrupt_base_summary(&pair.bob);

    let first = bob_syncs_with_alice(&pair).await;
    assert!(matches!(first, SyncAttempt::MergeRequired), "{first:?}");
    assert_eq!(
        pair.bob_stack.foreign_bases().merge_required(&group, HistoryEpoch::Base(base)).len(),
        1
    );

    // Alice comes to the same base with the honest summary: the two
    // advertisements now contradict each other and the session is refused.
    assert_eq!(seal_base(&pair.alice, base_authors(), 7), base);
    let refused = tokio::time::timeout(
        Duration::from_secs(30),
        pair.bob_stack.sync_with("device-alice", &group),
    )
    .await
    .expect("the sync must not hang");
    let error = match refused {
        Err(error) => error.to_string(),
        Ok(attempt) => panic!("a contradictory base must be refused, got {attempt:?}"),
    };
    assert!(error.contains("different summaries"), "{error}");

    let stale = pair.bob_stack.foreign_bases().merge_required(&group, HistoryEpoch::Base(base));
    assert!(stale.is_empty(), "a refused peer is not someone to merge with: {stale:?}");
}

/// A device that is no longer a member of the group is nobody to merge
/// with, whatever it claimed while it still was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_peers_claim_is_not_reported() {
    let pair = pair().await;
    let group = FolderGroupId(GROUP.into());

    seal_base(&pair.alice, base_authors(), 7);
    let attempt = bob_syncs_with_alice(&pair).await;
    assert!(matches!(attempt, SyncAttempt::MergeRequired), "{attempt:?}");
    assert_eq!(
        pair.bob_stack.foreign_bases().merge_required(&group, HistoryEpoch::Genesis).len(),
        1
    );

    // Alice loses her membership of the group on Bob's side.
    pair.bob.replace_peer_netmap_metadata(
        "device-alice",
        Some(ed25519_dalek::SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes()),
        &Default::default(),
        &Default::default(),
    );

    let reported = pair.bob_stack.foreign_bases().merge_required(&group, HistoryEpoch::Genesis);
    assert!(reported.is_empty(), "a revoked device is not someone to merge with: {reported:?}");
}
