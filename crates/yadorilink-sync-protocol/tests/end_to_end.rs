//! The protocol end to end, over an in-memory duplex.

mod support;

use std::collections::BTreeSet;
use std::time::Duration;

use support::{group, id, payload_for, MockReplica, PEER_A, PEER_B};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_rbsr::ItemId;
use yadorilink_sync_protocol::ports::PeerKey;
use yadorilink_sync_protocol::session::{
    reconcile, request_bundles, serve_bundles, ReconcileOutcome, Reconciled, Role, SessionConfig,
};
use yadorilink_sync_protocol::wire;

const PIPE: usize = 64 * 1024;

/// Reconcile both sides at once and return each side's view.
async fn reconcile_pair(
    left: &MockReplica,
    right: &MockReplica,
) -> (
    Result<Reconciled, yadorilink_sync_protocol::ProtocolError>,
    Result<Reconciled, yadorilink_sync_protocol::ProtocolError>,
) {
    let (mut a, mut b) = tokio::io::duplex(PIPE);
    let config = SessionConfig::default();
    let group = group();

    let (mine, theirs) = tokio::join!(
        reconcile(&mut a, left, PeerKey(PEER_B), &group, Role::Initiator, &config),
        reconcile(&mut b, right, PeerKey(PEER_A), &group, Role::Responder, &config),
    );
    let same_base = |outcome: ReconcileOutcome| outcome.expect_reconciled("same base");
    (mine.map(same_base), theirs.map(same_base))
}

/// One full sync in one direction: reconcile, then fetch what we are missing.
async fn sync_once(local: &MockReplica, remote: &MockReplica) -> Vec<ItemId> {
    let (mine, _theirs) = reconcile_pair(local, remote).await;
    let mine = mine.expect("reconciliation");

    if mine.want.is_empty() {
        return Vec::new();
    }

    let (mut a, mut b) = tokio::io::duplex(PIPE);
    let config = SessionConfig::default();
    let group = group();
    let (staged, served) = tokio::join!(
        request_bundles(&mut a, local, PeerKey(PEER_B), &group, &mine.want, &config),
        serve_bundles(&mut b, remote, PeerKey(PEER_A), &group),
    );
    served.expect("serving");
    staged.expect("staging")
}

#[tokio::test]
async fn two_peers_that_already_agree_settle_without_naming_anything() {
    let shared: Vec<ItemId> = (0..200).map(id).collect();
    let left = MockReplica::with(shared.clone());
    let right = MockReplica::with(shared);

    let (mine, theirs) = reconcile_pair(&left, &right).await;
    let mine = mine.unwrap();
    let theirs = theirs.unwrap();

    assert!(mine.is_settled(), "nothing to exchange: {mine:?}");
    assert!(theirs.is_settled());
    assert_eq!(mine.rounds, 1, "one fingerprint should settle it");
}

#[tokio::test]
async fn reconciliation_over_the_wire_finds_the_exact_difference() {
    let only_left: Vec<ItemId> = (0..40).map(id).collect();
    let only_right: Vec<ItemId> = (1000..1007).map(id).collect();
    let shared: Vec<ItemId> = (500..560).map(id).collect();

    let left = MockReplica::with(only_left.iter().chain(&shared).copied());
    let right = MockReplica::with(only_right.iter().chain(&shared).copied());

    let (mine, theirs) = reconcile_pair(&left, &right).await;
    let mine = mine.unwrap();
    let theirs = theirs.unwrap();

    assert_eq!(
        mine.want.iter().copied().collect::<BTreeSet<_>>(),
        only_right.iter().copied().collect()
    );
    assert_eq!(
        mine.offer.iter().copied().collect::<BTreeSet<_>>(),
        only_left.iter().copied().collect()
    );
    assert_eq!(
        theirs.want.iter().copied().collect::<BTreeSet<_>>(),
        only_left.iter().copied().collect()
    );
    assert_eq!(
        theirs.offer.iter().copied().collect::<BTreeSet<_>>(),
        only_right.iter().copied().collect()
    );
}

#[tokio::test]
async fn a_full_sync_makes_the_two_sides_hold_the_same_set() {
    let left = MockReplica::with((0..50).map(id));
    let right = MockReplica::with((25..90).map(id));

    let staged = sync_once(&left, &right).await;
    assert_eq!(staged.len(), 40, "the 40 identifiers only the peer held");

    let after_left = left.possessed();
    assert!(
        (0..90).map(id).all(|hash| after_left.contains(&hash)),
        "everything either side held is now held locally"
    );

    // A second sync has nothing to do — the convergence is real, not a
    // transfer that keeps repeating itself.
    let again = sync_once(&left, &right).await;
    assert!(again.is_empty(), "a converged pair must transfer nothing further");
}

/// A fingerprint reveals whether two sets agree, and a difference across a
/// range reveals that a peer is missing something there. Both are disclosures,
/// so entitlement is settled before the first fingerprint exists — not after.
#[tokio::test]
async fn an_unentitled_peer_is_refused_before_any_fingerprint_reaches_the_wire() {
    let local = MockReplica::with((0..50).map(id)).undisclosable();
    let (mut a, mut b) = tokio::io::duplex(PIPE);

    let result = reconcile(
        &mut a,
        &local,
        PeerKey(PEER_B),
        &group(),
        Role::Initiator,
        &SessionConfig::default(),
    )
    .await;

    assert!(
        matches!(result, Err(yadorilink_sync_protocol::ProtocolError::NotDisclosable { .. })),
        "expected a refusal, got {result:?}"
    );

    // Nothing at all was written: not a fingerprint, not an empty round, not
    // a rejection frame that would itself confirm the group exists here.
    let mut leaked = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(200), b.read(&mut leaked)).await;
    assert!(
        read.is_err(),
        "a refused reconciliation must put no bytes on the wire, saw {leaked:?}"
    );
}

#[tokio::test]
async fn a_peer_that_may_not_be_served_gets_no_bundles() {
    let local = MockReplica::with((0..10).map(id)).undisclosable();
    let (mut a, mut b) = tokio::io::duplex(PIPE);

    let wanted: Vec<ItemId> = (0..3).map(id).collect();
    let group = group();
    let config = SessionConfig::default();
    let empty = MockReplica::with([]);
    // Only the serving side is driven to completion. The requester writes its
    // request and then waits for an answer that will never come, which is
    // what a refusal looks like from its side: in production the substrate
    // closes the stream. Driving both to completion here would deadlock, and
    // the requester's own behaviour is covered by the other tests.
    let requester = request_bundles(&mut a, &empty, PeerKey(PEER_B), &group, &wanted, &config);
    tokio::pin!(requester);

    let served = tokio::select! {
        served = serve_bundles(&mut b, &local, PeerKey(PEER_A), &group) => served,
        _ = &mut requester => panic!("the requester must not complete before the server answers"),
    };

    assert!(matches!(served, Err(yadorilink_sync_protocol::ProtocolError::NotDisclosable { .. })));
    assert_eq!(
        local.serve_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing may even be loaded for a peer that may not be served"
    );
}

/// A peer may only answer what it was asked. Anything else is work we never
/// agreed to verify, pushed at us.
#[tokio::test]
async fn a_bundle_that_was_never_requested_is_refused() {
    let local = MockReplica::with([]);
    let (mut a, mut b) = tokio::io::duplex(PIPE);

    let wanted = vec![id(1)];
    let requester = async {
        request_bundles(
            &mut a,
            &local,
            PeerKey(PEER_B),
            &group(),
            &wanted,
            &SessionConfig::default(),
        )
        .await
    };

    let rogue = async {
        // Read and ignore the request, then answer with something else.
        let mut length = [0u8; 4];
        b.read_exact(&mut length).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
        b.read_exact(&mut body).await.unwrap();

        let unwanted = wire::OpaqueBundle { change_hash: id(999), payload: payload_for(&id(999)) };
        b.write_all(&wire::encode_bundle(&unwanted).unwrap()).await.unwrap();
        b.shutdown().await.unwrap();
    };

    let (result, ()) = tokio::join!(requester, rogue);
    assert!(matches!(result, Err(yadorilink_sync_protocol::ProtocolError::UnrequestedBundle)));
    assert!(local.possessed().is_empty(), "and nothing was staged");
}

/// Staging is all-or-nothing across the delivery, so a corrupted bundle at the
/// back cannot get the good ones at the front accepted.
#[tokio::test]
async fn a_delivery_that_fails_verification_stages_none_of_itself() {
    let local = MockReplica::with([]).rejecting_staging();
    let remote = MockReplica::with((0..20).map(id));

    let (mine, _) = reconcile_pair(&local, &remote).await;
    let wanted = mine.unwrap().want;
    assert_eq!(wanted.len(), 20);

    let (mut a, mut b) = tokio::io::duplex(PIPE);
    let group = group();
    let config = SessionConfig::default();
    let (staged, _served) = tokio::join!(
        request_bundles(&mut a, &local, PeerKey(PEER_B), &group, &wanted, &config),
        serve_bundles(&mut b, &remote, PeerKey(PEER_A), &group),
    );

    assert!(staged.is_err(), "a failed delivery must be refused");
    assert!(local.possessed().is_empty(), "and must leave nothing behind");
}

/// Nothing in a session is load-bearing. Cutting the connection at any point
/// costs the work in flight and nothing else: the next session recomputes the
/// same difference from durable state.
#[tokio::test]
async fn a_session_cut_mid_reconciliation_costs_only_the_work_in_flight() {
    let left = MockReplica::with((0..300).map(id));
    let right = MockReplica::with((150..500).map(id));

    let group = group();
    let full = SessionConfig::default();

    for cut_after in 0..6 {
        let (mut a, mut b) = tokio::io::duplex(PIPE);
        let config = SessionConfig { max_rounds: cut_after, ..SessionConfig::default() };

        // The initiator is cut off after `cut_after` rounds. The responder is
        // then waiting on a peer that will never speak again — exactly what a
        // dropped connection looks like from the other side — so it is
        // abandoned rather than driven to completion.
        {
            let responder =
                reconcile(&mut b, &right, PeerKey(PEER_A), &group, Role::Responder, &full);
            tokio::pin!(responder);

            tokio::select! {
                _ = reconcile(
                    &mut a, &left, PeerKey(PEER_B), &group, Role::Initiator, &config
                ) => {}
                _ = &mut responder => {}
            }
        }

        // Whatever happened above, a fresh session reaches the full answer.
        let (mine, _) = reconcile_pair(&left, &right).await;
        let mine = mine.unwrap();
        assert_eq!(
            mine.want.len(),
            200,
            "after a cut at round {cut_after}, a fresh session still finds the whole difference"
        );
    }
}
