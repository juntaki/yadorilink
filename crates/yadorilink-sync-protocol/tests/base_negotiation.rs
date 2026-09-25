//! Comparing history bases before comparing change sets.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use support::{group, id, MockReplica, PEER_A, PEER_B};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_sync_protocol::ports::{BaseVerdict, PeerKey};
use yadorilink_sync_protocol::session::{reconcile, ReconcileOutcome, Role, SessionConfig};
use yadorilink_sync_protocol::{wire, ProtocolError};

const PIPE: usize = 64 * 1024;

async fn reconcile_pair(
    left: &MockReplica,
    right: &MockReplica,
) -> (Result<ReconcileOutcome, ProtocolError>, Result<ReconcileOutcome, ProtocolError>) {
    let (mut a, mut b) = tokio::io::duplex(PIPE);
    let config = SessionConfig::default();
    let group = group();
    tokio::join!(
        reconcile(&mut a, left, PeerKey(PEER_B), &group, Role::Initiator, &config),
        reconcile(&mut b, right, PeerKey(PEER_A), &group, Role::Responder, &config),
    )
}

#[tokio::test]
async fn peers_on_the_same_base_go_on_to_compare_change_sets() {
    let left = MockReplica::with((0..10).map(id)).on_base(b"base-1");
    let right = MockReplica::with((5..15).map(id)).on_base(b"base-1");

    let (mine, theirs) = reconcile_pair(&left, &right).await;
    let mine = mine.unwrap().expect_reconciled("same base");
    let theirs = theirs.unwrap().expect_reconciled("same base");

    assert_eq!(mine.want.len(), 5);
    assert_eq!(theirs.want.len(), 5);
    assert_eq!(*left.verdicts.lock().unwrap(), vec![BaseVerdict::SameBase]);
    assert_eq!(*right.verdicts.lock().unwrap(), vec![BaseVerdict::SameBase]);
}

/// Different bases: both sides stop before a fingerprint exists. Neither
/// computes its servable set, so neither can disclose a difference or be
/// asked for a change, and neither stages anything.
#[tokio::test]
async fn peers_on_different_bases_stop_before_any_change_set_is_compared() {
    let left = MockReplica::with((0..10).map(id)).on_base(b"base-1");
    let right = MockReplica::with((5..15).map(id)).on_base(b"base-2");

    let (mine, theirs) = reconcile_pair(&left, &right).await;
    assert_eq!(mine.unwrap(), ReconcileOutcome::MergeRequired);
    assert_eq!(theirs.unwrap(), ReconcileOutcome::MergeRequired);

    for side in [&left, &right] {
        assert_eq!(side.servable_calls.load(Ordering::SeqCst), 0, "no set was computed");
        assert_eq!(side.stage_calls.load(Ordering::SeqCst), 0, "nothing was staged");
        assert_eq!(*side.verdicts.lock().unwrap(), vec![BaseVerdict::MergeRequired]);
    }
    assert_eq!(left.possessed().len(), 10);
    assert_eq!(right.possessed().len(), 10);
}

#[tokio::test]
async fn a_refused_negotiation_ends_the_session_on_both_sides() {
    let left = MockReplica::with((0..10).map(id)).refusing_bases();
    let right = MockReplica::with((5..15).map(id)).refusing_bases();

    let (mine, theirs) = reconcile_pair(&left, &right).await;
    for result in [mine, theirs] {
        assert!(matches!(result, Err(ProtocolError::BaseRefused { .. })), "{result:?}");
    }
    assert_eq!(left.servable_calls.load(Ordering::SeqCst), 0);
    assert_eq!(right.servable_calls.load(Ordering::SeqCst), 0);
}

/// On the wire: the opener's first frame is its advertisement, and after a
/// peer answers with a different base, the opener writes nothing more --
/// not an opening fingerprint, not an empty round.
#[tokio::test]
async fn after_a_foreign_advertisement_nothing_further_reaches_the_wire() {
    let local = MockReplica::with((0..10).map(id)).on_base(b"base-1");
    let (mut a, mut b) = tokio::io::duplex(PIPE);
    let (group, config) = (group(), SessionConfig::default());

    let initiator = reconcile(&mut a, &local, PeerKey(PEER_B), &group, Role::Initiator, &config);
    let peer = async {
        let mut length = [0u8; 4];
        b.read_exact(&mut length).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
        b.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"base-1", "the first frame is the opener's advertisement");

        b.write_all(&wire::encode_advertisement(b"base-2").unwrap()).await.unwrap();
        b.flush().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(initiator, peer);
    assert_eq!(outcome.unwrap(), ReconcileOutcome::MergeRequired);

    let mut leaked = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(200), b.read(&mut leaked)).await;
    assert!(
        !matches!(read, Ok(Ok(n)) if n > 0),
        "a foreign-base session must put nothing after the advertisements on the wire"
    );
    assert_eq!(local.servable_calls.load(Ordering::SeqCst), 0);
}

/// An advertisement's declared length is checked against its bound before
/// anything is allocated for it.
#[tokio::test]
async fn an_oversized_advertisement_is_refused_before_it_is_read() {
    let local = MockReplica::with([]);
    let (mut a, mut b) = tokio::io::duplex(PIPE);
    let (group, config) = (group(), SessionConfig::default());

    let responder = reconcile(&mut a, &local, PeerKey(PEER_B), &group, Role::Responder, &config);
    let peer = async {
        let declared = (wire::MAX_ADVERTISEMENT_BYTES + 1) as u32;
        b.write_all(&declared.to_be_bytes()).await.unwrap();
        b.flush().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(responder, peer);
    assert!(matches!(outcome, Err(ProtocolError::FrameTooLarge { .. })), "{outcome:?}");
    assert!(local.verdicts.lock().unwrap().is_empty(), "nothing was judged");
    assert_eq!(
        local.unjudged.lock().unwrap().len(),
        1,
        "but the port was told this negotiation ended unjudged, so no earlier claim of the \
         peer's outlives it"
    );
}

#[test]
fn an_oversized_advertisement_cannot_be_framed() {
    let oversized = vec![0u8; wire::MAX_ADVERTISEMENT_BYTES + 1];
    assert!(wire::encode_advertisement(&oversized).is_err());
}
