//! End-to-end reachability behavior a peer's status is derived from. With
//! no operator-run relay to fall back on, a peer that no direct candidate
//! can reach must resolve to an explicit `Unreachable` state (carrying a
//! failure category and a bounded-backoff retry deadline) rather than
//! silently sitting "connecting" forever — this is the signal the daemon
//! surfaces as a "cannot connect" peer status. And because that state is
//! terminal only until a fresh candidate turns up, an unreachable peer must
//! recover on its own the moment a live candidate is learned at runtime:
//! that is the only recovery path once realtime forwarding is gone, so it is
//! exercised here through the real transport, socket to socket.

use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use yadorilink_transport::{PeerChannel, PeerReachability, TransportHub, UnreachableCategory};

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Polls `cond` every 50ms until it returns `true`, or gives up once
/// `within` has elapsed. Returns whether the condition was met in time.
async fn poll_until(within: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if cond() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_channel_with_no_candidates_reports_unreachable_no_candidates() {
    let (local_secret, _local_public) = gen_keypair();
    let (_peer_secret, peer_public) = gen_keypair();

    // The channel still binds to a real device socket, but has no direct
    // candidate to reach the peer on — nothing to race, so it resolves
    // straight to `Unreachable`.
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let channel = PeerChannel::connect(
        local_secret,
        peer_public,
        0,
        vec![],
        TransportHub::from_socket(socket, None),
    )
    .await
    .unwrap();

    // It may momentarily report `Connecting` before the (empty) race
    // resolves, so poll briefly for the terminal state.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let PeerReachability::Unreachable { category, .. } = channel.reachability() {
            assert!(
                matches!(category, UnreachableCategory::NoCandidates),
                "expected NoCandidates, got {category:?}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a candidate-less channel never became Unreachable"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Candidate exhaustion doesn't just flip a peer "off": the `Unreachable`
/// state carries both the failure *category* the daemon renders as
/// "cannot connect (…)" and a `next_retry` deadline that schedules a bounded
/// background re-attempt, so an exhausted peer keeps being retried rather
/// than dropped. The empty-candidate race exhausts immediately, which is the
/// fast, deterministic case to assert that whole shape on.
#[tokio::test]
async fn candidate_exhaustion_marks_peer_unreachable_with_category_and_retry_deadline() {
    let (local_secret, _local_public) = gen_keypair();
    let (_peer_secret, peer_public) = gen_keypair();

    // Captured before connecting: the retry deadline is computed as
    // `entered_unreachable_at + backoff`, so it can never predate this.
    let before_connect = std::time::Instant::now();

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let channel = PeerChannel::connect(
        local_secret,
        peer_public,
        0,
        vec![],
        TransportHub::from_socket(socket, None),
    )
    .await
    .unwrap();

    let mut observed = None;
    let resolved = poll_until(Duration::from_secs(5), || {
        if let PeerReachability::Unreachable { category, next_retry } = channel.reachability() {
            observed = Some((category, next_retry));
            true
        } else {
            false
        }
    })
    .await;
    assert!(resolved, "an exhausted candidate race never became Unreachable");

    let (category, next_retry) = observed.unwrap();
    assert!(
        matches!(category, UnreachableCategory::NoCandidates),
        "an empty candidate set must be attributed to NoCandidates, got {category:?}"
    );
    assert!(
        next_retry >= before_connect,
        "Unreachable must schedule a bounded-backoff retry deadline, not leave the peer un-retried"
    );
}

/// The no-relay world's only recovery path: an `Unreachable` peer must heal
/// itself the moment a fresh, live candidate is learned at runtime (as LAN
/// discovery or a netmap push would surface one). Learning the candidate has
/// to reset the retry backoff, re-race immediately, and — when the candidate
/// is genuinely reachable — drive the peer all the way through to
/// `Connected`. Exercised end to end over the real transport so it covers
/// the actual handshake, not just the state bookkeeping.
#[tokio::test]
async fn unreachable_peer_recovers_to_connected_when_a_live_candidate_is_learned() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // A knows no candidate for B, so it resolves to Unreachable(NoCandidates)
    // — there is nothing to race yet.
    let channel_a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![],
        TransportHub::from_socket(socket_a, None),
    )
    .await
    .unwrap();

    // B knows A's address from the start and keeps trying to reach it, so the
    // handshake can complete as soon as A learns B's address and re-races.
    let _channel_b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        TransportHub::from_socket(socket_b, None),
    )
    .await
    .unwrap();

    // Precondition: A is genuinely stuck unreachable with no candidate.
    let unreachable = poll_until(Duration::from_secs(5), || {
        matches!(
            channel_a.reachability(),
            PeerReachability::Unreachable { category: UnreachableCategory::NoCandidates, .. }
        )
    })
    .await;
    assert!(unreachable, "A should start Unreachable(NoCandidates) with no candidate for B");

    // The recovery trigger: a live candidate for B arrives at runtime.
    channel_a.add_direct_candidate(addr_b).await;

    // A must reset its backoff, re-race, and reach Connected off its own back.
    let recovered = poll_until(Duration::from_secs(15), || {
        matches!(channel_a.reachability(), PeerReachability::Connected { .. })
    })
    .await;
    assert!(
        recovered,
        "A should recover to Connected once a live candidate is learned; still {:?}",
        channel_a.reachability()
    );
}
