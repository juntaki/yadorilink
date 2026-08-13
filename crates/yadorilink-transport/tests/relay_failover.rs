//! M3 Pass 6c: `PeerChannel`'s own direct<->relay failover state machine,
//! driven exactly the way `yadorilink-daemon`'s real `RelayCarrier`
//! implementation would drive it, but with a minimal test-only carrier
//! standing in for the real grant/session machinery (that machinery is
//! proven separately, over real orchestrator-managed sessions, in
//! `yadorilink-daemon`'s `tests/relay_session_e2e.rs`). This file isolates
//! the transport-layer state machine itself: does direct failure actually
//! trigger relay fallback, does relay-delivered traffic report
//! `ConnectedRelay` rather than a false `Connected`, and does a later
//! direct candidate promote back over relay once it actually confirms.
//!
//! `CANDIDATE_RACE_TIMEOUT`/`DIRECT_LIVENESS_TIMEOUT` (20s each) are real
//! wall-clock `std::time::Instant` reads inside the actor, not affected by
//! `tokio::time::pause` -- this test genuinely waits on the real clock,
//! matching `tunnel_longevity.rs`'s own established reasoning for its
//! real-time tests in this same crate. ~20s, not `#[ignore]`-worthy at
//! that scale (unlike that file's 30s/185s tests).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use tokio::time::timeout;
use yadorilink_transport::{PeerChannel, PeerReachability, RelayCarrier};

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn recv_within(channel: &PeerChannel, d: Duration) -> Vec<u8> {
    timeout(d, channel.recv())
        .await
        .expect("timed out waiting for message")
        .expect("channel closed unexpectedly")
}

async fn wait_for_reachability(
    channel: &PeerChannel,
    d: Duration,
    mut predicate: impl FnMut(PeerReachability) -> bool,
) -> PeerReachability {
    let mut rx = channel.reachability_watch();
    let deadline = tokio::time::Instant::now() + d;
    loop {
        let current = *rx.borrow();
        if predicate(current) {
            return current;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for reachability predicate; last seen {current:?}");
        }
        if timeout(remaining, rx.changed()).await.is_err() {
            panic!("timed out waiting for a reachability change; last seen {current:?}");
        }
    }
}

/// Forwards every datagram it's handed to a fixed destination address over
/// its own real UDP socket -- standing in for a real relay peer's own
/// dedicated forwarding socket (`yadorilink-daemon`'s `relay_forwarder.rs`)
/// without any of that crate's grant/admission/session bookkeeping, which
/// is proven separately.
struct ForwardingRelayCarrier {
    socket: tokio::net::UdpSocket,
    destination: SocketAddr,
    calls: AtomicUsize,
}

impl RelayCarrier for ForwardingRelayCarrier {
    fn send_via_relay<'a>(
        &'a self,
        _peer_public: &'a [u8; 32],
        datagram: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.socket.send_to(&datagram, self.destination).await.is_ok()
        })
    }
}

/// Never forwards anything -- used on C's side so C's own outbound replies
/// travel over its real, working direct candidate (A's real address) and
/// never need relay fallback themselves; isolates the test to A's own
/// state machine, not a full bidirectional relay round trip.
struct DenyingRelayCarrier;

impl RelayCarrier for DenyingRelayCarrier {
    fn send_via_relay<'a>(
        &'a self,
        _peer_public: &'a [u8; 32],
        _datagram: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
}

/// The core Pass 6 acceptance case: A is given an address for C that
/// nothing listens on (direct can never succeed), so once the candidate
/// race is exhausted, A's own `send_batch_direct` falls back to its
/// injected `RelayCarrier` -- here, a real UDP forward straight to C's
/// REAL address. C, receiving genuine authenticated WireGuard traffic from
/// an address that isn't a candidate address A ever advertised through it,
/// replies over its own real direct path back to A -- which A itself DOES
/// receive over its real socket (nothing about relaying changes which
/// physical socket ever receives bytes), but from an address that isn't
/// among A's own (broken) candidate list, so A reports `ConnectedRelay`,
/// never a false `Connected`. Only once A is explicitly given the real
/// candidate address (simulating a topology change -- e.g. local discovery
/// or a NAT re-traversal success) does the SAME reply promote A to a
/// genuine `Connected` (direct), and relay fallback stops being used.
#[tokio::test(flavor = "multi_thread")]
async fn direct_failure_falls_back_to_relay_then_promotes_back_once_direct_confirms() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let (secret_a, public_a) = gen_keypair();
    let (secret_c, public_c) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_c = socket_c.local_addr().unwrap();

    // Nothing is bound here -- a real, immediately-refused destination
    // (not just a timeout), so A's candidate race fails deterministically
    // fast rather than relying on silence alone.
    let unreachable_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let relay_forward_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_carrier = Arc::new(ForwardingRelayCarrier {
        socket: relay_forward_socket,
        destination: addr_c,
        calls: AtomicUsize::new(0),
    });

    let a = PeerChannel::connect_with_relay(
        secret_a,
        public_c,
        0,
        vec![unreachable_addr],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
        relay_carrier.clone(),
    )
    .await
    .unwrap();
    let c = PeerChannel::connect_with_relay(
        secret_c,
        public_a,
        0,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_c, Some(public_c)),
        Arc::new(DenyingRelayCarrier),
    )
    .await
    .unwrap();

    // Wait out the candidate race (real wall-clock CANDIDATE_RACE_TIMEOUT,
    // 20s -- see this file's own module doc comment) so A has genuinely
    // given up on direct before any send is attempted. Not asserted as a
    // literal observed `Unreachable` watch event: C's own `direct_probe`
    // timer independently races a REAL handshake initiation toward A
    // (C's `direct_candidates` includes A's real address, so `should_
    // probe` is satisfied for C from the moment it connects) completely
    // independently of anything this test does with A -- by the time
    // this sleep elapses, A may already be `ConnectedRelay` from THAT
    // inbound traffic rather than sitting in `Unreachable`, and a `watch`
    // channel only ever exposes the LATEST value, not every intermediate
    // one, so a transient `Unreachable` in between is not reliably
    // observable anyway. Both outcomes are equally valid for what this
    // test actually asserts: `send_batch_direct`'s relay-fallback
    // condition covers `Unreachable | ConnectedRelay`, and A is
    // guaranteed to be in one or the other (never `Connecting`) once this
    // elapses.
    tokio::time::sleep(Duration::from_secs(25)).await;
    assert!(
        !matches!(a.reachability(), PeerReachability::Connecting { .. }),
        "A must have left the initial candidate race by now"
    );

    a.send(b"hello via relay, A never reached C directly".to_vec()).await.unwrap();

    // A's fallback must have actually been invoked, and the datagram must
    // have physically reached C (real WireGuard handshake -- C only ever
    // relays a message up to `recv()` once its own tunnel decrypts it).
    let received = recv_within(&c, Duration::from_secs(10)).await;
    assert_eq!(received, b"hello via relay, A never reached C directly");
    assert!(relay_carrier.calls.load(Ordering::Relaxed) >= 1);

    // C's reply travels back over C's own real direct path to A's real
    // address -- A's real socket receives it, but from an address (C's
    // real address) that was never one of A's own advertised candidates,
    // so A must report `ConnectedRelay`, never silently treat this as a
    // confirmed direct path.
    c.send(b"reply".to_vec()).await.unwrap();
    let reachability = wait_for_reachability(&a, Duration::from_secs(10), |r| {
        !matches!(r, PeerReachability::Unreachable { .. })
    })
    .await;
    assert!(
        matches!(reachability, PeerReachability::ConnectedRelay),
        "expected ConnectedRelay, got {reachability:?}"
    );
    assert_eq!(a.confirmed_direct_addr(), None, "relay must never set a confirmed direct address");

    // Simulate a topology change making direct actually reachable now:
    // A learns C's real address as a genuine candidate. `add_direct_
    // candidate` only registers the candidate with A's actor (asynchronously,
    // via its own message channel) -- it does not itself force a
    // reconfirmation, so a reply racing ahead of that registration would
    // still land on the "not a known candidate" branch and leave
    // reachability unchanged (a no-op `set_reachability`, which `rx.
    // changed()` would then never observe). Retrying the send is what
    // actually exercises the intended behavior ("A confirms direct once
    // it knows the candidate"), not a race against the registration.
    a.add_direct_candidate(addr_c).await;
    let mut promoted = false;
    for _ in 0..25 {
        c.send(b"reply after candidate learned".to_vec()).await.unwrap();
        if timeout(Duration::from_millis(400), async {
            let mut rx = a.reachability_watch();
            loop {
                if matches!(*rx.borrow(), PeerReachability::Connected { .. }) {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
        .await
        .is_ok()
        {
            promoted = true;
            break;
        }
    }
    assert!(promoted, "A never promoted to Connected after learning C's real candidate");
    let reachability = a.reachability();
    assert!(matches!(reachability, PeerReachability::Connected { .. }));
    assert_eq!(a.confirmed_direct_addr(), Some(addr_c));

    // Direct having recovered, further sends must go straight to C's real
    // socket -- no further relay calls once a genuine direct path is
    // confirmed and in use.
    let calls_before = relay_carrier.calls.load(Ordering::Relaxed);
    a.send(b"now direct".to_vec()).await.unwrap();
    let received = recv_within(&c, Duration::from_secs(5)).await;
    assert_eq!(received, b"now direct");
    assert_eq!(
        relay_carrier.calls.load(Ordering::Relaxed),
        calls_before,
        "no relay call once direct is confirmed and in use"
    );
}
