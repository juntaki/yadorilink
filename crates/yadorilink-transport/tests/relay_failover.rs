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

/// Drains any already-queued inbound messages -- a retry loop that sends
/// the same logical step more than once (because an earlier attempt's
/// own short per-try timeout gave up before delivery actually completed,
/// not because delivery failed) can leave duplicates queued behind a
/// later, distinct message; without draining first, a later `recv_within`
/// picks up a STALE duplicate via plain FIFO order instead of the new one
/// it's actually asserting on.
async fn drain_queued(channel: &PeerChannel) {
    while timeout(Duration::from_millis(200), channel.recv()).await.is_ok() {}
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
/// is proven separately. `socket` is also read by a background task (see
/// this test's own setup) that injects whatever arrives on it back into
/// A via `deliver_relay_datagram` -- the REQUESTER-side half of the H1
/// round trip this test proves; this struct is only ever the SEND half.
struct ForwardingRelayCarrier {
    socket: Arc<tokio::net::UdpSocket>,
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
            // M3 Pass 8 closeout: wraps in the SAME relay envelope
            // `yadorilink-daemon`'s real `relay_forwarder.rs` now always
            // wraps its own forwarding sends in -- see `wrap_relay_
            // envelope`'s own doc comment. Without this, this test
            // double would send raw, unwrapped bytes indistinguishable
            // from genuine direct UDP, unable to actually exercise
            // (or prove regressions in) the route-provenance mechanism
            // this file's own `relay_delivered_traffic_from_a_colliding_
            // known_candidate_never_confirms_direct` test below depends
            // on.
            let enveloped = yadorilink_transport::wrap_relay_envelope(1, &datagram);
            self.socket.send_to(&enveloped, self.destination).await.is_ok()
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

    let relay_forward_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_carrier = Arc::new(ForwardingRelayCarrier {
        socket: relay_forward_socket.clone(),
        destination: addr_c,
        calls: AtomicUsize::new(0),
    });

    let a = Arc::new(
        PeerChannel::connect_with_relay(
            secret_a,
            public_c,
            0,
            vec![unreachable_addr],
            yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
            relay_carrier.clone(),
        )
        .await
        .unwrap(),
    );
    // C is given NO working candidate for A at all (unlike a real B's own
    // relay_forwarder, this test's `ForwardingRelayCarrier` is one-way --
    // it only forwards A's OUTBOUND datagrams to C; nothing about C
    // itself changes just because A has a relay carrier). Whatever
    // arrives at `relay_forward_socket` (C's own reply, sent to the
    // `confirmed_relay_addr` it learns from A's relayed initiation -- see
    // this test's own module doc comment / H1's own fix) is injected
    // back into A's requester-side inbound path here, exactly mirroring
    // how the daemon layer's own `handle_relay_data` routes a relay
    // reply into `deliver_relay_datagram` in production.
    let c = PeerChannel::connect_with_relay(
        secret_c,
        public_a,
        0,
        Vec::new(),
        yadorilink_transport::TransportHub::from_socket(socket_c, Some(public_c)),
        Arc::new(DenyingRelayCarrier),
    )
    .await
    .unwrap();
    {
        let relay_forward_socket = relay_forward_socket.clone();
        let a = a.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok(n) = relay_forward_socket.recv(&mut buf).await {
                a.deliver_relay_datagram(buf[..n].to_vec());
            }
        });
    }

    // Wait out the candidate race (real wall-clock CANDIDATE_RACE_TIMEOUT,
    // 20s -- see this file's own module doc comment) so A has genuinely
    // given up on direct before any send is attempted. Bounded-backoff
    // re-races mean A can cycle back into a transient `Connecting` even
    // after this (each attempt against `unreachable_addr` still fails,
    // it just takes another race-timeout round) -- `send_batch_direct`
    // refuses relay fallback specifically during `Connecting`, so rather
    // than pin this test to one exact moment in that cycle, retry the
    // send until it lands in a window where A isn't mid-race.
    tokio::time::sleep(Duration::from_secs(25)).await;

    // Bounded-backoff re-races cycle A through a FULL CANDIDATE_RACE_
    // TIMEOUT (20s) of `Connecting` each time `unreachable_addr` fails
    // again, so a short retry window can land entirely inside one such
    // cycle and never once catch A outside it -- this budget spans
    // several full cycles rather than assuming a specific one.
    let payload = b"hello via relay, A never reached C directly".to_vec();
    let mut delivered = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while tokio::time::Instant::now() < deadline {
        if matches!(a.reachability(), PeerReachability::Connecting { .. }) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        a.send(payload.clone()).await.unwrap();
        if let Ok(Some(received)) = timeout(Duration::from_millis(500), c.recv()).await {
            assert_eq!(received, payload);
            delivered = true;
            break;
        }
    }
    assert!(delivered, "A's hello never reached C via relay fallback");
    drain_queued(&c).await;

    // A's fallback must have actually been invoked (real WireGuard
    // handshake -- C only ever relays a message up to `recv()` once its
    // own tunnel decrypts it, so `delivered` above already proves the
    // datagram physically reached C).
    assert!(relay_carrier.calls.load(Ordering::Relaxed) >= 1);

    // C's reply goes to `confirmed_relay_addr` (H1's own fix) -- the
    // relay forwarding socket's address, learned from A's relayed
    // initiation -- which the background task above relays back into A
    // via `deliver_relay_datagram`. A's real socket never sees this
    // reply directly at all (C has no candidate for A's real address),
    // so this is a genuine end-to-end proof of the round trip, not an
    // accidental direct path.
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
    // C also needs a real candidate for A -- C started with none at all
    // (see this test's own setup), so without this its replies would
    // keep going out via `confirmed_relay_addr` (the relay path) forever,
    // never as real UDP to A's real address, and A could never confirm
    // direct no matter what candidates IT learns.
    a.add_direct_candidate(addr_c).await;
    c.add_direct_candidate(addr_a).await;
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

/// M3 Pass 8 closeout: the real end-to-end version of `peer_channel.rs`'s
/// own unit test `relay_tagged_datagram_from_a_colliding_known_candidate_
/// stays_relay` -- a GENUINE WireGuard handshake, relayed over a REAL UDP
/// socket wrapped in a REAL relay envelope, arriving at C from an address
/// C had ALREADY recorded as a known direct candidate for A (the exact
/// coincidence the final-gate review's own "opaque forwarding is
/// indistinguishable from direct" concern was about). Proves the address
/// collision no longer confirms a false direct path: C reports
/// `ConnectedRelay`, never `Connected`, and `confirmed_direct_addr` stays
/// `None`, even though `from_addr` alone would satisfy the old
/// candidate-membership check.
#[tokio::test(flavor = "multi_thread")]
async fn relay_delivered_traffic_from_a_colliding_known_candidate_never_confirms_direct() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let (secret_a, public_a) = gen_keypair();
    let (secret_c, public_c) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_c = socket_c.local_addr().unwrap();

    // Bound FIRST so its real (OS-assigned ephemeral) address is known
    // before constructing C -- this is the "coincidentally matching"
    // address: C is given it as a genuine direct candidate for A, even
    // though it's actually going to be this test's relay-forwarding
    // socket, exactly simulating the collision this test exists to prove
    // is now harmless.
    let relay_forward_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let colliding_addr = relay_forward_socket.local_addr().unwrap();

    let relay_carrier = Arc::new(ForwardingRelayCarrier {
        socket: relay_forward_socket.clone(),
        destination: addr_c,
        calls: AtomicUsize::new(0),
    });

    // Empty candidate list -- `Unreachable { NoCandidates }` immediately,
    // no need to wait out `CANDIDATE_RACE_TIMEOUT` first (this test isn't
    // exercising that state machine, only the destination-side confirm
    // gate), so `send_batch_direct`'s relay fallback is live right away.
    let a = Arc::new(
        PeerChannel::connect_with_relay(
            secret_a,
            public_c,
            0,
            Vec::new(),
            yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
            relay_carrier,
        )
        .await
        .unwrap(),
    );
    // C already "knows" the relay's own address as a direct candidate for
    // A -- the collision. A real deployment would only hit this via
    // astronomical coincidence (the relay's forwarding socket draws a
    // fresh OS-random ephemeral port every session); this test constructs
    // it deliberately rather than waiting for it.
    let c = PeerChannel::connect_with_relay(
        secret_c,
        public_a,
        0,
        vec![colliding_addr],
        yadorilink_transport::TransportHub::from_socket(socket_c, Some(public_c)),
        Arc::new(DenyingRelayCarrier),
    )
    .await
    .unwrap();
    // Without this, C's own handshake RESPONSE (sent to `colliding_addr`,
    // which is genuinely `relay_forward_socket`'s real address either
    // way -- both C's direct-candidate race AND its `confirmed_relay_
    // addr` reply path target it) never reaches A at all: nothing is
    // listening on `relay_forward_socket` to relay it onward, so A's
    // handshake never completes and `a.send`'s payload never actually
    // goes out as encrypted data, only ever re-sent as a bare
    // initiation. Same pattern as the earlier test in this file.
    {
        let relay_forward_socket = relay_forward_socket.clone();
        let a = a.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok(n) = relay_forward_socket.recv(&mut buf).await {
                a.deliver_relay_datagram(buf[..n].to_vec());
            }
        });
    }

    // A has no working direct path at all, so its own send falls back to
    // the relay carrier immediately (`send_batch_direct`'s `Unreachable`
    // branch) -- no need to wait out the candidate race first, since this
    // test isn't exercising that state machine, only the destination-side
    // confirm gate.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        a.send(b"hello".to_vec()).await.unwrap();
        if timeout(Duration::from_millis(300), c.recv()).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("A's hello never reached C via the relay");
        }
    }

    let reachability = wait_for_reachability(&c, Duration::from_secs(5), |r| {
        !matches!(r, PeerReachability::Connecting { .. } | PeerReachability::Unreachable { .. })
    })
    .await;
    assert_eq!(
        reachability,
        PeerReachability::ConnectedRelay,
        "a relay-delivered datagram from a colliding known candidate must report ConnectedRelay, \
         never a false Connected"
    );
    assert_eq!(
        c.confirmed_direct_addr(),
        None,
        "the colliding address must never become a confirmed direct path"
    );
}
