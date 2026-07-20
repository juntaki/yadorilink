//! WireGuard-protocol
//! encrypted tunnel: the tunnel behaviors that outlast a single
//! handshake, which the audit found unexercised: rekey after
//! the WireGuard time limit, a peer roaming to a new endpoint mid-session,
//! and handshake retry after a lost initiation. Handshake authentication
//! and steady-state encrypt/decrypt are already covered (`tunn_wrapper.rs`
//! / `peer_channel.rs` unit tests) and are not re-tested here.
//!
//! **Real-clock note.** `boringtun` 0.7 is built with its `mock-instant`
//! feature disabled, so `Tunn::update_timers` reads the real OS monotonic
//! clock — neither `tokio::time` nor madsim can fast-forward it. The rekey
//! and roaming behaviors are therefore genuinely time-based (120s rekey,
//! 180s reject, 20s direct-liveness re-traversal), so their tests are real
//! elapsed-time integration tests marked `#[ignore]` (run explicitly with
//! `--ignored`); the handshake-retry test recovers within ~5s (boringtun's
//! `REKEY_TIMEOUT`) and runs in the normal suite. Plain `#[tokio::test]`
//! over real OS sockets, matching `tests/peer_channel.rs`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use yadorilink_transport::{PeerChannel, PeerReachability};

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Repeatedly sends `payload` from `from` and drains `to`'s receive queue,
/// returning true as soon as an identical copy is delivered or `budget`
/// elapses. Resending is safe: the tunnel drops duplicates and this only
/// asserts *at-least-once* delivery, which is what "the tunnel still
/// works" means across a rekey / roam.
async fn deliver_within(
    from: &PeerChannel,
    to: &PeerChannel,
    payload: &[u8],
    budget: Duration,
) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let _ = from.send(payload.to_vec()).await;
        if let Ok(Some(msg)) = timeout(Duration::from_millis(700), to.recv()).await {
            if msg == payload {
                return true;
            }
        }
    }
    false
}

fn is_connected(channel: &PeerChannel) -> bool {
    matches!(channel.reachability(), PeerReachability::Connected { .. })
}

/// Two direct channels wired to each other's real UDP socket
/// (`tests/peer_channel.rs`'s direct-path pattern). Returns the channels
/// plus each peer's bound address, so a test can interpose or roam.
async fn direct_pair() -> (PeerChannel, PeerChannel, SocketAddr, SocketAddr) {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();
    (a, b, addr_a, addr_b)
}

/// A lost first handshake initiation must be recovered by boringtun's
/// retransmit timer (`REKEY_TIMEOUT` ~5s), after which the session
/// completes and delivers. A UDP proxy in the middle drops exactly the
/// first datagram device A emits (the initial handshake initiation) and
/// relays everything else, so the only way a message ever crosses is the
/// retried initiation.
#[tokio::test]
async fn handshake_retries_after_a_lost_initiation() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // Proxy faces: A talks to `proxy_a`, B talks to `proxy_b`. Each face is
    // both where its peer sends and the source address the peer sees, so
    // each side confirms the proxy face as its direct candidate.
    let proxy_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_a_addr = proxy_a.local_addr().unwrap();
    let proxy_b_addr = proxy_b.local_addr().unwrap();

    // A -> proxy_a -> proxy_b -> B, dropping the first datagram from A.
    {
        let pa = proxy_a.clone();
        let pb = proxy_b.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut dropped_first = false;
            loop {
                let Ok((n, _)) = pa.recv_from(&mut buf).await else { break };
                if !dropped_first {
                    dropped_first = true; // swallow the initial handshake initiation
                    continue;
                }
                let _ = pb.send_to(&buf[..n], addr_b).await;
            }
        });
    }
    // B -> proxy_b -> proxy_a -> A (never dropped).
    {
        let pa = proxy_a.clone();
        let pb = proxy_b.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _)) = pb.recv_from(&mut buf).await else { break };
                let _ = pa.send_to(&buf[..n], addr_a).await;
            }
        });
    }

    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![proxy_a_addr],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![proxy_b_addr],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();

    // The first initiation is dropped; the retransmit (~5s) completes the
    // handshake, so allow generous budget.
    assert!(
        deliver_within(&a, &b, b"delivered after a retried handshake", Duration::from_secs(20))
            .await,
        "a lost initial handshake initiation must be retried until the session establishes and \
         delivers"
    );
}

/// A connected tunnel must re-key after the WireGuard time limit and keep
/// delivering. Proof: keep traffic flowing past `REJECT_AFTER_TIME` (180s),
/// after which the original session's keys are rejected — a message
/// delivered at that point can only have crossed a freshly re-keyed
/// session.
#[tokio::test]
#[ignore = "real-time (~185s): boringtun's rekey/reject timers run on the real OS clock; delivery past REJECT_AFTER_TIME (180s) proves a rekey occurred"]
async fn tunnel_rekeys_and_keeps_delivering() {
    let (a, b, _addr_a, _addr_b) = direct_pair().await;
    assert!(
        deliver_within(&a, &b, b"warmup", Duration::from_secs(15)).await,
        "the tunnel must establish before the rekey window"
    );

    // Keep the tunnel busy across the 120s rekey and 180s reject
    // boundaries so the initiator actually re-keys rather than idling.
    let start = Instant::now();
    let mut seq = 0u64;
    while start.elapsed() < Duration::from_secs(182) {
        let _ = a.send(format!("keepalive-{seq}").into_bytes()).await;
        let _ = timeout(Duration::from_millis(400), b.recv()).await;
        seq += 1;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    assert!(
        deliver_within(&a, &b, b"after the rekey boundary", Duration::from_secs(30)).await,
        "past REJECT_AFTER_TIME the original keys are rejected, so continued delivery requires a \
         completed rekey"
    );
}

/// A connected session must survive the peer roaming to a new endpoint
/// address. With no relay, the roam is handled entirely by re-traversal:
/// the peer's old address goes fully dark (a NAT rebinding), the confirmed
/// direct path loses liveness (~20s), the channel re-races its candidates,
/// and once the peer reappears at its new address (surfaced via
/// `add_direct_candidate`, as local discovery would) the direct path
/// re-confirms there — with no payload lost across the whole roam.
///
/// `last_direct_rx` updates on *any* direct receive, so the old endpoint
/// must go dark in both directions for the liveness timer to fire — which
/// is exactly what a real address change looks like. During the gap there
/// is no fallback path, so delivery pauses until the new candidate
/// confirms; the test asserts recovery, not gap-time delivery.
#[tokio::test]
#[ignore = "real-time (~30s): direct-liveness re-traversal (DIRECT_LIVENESS_TIMEOUT 20s) runs on the real OS clock"]
async fn session_survives_a_peer_roaming_to_a_new_address() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // Proxy: single B-facing socket; two A-facing sockets standing for B's
    // pre- and post-roam addresses. `old_dead` cuts B's original address in
    // both directions (the rebinding); `new_alive` brings up the new one.
    let proxy_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let a_face1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let a_face2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_b_addr = proxy_b.local_addr().unwrap();
    let a_face1_addr = a_face1.local_addr().unwrap();
    let a_face2_addr = a_face2.local_addr().unwrap();
    let old_dead = Arc::new(AtomicBool::new(false));
    let new_alive = Arc::new(AtomicBool::new(false));

    // A -> a_face1 -> B, until the old address dies.
    {
        let pb = proxy_b.clone();
        let af1 = a_face1.clone();
        let old_dead = old_dead.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _)) = af1.recv_from(&mut buf).await else { break };
                if old_dead.load(Ordering::SeqCst) {
                    continue;
                }
                let _ = pb.send_to(&buf[..n], addr_b).await;
            }
        });
    }
    // A -> a_face2 -> B, once the new address is alive.
    {
        let pb = proxy_b.clone();
        let af2 = a_face2.clone();
        let new_alive = new_alive.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _)) = af2.recv_from(&mut buf).await else { break };
                if !new_alive.load(Ordering::SeqCst) {
                    continue;
                }
                let _ = pb.send_to(&buf[..n], addr_b).await;
            }
        });
    }
    // B -> proxy_b -> A, via a_face1 (pre-roam), nothing (gap), or a_face2
    // (post-roam). The gap is what lets A's direct liveness lapse.
    {
        let pb = proxy_b.clone();
        let af1 = a_face1.clone();
        let af2 = a_face2.clone();
        let old_dead = old_dead.clone();
        let new_alive = new_alive.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _)) = pb.recv_from(&mut buf).await else { break };
                if new_alive.load(Ordering::SeqCst) {
                    let _ = af2.send_to(&buf[..n], addr_a).await;
                } else if !old_dead.load(Ordering::SeqCst) {
                    let _ = af1.send_to(&buf[..n], addr_a).await;
                } // else: the roam gap — B's traffic to A is dropped
            }
        });
    }

    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![a_face1_addr],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![proxy_b_addr],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();

    // Establish and confirm the direct path on B's original address.
    assert!(
        deliver_within(&a, &b, b"pre-roam", Duration::from_secs(15)).await,
        "the tunnel must establish before the roam"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_connected(&a) && Instant::now() < deadline {
        let _ = deliver_within(&a, &b, b"warm-direct", Duration::from_secs(1)).await;
    }
    assert!(is_connected(&a), "must have a confirmed direct path before roaming");

    // B's address changes: the old endpoint goes dark in both directions,
    // and A learns the new candidate (as discovery would surface it).
    old_dead.store(true, Ordering::SeqCst);
    a.add_direct_candidate(a_face2_addr).await;

    // The peer reappears at its new address; re-traversal re-confirms the
    // direct path there and delivery resumes with nothing lost — the
    // session has survived the roam end to end.
    new_alive.store(true, Ordering::SeqCst);
    assert!(
        deliver_within(&a, &b, b"post-roam", Duration::from_secs(40)).await,
        "delivery must resume after the peer reappears at its new address"
    );
    assert!(
        deliver_within(&b, &a, b"post-roam-reverse", Duration::from_secs(15)).await,
        "the roamed session must deliver in both directions"
    );

    // The direct path must re-confirm on the roamed endpoint — the whole
    // point of re-traversal (there is no fallback path to coast on).
    let deadline = Instant::now() + Duration::from_secs(20);
    while !is_connected(&a) && Instant::now() < deadline {
        let _ = deliver_within(&a, &b, b"re-traverse", Duration::from_secs(1)).await;
    }
    assert!(is_connected(&a), "the direct path must re-confirm onto the roamed endpoint");
}
