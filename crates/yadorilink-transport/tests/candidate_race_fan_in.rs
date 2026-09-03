//! What a candidate race costs when many peers are racing at once.
//!
//! Racing changed the units the daemon's own handshake bound counts in. The
//! semaphore that gates reconnects still admits four peers at a time, but a
//! peer is now a *race* rather than a dial, and a race opens one handshake
//! per candidate. Four peers times the eight-candidate cap is thirty-two
//! outgoing handshakes, not four -- so the question "is the bound still
//! sized for what it admits" has to be measured rather than assumed.
//!
//! This measures well above that ceiling on purpose: sixteen concurrent
//! races of eight candidates each, seven of them silent, is a hundred and
//! twenty-eight concurrent handshakes. If that is comfortable then
//! thirty-two is not worth bounding further, and the constant's own comment
//! is what needs correcting.
#![cfg(not(madsim))]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_transport::{DeviceSigningKeyPair, QuicPeerEndpoint, TransportHub};

/// Peers racing at once, comfortably above the four the reconnect semaphore
/// admits.
const CONCURRENT_PEERS: usize = 16;

/// Silent addresses ahead of the working one, filling the raced-candidate
/// cap so each race opens the most handshakes it ever can.
const DEAD_CANDIDATES: usize = 7;

/// This device's own resident set, in kibibytes, read from `/proc`.
///
/// Peak would be better than current, but current before and after is enough
/// to answer the question actually asked -- whether racing leaves a
/// per-connection cost behind that a serial dial did not.
fn resident_kib() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 =
        statm.split_whitespace().nth(1).and_then(|value| value.parse().ok()).unwrap_or(0);
    pages * 4
}

async fn endpoint() -> (Arc<QuicPeerEndpoint>, SocketAddr, [u8; 32]) {
    let hub = TransportHub::bind((Ipv4Addr::LOCALHOST, 0).into()).await.expect("bind hub");
    let addr = hub.local_addr();
    let device = DeviceSigningKeyPair::generate();
    let public = device.public_bytes();
    (QuicPeerEndpoint::new(hub, device).expect("device endpoint"), addr, public)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn many_peers_racing_at_once_stay_bounded_and_prompt() {
    let (dialler, _dialler_addr, dialler_key) = endpoint().await;

    // One real peer per race, each also advertising silent addresses ahead
    // of its own. Port 1 on distinct loopback addresses: nothing listens, and
    // every one of them is a real destination rather than a black hole that
    // might behave differently.
    let mut peers = Vec::new();
    for index in 0..CONCURRENT_PEERS {
        let (peer, addr, key) = endpoint().await;
        peer.authorize(dialler_key);
        dialler.authorize(key);
        let mut candidates: Vec<SocketAddr> = (0..DEAD_CANDIDATES)
            .map(|dead| {
                SocketAddr::from((Ipv4Addr::new(127, 0, 0, (index % 250 + 2) as u8), dead as u16 + 1))
            })
            .collect();
        candidates.push(addr);
        peers.push((peer, key, candidates));
    }

    // Every peer parked in accept before any dial starts, so the measurement
    // is of the races and not of a peer that had not begun listening.
    let accepting: Vec<_> = peers
        .iter()
        .map(|(peer, _, _)| {
            let peer = peer.clone();
            tokio::spawn(async move { peer.accept(dialler_key).await })
        })
        .collect();

    let before_kib = resident_kib();
    let started = Instant::now();

    let races: Vec<_> = peers
        .iter()
        .map(|(_, key, candidates)| {
            let dialler = dialler.clone();
            let key = *key;
            let candidates = candidates.clone();
            tokio::spawn(async move { dialler.connect_racing(&candidates, key).await })
        })
        .collect();

    // The winners are held, not counted and dropped: dropping a
    // `quinn::Connection` closes it, and a closed connection is one the peer
    // will refuse -- which is the selection gate working, but it would make
    // this measure teardown rather than fan-in.
    let mut winners = Vec::new();
    for race in races {
        let outcome = tokio::time::timeout(Duration::from_secs(60), race)
            .await
            .expect("a race must resolve well inside one handshake timeout")
            .expect("race task");
        if let Ok((connection, _candidate)) = outcome {
            winners.push(connection);
        }
    }
    let connected = winners.len();
    let elapsed = started.elapsed();
    let after_kib = resident_kib();

    for accept in accepting {
        let claimed = tokio::time::timeout(Duration::from_secs(30), accept)
            .await
            .expect("every peer must claim its selected connection")
            .expect("accept task");
        assert!(claimed.is_some(), "every peer must be handed the connection the dialler chose");
    }

    println!(
        "fan-in: {CONCURRENT_PEERS} concurrent races x {} candidates ({DEAD_CANDIDATES} dead) \
         connected={connected} in {elapsed:?}; rss {before_kib} KiB -> {after_kib} KiB \
         (delta {} KiB)",
        DEAD_CANDIDATES + 1,
        after_kib.saturating_sub(before_kib),
    );

    assert_eq!(connected, CONCURRENT_PEERS, "every peer's live candidate must answer");
    // The live candidate is one stagger interval per dead predecessor behind
    // the first, so the floor is ~1.75s. A ceiling well under a handshake
    // timeout is what says the dead candidates were paid for concurrently
    // rather than in series, at this width as well as at one peer.
    assert!(
        elapsed < Duration::from_secs(15),
        "racing must stay concurrent under fan-in: {CONCURRENT_PEERS} peers took {elapsed:?}"
    );
    // Generous, because this is a regression bound and not a budget: what it
    // catches is a race that retains per-candidate state after it ends.
    assert!(
        after_kib.saturating_sub(before_kib) < 512 * 1024,
        "fan-in must not leave hundreds of megabytes behind: {before_kib} KiB -> {after_kib} KiB"
    );
}
