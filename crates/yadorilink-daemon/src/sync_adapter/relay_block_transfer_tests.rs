//! R4: a real Block-lane transfer, with direct IP transport unavailable so
//! the in-process relay is the ONLY carrier.
//!
//! `relay_equivalence_tests.rs` (R2) already proves that a *Change* --
//! metadata -- lands identically whichever carrier delivered it. What it
//! does not touch is the block lane: On-Demand's actual file content moves
//! separately, fetched by `PeerSyncSession::fetch_block` only when
//! something asks for it (`crate::hydration::hydrate`). This test carries
//! that further: a real Change referring to a real, chunked >=64 KiB file
//! version is admitted on the source device and reaches the hydrating one
//! over the relay exactly as R2 proves; this device's own background
//! convergence engine (the same one that runs in production --
//! `DaemonState::new` spawns it unconditionally) materializes that into an
//! On-Demand placeholder with no test-side help; `hydration::hydrate` then
//! triggers a real `PeerSyncSession` block fetch, over a `PeerSyncSession`
//! built on the SAME relay-only substrate `SyncStack` reconciled through --
//! the hydrating device's endpoint has no IP transport at all, so every
//! byte fetched here has nowhere to go but through the relay.
//!
//! Negative control (checked by hand, not kept as a second test): with
//! `hydrating_stack`
//! spawned via `relay.direct_or_relay()` instead of `relay.relay_only()`,
//! both endpoints are loopback-reachable and iroh finds the direct path,
//! same as `in_process_relay.rs`'s own
//! `a_node_that_can_go_direct_does_not_stay_on_the_relay`. Under that
//! configuration this test's `Carrier::Relay` assertion on the link the
//! block fetch just used fails (observed carrier is `Some(Direct)`), and
//! `has_direct_path()` is true -- proof the assertion actually
//! discriminates a relay-only transfer from one that quietly went direct,
//! rather than passing regardless of carrier. Reverting to
//! `relay.relay_only()` is what is committed below.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_transport::{ConnectRole, QuicPeerChannel};

use super::sync_stack::SyncStack;

const PATH: &str = "relayed-content.bin";

/// Over half a default 128 KiB block: real block-lane content, not
/// something that would fit in a control frame, while still being exactly
/// one block -- this test is about the block lane riding the relay, not
/// about multi-block reassembly.
const CONTENT_SIZE: usize = 64 * 1024;

async fn relayed_address_of(stack: &SyncStack) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let relays: Vec<String> = stack.local_address().relay_urls().map(str::to_string).collect();
        if !relays.is_empty() {
            return relays;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a relay-capable node never registered with the relay"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Chunks real content once and returns its (single) block plus the raw
/// bytes, keyed by hash -- the same shape `multi_peer_hydration.rs`'s own
/// `chunk_content` produces.
fn chunk_content(content: &[u8]) -> (yadorilink_replica_domain::file::BlockInfo, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, content).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(&store, &src).unwrap();
    assert_eq!(blocks.len(), 1, "this test's content is meant to be exactly one block");
    let block = blocks.into_iter().next().unwrap();
    let bytes = store.get(&hex::encode(&block.hash)).unwrap();
    (block, bytes)
}

async fn connect_pair() -> (Arc<QuicPeerChannel>, Arc<QuicPeerChannel>) {
    use yadorilink_transport::{DeviceSigningKeyPair, QuicPeerEndpoint, TransportHub};
    let socket_a = yadorilink_transport::sim_net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = yadorilink_transport::sim_net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let key_a = DeviceSigningKeyPair::generate();
    let key_b = DeviceSigningKeyPair::generate();
    let public_a = key_a.public_bytes();
    let public_b = key_b.public_bytes();
    let endpoint_a = QuicPeerEndpoint::new(TransportHub::from_socket(socket_a), key_a).unwrap();
    let endpoint_b = QuicPeerEndpoint::new(TransportHub::from_socket(socket_b), key_b).unwrap();
    endpoint_a.authorize(public_b);
    endpoint_b.authorize(public_a);
    let accepting = {
        let endpoint_b = endpoint_b.clone();
        tokio::spawn(async move { endpoint_b.accept(public_a).await })
    };
    let dialed = endpoint_a.connect(addr_b, public_b).await.unwrap();
    let accepted = accepting.await.unwrap().unwrap();
    (
        QuicPeerChannel::new(dialed, ConnectRole::Dial),
        QuicPeerChannel::new(accepted, ConnectRole::Accept),
    )
}
