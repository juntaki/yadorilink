//! R5: the SAME connection a `PeerSyncSession` pair was built on evolves
//! from the relay to a direct path while it is live, with no reconnect, no
//! new session, and no application-level "promotion" logic -- iroh owns the
//! whole thing, exactly as `PeerLink::carrier`'s own doc comment describes:
//! "A connection normally opens over a relay and gains a direct path once
//! hole punching succeeds, at which point the selected path changes under
//! it -- the connection itself does not change."
//!
//! Unlike `relay_block_transfer_tests.rs` (R4), where the hydrating device
//! has NO IP transport at all -- so relay is the only carrier there could
//! ever be -- both devices here keep their real IP transports
//! (`relay.direct_or_relay()` on both sides). What forces the connection to
//! *start* on the relay is narrower and more precise than removing a whole
//! transport: `device-b`'s own knowledge of `device-a`'s address is
//! deliberately recorded with no direct candidates at all, only the relay
//! URL -- exactly what a coordination-plane netmap entry looks like before
//! it has ever learned a peer's direct endpoint. iroh dials with only that,
//! so the first path the connection can possibly use is the relay; nothing
//! here disables direct dialling in general, the way `relay_only_for_tests`
//! does.
//!
//! Once connected, this device does nothing else at all -- no address
//! update, no reconnect, no session swap. iroh's own hole-punching discovers
//! and validates a direct path on the SAME live connection independently of
//! what candidate addresses were supplied at dial time (confirmed
//! empirically before writing this test: a throwaway probe dialling with a
//! relay-only `PeerAddress`, both ends otherwise IP-transport-capable, still
//! reached `has_direct_path() == true` / `carrier() == Some(Direct)` well
//! inside `in_process_relay.rs`'s own 30s budget for the equivalent
//! already-direct-addressed case). That is the property under test: this
//! crate's job is to have supplied the required transports once and then
//! get out of the way.
//!
//! A single `PeerSyncSession` pair, constructed once and never rebuilt,
//! serves two different authorized blocks -- one fetched before the
//! transition, one after -- and is asked, both before and after, to fetch a
//! block that was never published at all. The two denials must be
//! identical: `block_request_is_referenced`'s check
//! (`published_file_at_path`/`published_group_file_version_references_block`)
//! takes no parameter naming a carrier, and this test asserts that rather
//! than merely relying on it.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId};
use yadorilink_sync_sqlite::verified_change_store;
use yadorilink_transport::{ConnectRole, QuicPeerChannel};

use super::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{change_putting, honest_bundle_carrying};

/// Real content, really chunked -- one block each, so a fetch is one
/// request/response pair and the property under test is not entangled with
/// multi-block reassembly. `tag` keeps the three blocks' bytes (and
/// therefore their hashes) from colliding with each other.
fn chunk_tagged_content(
    tag: u8,
    size: usize,
) -> (Vec<u8>, yadorilink_replica_domain::file::BlockInfo, Vec<u8>) {
    let content: Vec<u8> = (0..size as u32).map(|i| tag.wrapping_add((i % 251) as u8)).collect();
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, &content).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(&store, &src).unwrap();
    assert_eq!(blocks.len(), 1, "this test's content is meant to be exactly one block");
    let block = blocks.into_iter().next().unwrap();
    let bytes = store.get(&hex::encode(&block.hash)).unwrap();
    (content, block, bytes)
}

/// A raw QUIC channel pair for the session's own message-channel argument --
/// unrelated to the relay: `SessionTransports` (built from `SyncStack::
/// transports_for`, below) is what carries the actual block-lane traffic
/// this test is about. See `relay_block_transfer_tests.rs`'s own
/// `connect_pair` -- identical helper, duplicated rather than shared, the
/// same way that file duplicates it from nothing further up.
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

/// Publishes one block on `state` as a genuinely admitted, published
/// `FileVersion` at `path` -- the same staging + `dag_put_file_version` +
/// admission-drain sequence `relay_block_transfer_tests.rs` uses, and for
/// the same reason: `block_request_is_referenced` checks the *published*
/// index, not merely "this device holds the bytes".
async fn publish_block(
    state: &Arc<crate::daemon_state::DaemonState>,
    stack: &SyncStack,
    group: &FolderGroupId,
    path: &str,
    block: &yadorilink_replica_domain::file::BlockInfo,
    block_bytes: &[u8],
    content_len: u64,
) {
    state.block_store.put(block_bytes).unwrap();
    state
        .replica_coordinator
        .change_history_repository()
        .record_group_block_provenance(&group.0, std::slice::from_ref(&block.hash))
        .unwrap();
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block.hash.clone()), size: block.size }],
        content_len,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let change = change_putting(path, &version);
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                1,
            )
        })
        .unwrap();
    state
        .replica_coordinator
        .change_history_repository()
        .dag_put_file_version(&group.0, &version)
        .unwrap();
    stack.admission().drain(group).await.expect("admission drain must not fail");
    assert!(
        state
            .replica_coordinator
            .change_history_repository()
            .dag_group_file_version_references_block(&group.0, &block.hash)
            .unwrap(),
        "the published Change must be promoted into the canonical DAG before it can authorize serving"
    );
}
