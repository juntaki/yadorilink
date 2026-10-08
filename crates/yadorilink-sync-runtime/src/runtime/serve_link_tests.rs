#![cfg(test)]

use std::time::Duration;

use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{AdmitAnyAuthenticated, NetworkConfig};

use super::*;

async fn spawn_node(
    seed: u8,
    book: &SharedAddressBook,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    SubstrateNode::spawn(
        iroh::SecretKey::from_bytes(&[seed; 32]),
        NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
        Arc::new(AdmitAnyAuthenticated),
    )
    .await
    .expect("substrate starts")
}

/// A server runtime that reports the group of every lane stream it is handed,
/// and a link to it from a second node.
async fn serving_pair() -> (
    tokio::sync::mpsc::UnboundedReceiver<String>,
    PeerLink,
    (SubstrateNode, SyncRuntime, ServeHandle),
) {
    let book = SharedAddressBook::new();
    let (server_node, inbound) = spawn_node(1, &book).await;
    let (client_node, _client_inbound) = spawn_node(2, &book).await;
    let server = SyncRuntime::new(server_node);
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    server.when_lane_stream(Arc::new(move |_peer, group, _lane, _stream| {
        let seen_tx = seen_tx.clone();
        Box::pin(async move {
            let _ = seen_tx.send(group.0);
        })
    }));
    let handle = server.serve(inbound);
    let link = client_node.connect(server.peer_id()).await.expect("the client dials the server");
    (seen_rx, link, (client_node, server, handle))
}

async fn open_hello_lane(link: &PeerLink, group: &str) {
    let mut lane = link.open_lane(Lane::Service).await.expect("a lane opens");
    yadorilink_sync_protocol::session::open_lane(&mut lane, &GroupId(group.into()))
        .await
        .expect("the hello is written");
    // Keep the lane alive until the test ends.
    std::mem::forget(lane);
}

/// One stream with an unknown lane tag must not stop the connection's lane
/// serving: the next, well-formed stream is still handed to its hook.
#[tokio::test]
async fn a_stream_with_an_unknown_lane_tag_does_not_stop_later_streams_being_served() {
    let (mut seen, link, _keep) = serving_pair().await;

    let (mut send, _recv) = link.open_raw_stream_for_test().await.unwrap();
    send.write_all(&[0xEE]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    open_hello_lane(&link, "after-bad-tag").await;
    let group = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("the later stream must still be served")
        .unwrap();
    assert_eq!(group, "after-bad-tag");
}

/// A stream that never sends its lane tag must not hold up accepting the
/// streams behind it.
#[tokio::test]
async fn a_stream_that_never_sends_its_tag_does_not_block_the_streams_behind_it() {
    let (mut seen, link, _keep) = serving_pair().await;

    // Opened and left silent; QUIC only announces a stream once it has data, so send
    // nothing but keep the handle alive.
    let (mut silent, _silent_recv) = link.open_raw_stream_for_test().await.unwrap();
    silent.write_all(&[]).await.unwrap();

    open_hello_lane(&link, "behind-the-silent-stream").await;
    let group = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("a silent stream must not stall the accept loop")
        .unwrap();
    assert_eq!(group, "behind-the-silent-stream");
    drop(silent);
}
