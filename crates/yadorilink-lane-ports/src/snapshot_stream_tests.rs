//! Snapshot transfer over the history lane.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_sync_substrate::{HistoryStreamKind, Lane, NetworkConfig, PeerLink, SubstrateNode};

use super::snapshot_stream::{receive_snapshot_into, send_snapshot, SnapshotTransferError};
use yadorilink_sync_substrate::testing::SharedAddressBook;

/// A node publishing into, and resolving out of, `book`.
///
/// The book is per-test on purpose. A process-wide one is shared by every test
/// in this binary, and these tests reuse fixed seeds -- so two running at once
/// mint the SAME endpoint id, the later publish overwrites the earlier address,
/// and the first test then dials the second's node and waits forever for a
/// stream it will never open.
async fn node(
    book: &SharedAddressBook,
    seed: u8,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    let spawned = SubstrateNode::spawn_as_device(
        SigningKey::from_bytes(&[seed; 32]).to_bytes(),
        NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();
    // The dial that follows resolves out of the book, and iroh fills it
    // asynchronously -- see `wait_published`.
    book.wait_published(spawned.0.peer_id()).await;
    spawned
}

fn a_snapshot(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn hash_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_crosses_whole_and_verifies_against_its_manifest_hash() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 41).await;
    let (client, _c) = node(&book, 42).await;

    let snapshot = a_snapshot(3 * 1024 * 1024);
    let expected = hash_of(&snapshot);
    let sending = snapshot.clone();

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let mut lane = link.accept_lane().await.unwrap();
        assert_eq!(lane.lane(), Lane::History);
        send_snapshot(&mut lane, &sending).await.unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut lane = link.open_lane(Lane::History).await.unwrap();
    let mut spool = Vec::new();
    let written = receive_snapshot_into(&mut lane, &mut spool, &expected).await.unwrap();

    assert_eq!(written as usize, snapshot.len());
    assert_eq!(spool, snapshot);
    serving.await.unwrap();
}

/// One byte different is a different snapshot. The manifest is the authority
/// on which one this is, and the bytes answer to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_altered_byte_is_refused_against_the_manifest_hash() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 43).await;
    let (client, _c) = node(&book, 44).await;

    let snapshot = a_snapshot(128 * 1024);
    let expected = hash_of(&snapshot);
    let mut tampered = snapshot.clone();
    tampered[64 * 1024] ^= 0x01;

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let mut lane = link.accept_lane().await.unwrap();
        send_snapshot(&mut lane, &tampered).await.unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut lane = link.open_lane(Lane::History).await.unwrap();
    let mut spool = Vec::new();
    let refused = receive_snapshot_into(&mut lane, &mut spool, &expected).await;

    assert!(
        matches!(refused, Err(SnapshotTransferError::HashMismatch { .. })),
        "expected the altered snapshot to be refused, got {refused:?}"
    );
    serving.await.unwrap();
}

/// A peer that never stops sending is cut off by a ceiling, not by memory
/// running out. Nothing here ever reserved capacity on the peer's say-so —
/// there is no declared length to believe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_endless_snapshot_is_cut_off_rather_than_believed() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 45).await;
    let (client, _c) = node(&book, 46).await;

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let mut lane = link.accept_lane().await.unwrap();
        let chunk = vec![0u8; 64 * 1024];
        // Writes until the far end gives up on it.
        while lane.write_all(&chunk).await.is_ok() {}
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut lane = link.open_lane(Lane::History).await.unwrap();

    // A small ceiling stands in for the real one so the test is quick; the
    // property is that the receiver stops, not where it stops.
    let mut spool = CountingSink { written: 0, limit: 1 << 20 };
    let outcome = receive_snapshot_into(&mut lane, &mut spool, &[0u8; 32]).await;
    assert!(outcome.is_err(), "an endless stream must not be accepted");
    serving.abort();
}

/// The receiver writes as it reads: a snapshot far larger than any buffer it
/// holds still arrives, because it is never held whole in memory.
struct CountingSink {
    written: u64,
    limit: u64,
}

impl tokio::io::AsyncWrite for CountingSink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.written += buf.len() as u64;
        if self.written > self.limit {
            return std::task::Poll::Ready(Err(std::io::Error::other("spool ceiling reached")));
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// The reason the history lane is a lane at all: a large snapshot in flight
/// must not make reconciliation wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciliation_stays_responsive_while_a_snapshot_is_in_flight() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 47).await;
    let (client, _c) = node(&book, 48).await;

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        while let Ok(mut lane) = link.accept_lane().await {
            tokio::spawn(async move {
                match lane.lane() {
                    // Holds the snapshot stream open, sending slowly, exactly
                    // as a real one competing for the connection would.
                    Lane::History => {
                        let chunk = vec![0u8; 64 * 1024];
                        loop {
                            if lane.write_all(&chunk).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                    Lane::Reconciliation => {
                        let mut byte = [0u8; 1];
                        while lane.read_exact(&mut byte).await.is_ok() {
                            if lane.write_all(&byte).await.is_err() {
                                return;
                            }
                            let _ = lane.flush().await;
                        }
                    }
                    _ => {}
                }
            });
        }
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let _snapshot_lane = link.open_lane(Lane::History).await.unwrap();
    // Let the bulk stream get going before timing the small one.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut lane = link.open_lane(Lane::Reconciliation).await.unwrap();
    let started = Instant::now();
    lane.write_all(&[7u8]).await.unwrap();
    lane.flush().await.unwrap();
    let mut echoed = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), lane.read_exact(&mut echoed))
        .await
        .expect("reconciliation must not be stuck behind the snapshot")
        .unwrap();
    assert_eq!(echoed[0], 7);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a reconciliation round trip took {:?} with a snapshot in flight",
        started.elapsed()
    );

    serving.abort();
}

/// An unknown history stream kind fails closed rather than being guessed at.
#[test]
fn an_unknown_history_stream_kind_is_refused() {
    assert_eq!(HistoryStreamKind::from_tag(0), None);
    assert_eq!(HistoryStreamKind::from_tag(3), None);
    assert_eq!(HistoryStreamKind::from_tag(u8::MAX), None);
}

/// The three properties that make issuing a manifest safe: it is not a
/// capability, it is scoped to one group, and it is not a promise.
mod prepared_snapshot_gates {

    use std::sync::Arc;

    use crate::directory::PeerDirectory;
    use crate::prepared_snapshots::PreparedSnapshots;
    use crate::snapshot_service::serve_snapshot_stream;
    use ed25519_dalek::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yadorilink_sync_substrate::{Lane, NetworkConfig, PeerLink, SubstrateNode};

    const PEER: [u8; 32] = [61u8; 32];

    /// A directory whose answer can change between the manifest being issued
    /// and the snapshot being collected — which is the point.
    struct Revocable {
        authorized: std::sync::atomic::AtomicBool,
    }

    impl std::fmt::Debug for Revocable {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Revocable")
        }
    }

    impl PeerDirectory for Revocable {
        fn device_for_endpoint(&self, _endpoint: &[u8; 32]) -> Option<String> {
            Some("device-b".into())
        }
        fn is_authorized(&self, _device_id: &str, _group_id: &str) -> bool {
            self.authorized.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    /// A fresh book per call, not a shared one.
    ///
    /// These seeds are fixed, so every test here mints the SAME two endpoint
    /// ids. Sharing one book across tests let a later publish overwrite an
    /// earlier address, after which a test dialled another test's node and
    /// waited forever for a stream nobody was going to open -- which is why
    /// this binary hung above four test threads and passed serially.
    async fn nodes() -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>, SubstrateNode) {
        let book = super::SharedAddressBook::new();
        let (server, inbound) = SubstrateNode::spawn_as_device(
            SigningKey::from_bytes(&[51u8; 32]).to_bytes(),
            NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
            std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
        )
        .await
        .unwrap();
        let (client, _c) = SubstrateNode::spawn_as_device(
            SigningKey::from_bytes(&[52u8; 32]).to_bytes(),
            NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
            std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
        )
        .await
        .unwrap();
        (server, inbound, client)
    }

    /// Collect from `hello_group`, asking for `hash`, and report what came
    /// back.
    async fn collect(
        directory: Arc<Revocable>,
        prepared: Arc<PreparedSnapshots>,
        hello_group: &'static str,
        serve_group: &'static str,
        hash: [u8; 32],
    ) -> Vec<u8> {
        let (server, mut inbound, client) = nodes().await;

        let serving = tokio::spawn(async move {
            let link = inbound.recv().await.unwrap();
            let lane = link.accept_lane().await.unwrap();
            serve_snapshot_stream(lane, &PEER, serve_group, directory.as_ref(), prepared.as_ref())
                .await;
        });

        let link = client.connect(server.local_address().peer()).await.unwrap();
        let mut lane = link.open_lane(Lane::History).await.unwrap();
        let _ = hello_group;
        lane.write_all(&hash).await.unwrap();
        lane.flush().await.unwrap();
        let mut received = Vec::new();
        let _ = lane.read_to_end(&mut received).await;
        serving.await.unwrap();
        received
    }

    /// Gate 8: revoked after the manifest was issued, so the bytes are not
    /// served. A manifest already handed over is not a capability.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_revoked_after_the_manifest_was_issued_collects_nothing() {
        let prepared = Arc::new(PreparedSnapshots::new());
        prepared.prepare("g", [9u8; 32], Arc::new(vec![1u8; 4096]));

        let directory =
            Arc::new(Revocable { authorized: std::sync::atomic::AtomicBool::new(false) });
        let received = collect(directory, prepared.clone(), "g", "g", [9u8; 32]).await;
        assert!(received.is_empty(), "a revoked peer must collect nothing");

        // And still collectable by someone who is authorized, so the refusal
        // was the authorization and not the snapshot being gone.
        let directory =
            Arc::new(Revocable { authorized: std::sync::atomic::AtomicBool::new(true) });
        let received = collect(directory, prepared, "g", "g", [9u8; 32]).await;
        assert_eq!(received.len(), 4096);
    }

    /// Gate 9: the same hash, asked for under another group's hello, reaches
    /// nothing. The hash is in a signed manifest and is not a secret.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_same_hash_under_another_groups_hello_collects_nothing() {
        let prepared = Arc::new(PreparedSnapshots::new());
        prepared.prepare("g", [9u8; 32], Arc::new(vec![1u8; 4096]));

        let directory =
            Arc::new(Revocable { authorized: std::sync::atomic::AtomicBool::new(true) });
        let received = collect(directory, prepared, "other", "other", [9u8; 32]).await;
        assert!(received.is_empty(), "another group's hello must reach nothing");
    }

    /// Gate 10: after a restart the prepared snapshot is gone, and a stale
    /// fetch ends cleanly with nothing rather than erroring or hanging. The
    /// requester's recovery is to ask again from the top.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stale_fetch_after_a_restart_ends_cleanly_with_nothing() {
        let before_restart = Arc::new(PreparedSnapshots::new());
        before_restart.prepare("g", [9u8; 32], Arc::new(vec![1u8; 4096]));

        // A fresh store is what a restarted daemon has.
        let after_restart = Arc::new(PreparedSnapshots::new());
        let directory =
            Arc::new(Revocable { authorized: std::sync::atomic::AtomicBool::new(true) });
        let received = collect(directory, after_restart.clone(), "g", "g", [9u8; 32]).await;
        assert!(received.is_empty(), "a restarted daemon serves no stale snapshot");

        // Asking again from the top prepares it afresh and completes.
        after_restart.prepare("g", [9u8; 32], Arc::new(vec![2u8; 4096]));
        let directory =
            Arc::new(Revocable { authorized: std::sync::atomic::AtomicBool::new(true) });
        let received = collect(directory, after_restart, "g", "g", [9u8; 32]).await;
        assert_eq!(received.len(), 4096);
    }
}
