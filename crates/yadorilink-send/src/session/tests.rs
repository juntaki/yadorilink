#![cfg(test)]

use super::*;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use yadorilink_sync_substrate::{AdmitNone, AdmitWhen, NetworkConfig};

/// One device's iroh endpoint on loopback, answering Track Send's ALPN.
///
/// Who may open a Track Send connection to it is `admitted`, standing in
/// for the daemon's grant/accepted-offer admission; nobody may open a sync
/// connection. The grant gate this module tests is enforced at the
/// application layer (`handle_offer`) on top of that admission, so proving
/// it needs the same real handshake and ALPN routing production uses.
struct TestEndpoint {
    node: SubstrateNode,
    key: [u8; 32],
    admitted: Arc<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>>,
    inbound: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<TrackSendConnection>>>,
}

impl TestEndpoint {
    /// Let `key` open Track Send connections to this endpoint.
    fn admit(&self, key: [u8; 32]) {
        self.admitted.lock().unwrap().insert(key);
    }

    /// The inbound Track Send connections; one owner.
    fn take_inbound(&self) -> tokio::sync::mpsc::Receiver<TrackSendConnection> {
        self.inbound.lock().unwrap().take().expect("the inbound queue has exactly one owner")
    }

    /// How another device's directory would describe this one.
    fn resolved(&self, device_id: &str) -> ResolvedDevice {
        let address = self.node.local_address();
        ResolvedDevice {
            device_id: device_id.to_string(),
            signing_key: self.key,
            direct_addresses: address.direct_addrs().copied().collect(),
            relay_urls: Vec::new(),
        }
    }
}

async fn raw_endpoint() -> Arc<TestEndpoint> {
    let secret: [u8; 32] = rand_key();
    let admitted: Arc<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> = Arc::default();
    let admission = {
        let admitted = admitted.clone();
        AdmitWhen::new(move |peer: &PeerId| admitted.lock().unwrap().contains(peer.as_bytes()))
    };
    let (inbound_tx, inbound) = tokio::sync::mpsc::channel(16);
    let (node, _sync_inbound) = SubstrateNode::spawn_as_device(
        secret,
        NetworkConfig::direct_only().with_track_send(admission, inbound_tx),
        Arc::new(AdmitNone),
    )
    .await
    .expect("bind endpoint");
    let key = *node.peer_id().as_bytes();
    Arc::new(TestEndpoint { node, key, admitted, inbound: std::sync::Mutex::new(Some(inbound)) })
}

/// A fresh random 32-byte secret, from the same source transfer ids use.
fn rand_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key
}

/// A fresh `SendService` over `endpoint`, backed by its own isolated
/// temp directory (kept alive by the returned guard). Never starts
/// `run_inbound_dispatcher` itself -- a caller that needs this service
/// to actually receive connections spawns that separately with the
/// endpoint's inbound queue, exactly like production (`send_transfer::run`)
/// does.
fn make_service(
    endpoint: &TestEndpoint,
    directory: Arc<dyn DeviceDirectory>,
) -> (Arc<SendService>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store_db_path = dir.path().join("store.sqlite3");
    let block_store_root = dir.path().join("blocks");
    let inbox_dir = dir.path().join("inbox");
    let service = SendService::new(
        endpoint.node.clone(),
        store_db_path,
        block_store_root,
        directory,
        inbox_dir,
    )
    .expect("SendService::new should succeed against a fresh temp directory");
    (Arc::new(service), dir)
}

/// `make_service`, with the service serving `endpoint`'s inbound Track
/// Send connections.
fn serving_service(
    endpoint: &TestEndpoint,
    directory: Arc<dyn DeviceDirectory>,
) -> (Arc<SendService>, tempfile::TempDir) {
    let (service, guard) = make_service(endpoint, directory);
    tokio::spawn(service.clone().run_inbound_dispatcher(endpoint.take_inbound()));
    (service, guard)
}

/// A single-use, in-memory stand-in for the coordination plane's
/// `send_authorizations` table -- atomic issue/consume, bound to the
/// presenting connection's authenticated key, matching
/// `DaemonDeviceDirectory::consume_grant`'s own doc comment for the
/// real primitive, without needing a real D1/coordination worker for
/// these tests.
#[derive(Default)]
struct FakeGrantStore {
    inner: std::sync::Mutex<FakeGrantStoreInner>,
}

#[derive(Default)]
struct FakeGrantStoreInner {
    grants: HashMap<String, FakeGrantRecord>,
    last_issued: Option<(String, String)>,
}

struct FakeGrantRecord {
    nonce: String,
    sender_key: [u8; 32],
    consumed: bool,
}

impl FakeGrantStore {
    fn issue(&self, grant_id: &str, nonce: &str, sender_key: [u8; 32]) {
        let mut inner = self.inner.lock().unwrap();
        inner.grants.insert(
            grant_id.to_string(),
            FakeGrantRecord { nonce: nonce.to_string(), sender_key, consumed: false },
        );
        inner.last_issued = Some((grant_id.to_string(), nonce.to_string()));
    }

    fn last_issued(&self) -> (String, String) {
        self.inner.lock().unwrap().last_issued.clone().expect("a grant must have been issued")
    }

    /// One lock guards the whole check-then-mark sequence, so two
    /// presentations of the same grant can never both observe it as
    /// unconsumed -- the same atomicity
    /// `DaemonDeviceDirectory::consume_grant`'s own doc comment
    /// describes for the real coordination-plane primitive.
    fn consume(
        &self,
        grant_id: &str,
        nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        let Some(record) = inner.grants.get_mut(grant_id) else {
            return Err("send authorization is invalid, expired, or already used".to_string());
        };
        if record.consumed || record.nonce != nonce || &record.sender_key != peer_key {
            return Err("send authorization is invalid, expired, or already used".to_string());
        }
        record.consumed = true;
        Ok(())
    }
}

/// A `DeviceDirectory` for the RECEIVING side of these tests.
/// `consume_grant` either delegates to a real (fake) grant store, or --
/// when `grants` is `None` -- fails closed exactly like the trait's own
/// default, modeling a directory with ZERO grant capability at all (the
/// cross-account-shaped case: nothing this directory could ever have
/// granted). `resolve` always returns `None`: `handle_offer` never
/// calls it (only `offer_send` used to, before this fix), so these
/// tests keep it inert on purpose rather than implying it takes part in
/// the check being tested. `request_grant` is never overridden: none of
/// these tests drive `offer_send` from the receiving side.
struct TestDirectory {
    grants: Option<Arc<FakeGrantStore>>,
    device_labels: HashMap<[u8; 32], String>,
}

#[async_trait::async_trait]
impl DeviceDirectory for TestDirectory {
    fn resolve(&self, _device_query: &str) -> Option<ResolvedDevice> {
        None
    }

    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        self.device_labels.get(signing_key).cloned()
    }

    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        match &self.grants {
            Some(store) => store.consume(grant_id, grant_nonce, peer_key),
            None => Err("this directory does not support Track Send grants".to_string()),
        }
    }
}

/// A `DeviceDirectory` for the SENDING side of the positive-control
/// test at the bottom of this module: `request_grant` mints a real,
/// single-use grant against a shared `FakeGrantStore`, bound to
/// `sender_key` -- the same shape `DaemonDeviceDirectory::request_grant`
/// produces against the real coordination plane. `resolve` is always
/// `None`: the point of that test is that `offer_send` completes with
/// NO ordinary netmap relationship at all.
struct GrantingDirectory {
    sender_key: [u8; 32],
    grants: Arc<FakeGrantStore>,
    target: ResolvedDevice,
}

#[async_trait::async_trait]
impl DeviceDirectory for GrantingDirectory {
    fn resolve(&self, _device_query: &str) -> Option<ResolvedDevice> {
        None
    }

    fn device_id_for_key(&self, _signing_key: &[u8; 32]) -> Option<String> {
        None
    }

    async fn request_grant(&self, receiver_device_query: &str) -> Option<GrantedDevice> {
        if receiver_device_query != self.target.device_id {
            return None;
        }
        let grant_id = format!("grant-{}", uuid::Uuid::new_v4());
        let grant_nonce = format!("nonce-{}", uuid::Uuid::new_v4());
        self.grants.issue(&grant_id, &grant_nonce, self.sender_key);
        Some(GrantedDevice {
            device: self.target.clone(),
            grant_id,
            grant_nonce,
            // Effectively never expires within a test's lifetime.
            expires_at_unix: i64::MAX,
        })
    }
}

/// Dials `addr` over send-ALPN and presents a bare-bones manifest offer
/// carrying exactly the `grant_id`/`grant_nonce` given -- the raw
/// wire-level primitive every test below drives directly, bypassing
/// `offer_send` entirely, so each test controls precisely what an
/// adversarial or merely non-compliant sender presents (including
/// presenting nothing at all).
async fn raw_offer(
    dialer: &TestEndpoint,
    target: &TestEndpoint,
    transfer_id: &str,
    grant_id: &str,
    grant_nonce: &str,
) -> SendManifestAck {
    let connection =
        dialer.node.connect_track_send(&target.resolved("target").address()).await.expect(
            "a Track Send dial completes -- transport-layer admission is not this test's \
         concern, only the application-layer grant check is",
        );
    let (mut send, mut recv) = connection.open_stream().await.expect("open a stream");
    write_message(
        &mut send,
        &SendEnvelope {
            payload: Some(send_envelope::Payload::Manifest(SendManifest {
                transfer_id: transfer_id.to_string(),
                files: vec![],
                total_size: 0,
                offered_at_unix_nanos: 0,
            })),
            grant_id: grant_id.to_string(),
            grant_nonce: grant_nonce.to_string(),
        },
    )
    .await
    .unwrap();
    send.finish().ok();
    let ack: SendManifestAck = read_message(&mut recv).await.unwrap();
    connection.close(close_code::DONE, b"test offer");
    ack
}

/// A peer the Track Send ALPN admits (because this device expects it for
/// some other reason -- an earlier grant, an accepted offer) and a
/// receiving directory that DOES have real grant capability, so a compliant
/// sender genuinely could have obtained and presented one. An offer that
/// presents no grant at all must still be rejected: being admitted on the
/// ALPN is never, by itself, sufficient to deliver a Send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_offer_from_an_admitted_peer_is_rejected() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    acceptor.admit(dialer.key);

    let grants = Arc::new(FakeGrantStore::default());
    let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants),
        device_labels: HashMap::from([(dialer.key, "dialer-device".to_string())]),
    });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let ack = raw_offer(&dialer, &acceptor, "ungranted-admitted", "", "").await;

    assert!(
        !ack.accepted,
        "an admitted peer must not be able to complete a Send offer without presenting a grant"
    );
    assert!(!ack.reason.is_empty(), "a rejection must carry a reason");
    assert!(
        service.list_inbox().unwrap().is_empty(),
        "a rejected offer must leave no trace, not even a rejected-but-stored inbox entry"
    );
}

/// The cross-account-shaped variant: an admitted peer whose receiving
/// directory has ZERO grant capability whatsoever -- not merely "this
/// sender didn't present one", but "nothing here could ever have granted
/// it" (the trait's own default `consume_grant`). Must still be rejected
/// outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_offer_from_an_admitted_peer_with_zero_grant_capability_is_rejected() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    acceptor.admit(dialer.key);

    let directory: Arc<dyn DeviceDirectory> =
        Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let ack = raw_offer(&dialer, &acceptor, "ungranted-cross-account-shaped", "", "").await;

    assert!(!ack.accepted, "a directory with zero grant capability must still reject cleanly");
    assert!(service.list_inbox().unwrap().is_empty());
}

/// A genuinely valid grant authorizes exactly ONE offer, not unlimited
/// offers from an already-admitted sender -- a second presentation of the
/// SAME grant, and a third offer that omits `grant_id` entirely while
/// still admitted from the first grant, must both be rejected. Otherwise a
/// sender could omit `grant_id` on every offer after its first and ride
/// that one grant admission indefinitely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumed_grant_cannot_authorize_a_second_or_third_offer() {
    let dialer = raw_endpoint().await;
    let acceptor = raw_endpoint().await;
    // Admitted because of the grant below -- the groupless-sender shape.
    acceptor.admit(dialer.key);

    let grants = Arc::new(FakeGrantStore::default());
    grants.issue("grant-1", "nonce-1", dialer.key);
    let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants),
        device_labels: HashMap::from([(dialer.key, "sender-device".to_string())]),
    });
    let (service, _dir_guard) = serving_service(&acceptor, directory);

    let first = raw_offer(&dialer, &acceptor, "transfer-3a", "grant-1", "nonce-1").await;
    assert!(
        first.accepted,
        "a genuinely valid, unconsumed grant must authorize its offer: {}",
        first.reason
    );

    let second = raw_offer(&dialer, &acceptor, "transfer-3b", "grant-1", "nonce-1").await;
    assert!(
        !second.accepted,
        "a second presentation of an already-consumed grant must be rejected"
    );

    let third = raw_offer(&dialer, &acceptor, "transfer-3c", "", "").await;
    assert!(
        !third.accepted,
        "omitting grant_id must not let an already-admitted sender make unlimited offers off \
         one grant admission"
    );

    let inbox = service.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1, "only the single genuinely-granted offer should be recorded");
    assert_eq!(inbox[0].transfer_id, "transfer-3a");
}

/// The positive control: `offer_send` itself, driven end to end with NO
/// ordinary netmap relationship on either side at all, still completes
/// -- because it always obtains a real grant via `request_grant` rather
/// than needing `resolve` to succeed first. Proves the gate does not
/// merely reject everything: a compliant sender presenting a real,
/// freshly-obtained grant is still accepted, and that same grant cannot
/// then be replayed over the raw wire path either. Also pins the sender's
/// half of pull admission: once the offer is accepted, the sender expects
/// the receiver back (`expects_pull_from`), and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_send_obtains_and_attaches_a_real_grant_with_no_netmap_relationship_at_all() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;

    let grants = Arc::new(FakeGrantStore::default());
    let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
        grants: Some(grants.clone()),
        device_labels: HashMap::from([(sender_endpoint.key, "sender-device".to_string())]),
    });
    let (receiver_service, _receiver_dir_guard) =
        serving_service(&receiver_endpoint, receiver_directory);
    // Outside this crate's own scope in production: the coordination
    // plane pushes the grant to the RECEIVER over its netmap
    // subscription, and the daemon's Track Send admission then lets the
    // sender's key in for the grant's lifetime. This crate has no idea a
    // coordination plane exists, so this test stands in for that push
    // having already landed before the sender's offer connection arrives.
    receiver_endpoint.admit(sender_endpoint.key);

    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
        sender_key: sender_endpoint.key,
        grants: grants.clone(),
        target: receiver_endpoint.resolved("receiver-device"),
    });
    let (sender_service, _sender_dir_guard) = make_service(&sender_endpoint, sender_directory);
    assert!(
        !sender_service.expects_pull_from(&receiver_endpoint.key),
        "nothing has been offered yet"
    );

    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("hello.txt");
    std::fs::write(&source_path, b"hello via a fresh grant, no netmap relationship at all")
        .unwrap();

    let outcome = sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect("offer_send should succeed once a real grant is obtained");
    assert_eq!(outcome.files_offered, vec!["hello.txt".to_string()]);
    assert!(
        sender_service.expects_pull_from(&receiver_endpoint.key),
        "an accepted offer's receiver may come back to pull"
    );
    assert!(
        !sender_service.expects_pull_from(&sender_endpoint.key),
        "only the device the offer was accepted by"
    );

    let inbox = receiver_service.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].transfer_id, outcome.transfer_id);

    // The exact grant `offer_send` minted and consumed above must not
    // be replayable over the raw wire path either.
    let (used_grant_id, used_grant_nonce) = grants.last_issued();
    let replay = raw_offer(
        &sender_endpoint,
        &receiver_endpoint,
        "replay-attempt",
        &used_grant_id,
        &used_grant_nonce,
    )
    .await;
    assert!(!replay.accepted, "the grant offer_send already consumed must not be replayable");
}

/// A receiver that answers `SendManifestAck{accepted:false}` must not
/// be able to dial the sender back afterward and pull the file content
/// anyway. `offer_send` moves the outbound row to
/// `OutboundStatus::Rejected` once it observes the rejection, and
/// `handle_pull` requires `OutboundStatus::Acked` before serving any
/// chunk -- this drives both halves together over real connections, in
/// the exact two-connection shape (one for the offer, a wholly separate
/// one for the pull) a real receiver uses. The sender also stops
/// expecting that receiver (`expects_pull_from`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_rejects_the_offer_cannot_later_pull_the_content() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    // Stands in for the coordination plane's own push of the grant to
    // the receiver, exactly as the positive-control test does.
    receiver_endpoint.admit(sender_endpoint.key);
    // The sender still admits the receiver's key while the grant it
    // requested is live, so a pull attempt reaches `handle_pull` and must
    // be refused there.
    sender_endpoint.admit(receiver_endpoint.key);

    let grants = Arc::new(FakeGrantStore::default());
    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
        sender_key: sender_endpoint.key,
        grants: grants.clone(),
        target: receiver_endpoint.resolved("receiver-device"),
    });
    // Production parity: `send_transfer::run` always runs the dispatcher,
    // so the sender really does serve inbound pulls.
    let (sender_service, _sender_guard) = serving_service(&sender_endpoint, sender_directory);

    let secret = b"content a rejecting receiver must never get".to_vec();
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("secret.txt");
    std::fs::write(&source_path, &secret).unwrap();

    // A hand-rolled receiver that rejects every offer but remembers the
    // transfer id it saw in the manifest, so it can try pulling by id
    // afterward exactly like a real (malicious or merely buggy) client
    // could.
    let mut inbox = receiver_endpoint.take_inbound();
    let (id_tx, id_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let connection = inbox.recv().await.expect("an inbound offer");
        let (mut send, mut recv) = connection.accept_stream().await.expect("offer stream");
        let envelope: SendEnvelope = read_message(&mut recv).await.unwrap();
        let Some(send_envelope::Payload::Manifest(manifest)) = envelope.payload else {
            panic!("expected a manifest offer");
        };
        write_message(
            &mut send,
            &SendManifestAck { accepted: false, reason: "receiver rejects this offer".to_string() },
        )
        .await
        .unwrap();
        send.finish().ok();
        send.flushed(Duration::from_secs(5)).await;
        let _ = id_tx.send(manifest.transfer_id);
    });

    let err = sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect_err("the receiver rejected, so offer_send must fail");
    assert!(matches!(err, SendError::OfferRejected(_)), "got {err:?}");
    let transfer_id = id_rx.await.expect("the receiver saw a transfer id");
    assert!(
        !sender_service.expects_pull_from(&receiver_endpoint.key),
        "a rejected offer gives the receiver no reason to be let back in"
    );

    // Now the rejecting receiver dials the sender BACK, on a fresh
    // connection, and pulls -- this must be refused at the application
    // layer, in `handle_pull` itself.
    let connection = receiver_endpoint
        .node
        .connect_track_send(&sender_endpoint.resolved("sender").address())
        .await
        .expect("the sender still admits this key on the Track Send ALPN");
    let (mut send, mut recv) = connection.open_stream().await.unwrap();
    write_message(
        &mut send,
        &SendEnvelope {
            payload: Some(send_envelope::Payload::Pull(ChunkPullRequest {
                transfer_id,
                file_index: 0,
                start_chunk_index: 0,
            })),
            grant_id: String::new(),
            grant_nonce: String::new(),
        },
    )
    .await
    .unwrap();
    send.finish().ok();

    let message: ChunkStreamMessage =
        tokio::time::timeout(Duration::from_secs(15), read_message(&mut recv))
            .await
            .expect("the sender answered the pull within 15s")
            .unwrap();
    match message.payload {
        Some(chunk_stream_message::Payload::Rejected(r)) => {
            assert!(!r.reason.is_empty(), "a rejection must carry a reason");
        }
        Some(chunk_stream_message::Payload::Header(h)) => {
            let body = read_body(&mut recv, h.size as usize).await.unwrap();
            panic!(
                "a receiver that rejected the offer must not be able to pull the content, \
                 but the pull was served: {} bytes, matches source: {}",
                body.len(),
                body == secret
            );
        }
        None => panic!("empty message"),
    }
}

/// A `DeviceDirectory` that can resolve a target through ordinary
/// netmap connectivity (`resolve` -> `Some`, a real reachable address)
/// but has ZERO grant capability (`request_grant` falls through to the
/// trait's own `None` default) -- the shape a same-account device this
/// daemon can already reach over sync, but for which the coordination
/// plane will not currently mint a Send grant, would present.
struct NetmapOnlyDirectory {
    target: ResolvedDevice,
}

#[async_trait::async_trait]
impl DeviceDirectory for NetmapOnlyDirectory {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        (device_query == self.target.device_id).then(|| self.target.clone())
    }
    fn device_id_for_key(&self, _signing_key: &[u8; 32]) -> Option<String> {
        None
    }
}

/// The negative control for `offer_send`'s own half of the grant
/// requirement: a target `resolve` can reach through ordinary netmap
/// connectivity, but for which no grant is obtainable, must make
/// `offer_send` fail with `NoKnownDeviceKey` BEFORE it ever dials --
/// not fall back to sending an ungranted offer the receiver then has to
/// reject on its own. The positive-control test above cannot exercise
/// this guard by itself, because its own `resolve` always returns
/// `None`; this test is the one that actually proves `offer_send` never
/// treats netmap-resolvability as a substitute for a grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_send_refuses_a_netmap_resolvable_target_when_no_grant_can_be_obtained() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    // Even admitted on the receiver's side, nothing may be sent ungranted.
    receiver_endpoint.admit(sender_endpoint.key);

    let receiver_directory: Arc<dyn DeviceDirectory> =
        Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
    let (receiver_service, _receiver_guard) =
        serving_service(&receiver_endpoint, receiver_directory);

    let sender_directory: Arc<dyn DeviceDirectory> =
        Arc::new(NetmapOnlyDirectory { target: receiver_endpoint.resolved("receiver-device") });
    let (sender_service, _sender_guard) = make_service(&sender_endpoint, sender_directory);

    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("hello.txt");
    std::fs::write(&source_path, b"ordinary netmap peer, no grant available").unwrap();

    let error = sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect_err("a target with no obtainable grant must not be sendable to");
    assert!(
        matches!(error, SendError::NoKnownDeviceKey(_)),
        "offer_send must fail on the missing grant BEFORE dialing, not fall back to an \
         ungranted offer the receiver then rejects; got: {error:?}"
    );
    assert!(
        receiver_service.list_inbox().unwrap().is_empty(),
        "no offer should have reached the receiver at all"
    );
}

// ---- pull-loop validation against the receiver's own manifest -------
//
// `pull_file` is exercised directly (bypassing `receive_transfer`'s own
// store/destination-directory bookkeeping, which is orthogonal to what
// is being proven here) against a hand-rolled "sender" that answers a
// pull with whatever a real, already-accepted `SendService` never
// would -- a wrong chunk index, a chunk declared a different size than
// the manifest says, a chunk whose body does not hash to what the
// manifest recorded, or more chunks than the manifest has entries for.
// The point in every case is the same: an accepted sender is trusted
// for network reachability, never for chunk content, size, order, or
// count -- this device's own manifest, already durably on disk before
// any of these pulls dial out, is what every received chunk is
// checked against.

/// A `SendFileEntry` whose `chunk_hashes`/`chunk_size`/`size` are
/// derived directly from `chunk_bodies`, exactly the way
/// `build_outbound_manifest` would have produced them for a real file
/// split into these exact chunks -- so `pull_file`'s validation against
/// this entry is checked against the same shape of manifest a real
/// offer would carry, not a hand-waved stand-in.
fn pull_test_entry(chunk_size: u32, chunk_bodies: &[&[u8]]) -> SendFileEntry {
    let chunk_hashes = chunk_bodies
        .iter()
        .map(|body| hex::decode(hash_block_bytes(body)).expect("hex-decodes"))
        .collect();
    let size: u64 = chunk_bodies.iter().map(|body| body.len() as u64).sum();
    SendFileEntry { relative_path: "pulled.bin".to_string(), size, chunk_size, chunk_hashes }
}

/// Accepts exactly one inbound Track Send connection on `endpoint`,
/// confirms it carries a `ChunkPullRequest` (not a manifest offer), and
/// then writes exactly the `(header, body)` pairs given, in order,
/// before finishing the stream -- a hand-rolled "sender" answering a
/// pull with whatever a test wants to present, without a second real
/// `SendService` involved at all.
async fn fake_pull_responder(endpoint: Arc<TestEndpoint>, responses: Vec<(ChunkHeader, Vec<u8>)>) {
    let mut inbox = endpoint.take_inbound();
    let connection = inbox.recv().await.expect("an inbound pull connection");
    let (mut send, mut recv) = connection.accept_stream().await.expect("pull stream");
    let envelope: SendEnvelope = read_message(&mut recv).await.unwrap();
    assert!(
        matches!(envelope.payload, Some(send_envelope::Payload::Pull(_))),
        "expected a chunk pull request, got {envelope:?}"
    );
    for (header, body) in responses {
        write_message(
            &mut send,
            &ChunkStreamMessage { payload: Some(chunk_stream_message::Payload::Header(header)) },
        )
        .await
        .unwrap();
        send.write_all(&body).await.unwrap();
    }
    send.finish().ok();
    send.flushed(Duration::from_secs(5)).await;
}

/// A real receiver `SendService`, plus a fake sender's raw endpoint
/// (already admitting the receiver's key on the Track Send ALPN, exactly
/// as a real sender's admission does for an accepted offer) and the
/// `ResolvedDevice` `pull_file` needs to dial it -- the shared setup
/// every test in this group starts from.
async fn receiver_and_fake_sender(
) -> (Arc<SendService>, tempfile::TempDir, Arc<TestEndpoint>, ResolvedDevice) {
    let fake_sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    fake_sender_endpoint.admit(receiver_endpoint.key);

    let receiver_directory: Arc<dyn DeviceDirectory> =
        Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
    let (receiver_service, receiver_guard) = make_service(&receiver_endpoint, receiver_directory);
    let sender = fake_sender_endpoint.resolved("fake-sender");
    (receiver_service, receiver_guard, fake_sender_endpoint, sender)
}

/// A chunk header whose declared `size` disagrees with what this
/// device's own manifest says chunk 0 of a single-chunk file must be
/// must be rejected -- and rejected BEFORE the body is read, since an
/// unchecked peer-supplied `size` is exactly what would otherwise size
/// an unbounded allocation in `read_body`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_file_rejects_a_chunk_whose_declared_size_disagrees_with_the_manifest() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"hello"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![(ChunkHeader { chunk_index: 0, size: 999, last_chunk: true }, b"hello".to_vec())],
    ));

    let error = tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang on an oversized declared chunk size")
    .expect_err("a chunk whose declared size disagrees with the manifest must be rejected");
    assert!(matches!(error, SendError::Protocol(_)), "got {error:?}");
}

/// A chunk whose body does not hash to what this device's own manifest
/// recorded for that chunk index must be rejected -- and rejected
/// before `block_store.put` ever durably commits it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_file_rejects_a_chunk_that_fails_hash_verification() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"hello"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![(ChunkHeader { chunk_index: 0, size: 5, last_chunk: true }, b"WRONG".to_vec())],
    ));

    let error = tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang on a hash-mismatched chunk")
    .expect_err("a chunk that does not hash to the manifest's entry must be rejected");
    assert!(
        matches!(error, SendError::ChunkHashMismatch { file_index: 0, chunk_index: 0 }),
        "got {error:?}"
    );

    // The mismatched body must never have reached the block store --
    // the receiver's own manifest hash is checked before `put`, not
    // after.
    let expected_hex = hex::encode(&entry.chunk_hashes[0]);
    let present =
        receiver_service.block_store.present_blocks(std::slice::from_ref(&expected_hex)).unwrap();
    assert_eq!(present, vec![false], "the expected chunk hash must not be present");
}

/// However many extra chunks a peer keeps sending, and whatever it sets
/// `last_chunk` to, `pull_file` must stop reading once it has received
/// as many chunks as this device's own manifest says the file has --
/// never fewer (an early, dishonest `last_chunk: true` is a separate,
/// pre-existing concern this test does not touch), and never more.
/// Proven by a fake sender that never sets `last_chunk: true` at all,
/// and would fail a THIRD chunk's own size validation if `pull_file`
/// ever asked for it (`chunk_byte_size` has no chunk index 2 in a
/// 2-chunk manifest) -- so the pull only succeeds if the loop stopped
/// itself, by count, without ever issuing that third read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_file_stops_at_the_manifests_chunk_count_regardless_of_last_chunk() {
    let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
        receiver_and_fake_sender().await;
    let entry = pull_test_entry(5, &[b"AAAAA", b"BB"]);

    tokio::spawn(fake_pull_responder(
        fake_sender_endpoint,
        vec![
            // Neither chunk claims to be the last one -- a buggy or
            // malicious sender that never sends a true `last_chunk`.
            (ChunkHeader { chunk_index: 0, size: 5, last_chunk: false }, b"AAAAA".to_vec()),
            (ChunkHeader { chunk_index: 1, size: 2, last_chunk: false }, b"BB".to_vec()),
            // Would blow up `chunk_byte_size` (out of range for a
            // 2-chunk manifest) if `pull_file` ever read this far.
            (
                ChunkHeader { chunk_index: 2, size: 999, last_chunk: true },
                b"should never be read".to_vec(),
            ),
        ],
    ));

    tokio::time::timeout(
        Duration::from_secs(15),
        receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
    )
    .await
    .expect("pull_file must not hang")
    .expect(
        "pull_file must stop cleanly at the manifest's own chunk count, \
         never reading the peer's extra, out-of-range third chunk",
    );

    // Both genuine chunks were still durably received.
    let hashes: Vec<String> = entry.chunk_hashes.iter().map(hex::encode).collect();
    let present = receiver_service.block_store.present_blocks(&hashes).unwrap();
    assert_eq!(present, vec![true, true], "both real chunks must have been stored");
}

// ---- ack-then-immediate-pull ordering --------------------------------

/// A `DeviceDirectory` for the RECEIVING side of the test below only:
/// unlike `TestDirectory` (used everywhere else in this module, which
/// never resolves anything -- see its own doc comment), this one CAN
/// resolve the sender back to a dialable address, because
/// `receive_transfer`'s pull-phase dial-back needs exactly that. Also
/// consumes grants against a real (fake) shared `FakeGrantStore`, like
/// `TestDirectory` does, since the offer this test drives needs one to
/// be accepted at all.
struct ReceiverWithResolvableSender {
    sender: ResolvedDevice,
    grants: Arc<FakeGrantStore>,
}

#[async_trait::async_trait]
impl DeviceDirectory for ReceiverWithResolvableSender {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        (device_query == self.sender.device_id).then(|| self.sender.clone())
    }
    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        (signing_key == &self.sender.signing_key).then(|| self.sender.device_id.clone())
    }
    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        self.grants.consume(grant_id, grant_nonce, peer_key)
    }
}

/// Regression for the ack/pull reordering in `offer_send`:
/// `mark_outbound_acked` now runs BEFORE `connection.close()` (see that
/// call site's own comment) instead of after, so this device's own
/// record of an acceptance lands as early as it possibly can, narrowing
/// -- not eliminating -- the window in which a receiver that already
/// answered `accepted: true` and immediately dials back can hit
/// `handle_pull`'s `Acked` check first.
///
/// Races a real accept against a real, immediate pull attempt with no
/// artificial delay on either side -- the racing task starts polling
/// before `offer_send` has even been called, which is earlier than any
/// real client could react. A transient rejection here is therefore
/// still an expected, self-healing outcome (see `offer_send`'s own
/// comment: this is a narrowed race, not a closed one), so a bounded
/// number of quick retries is allowed -- but the pull must succeed,
/// and quickly, not require the kind of retry-with-backoff a real
/// networked race might.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receiver_can_pull_immediately_after_accepting_the_offer() {
    let sender_endpoint = raw_endpoint().await;
    let receiver_endpoint = raw_endpoint().await;
    receiver_endpoint.admit(sender_endpoint.key);
    sender_endpoint.admit(receiver_endpoint.key);

    let grants = Arc::new(FakeGrantStore::default());
    let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
        sender_key: sender_endpoint.key,
        grants: grants.clone(),
        target: receiver_endpoint.resolved("receiver-device"),
    });
    let (sender_service, _sender_guard) = serving_service(&sender_endpoint, sender_directory);

    let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(ReceiverWithResolvableSender {
        sender: sender_endpoint.resolved("sender-device"),
        grants,
    });
    let (receiver_service, _receiver_guard) =
        serving_service(&receiver_endpoint, receiver_directory);

    let content = b"pulled right after acceptance, no meaningful delay".to_vec();
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("race.txt");
    std::fs::write(&source_path, &content).unwrap();

    let receiver_for_race = receiver_service.clone();
    let racer = tokio::spawn(async move {
        // Polls the receiver's own inbox rather than sleeping -- picks
        // up the offer (and attempts the pull) as early as physically
        // possible on this task, which can be before the sender has
        // even read this receiver's own ack.
        let transfer_id = loop {
            if let Some(entry) = receiver_for_race.list_inbox().unwrap().into_iter().next() {
                break entry.transfer_id;
            }
            tokio::task::yield_now().await;
        };
        for attempt in 0..50 {
            match receiver_for_race.receive_transfer(&transfer_id, None).await {
                Ok(outcome) => return outcome,
                Err(_) if attempt < 49 => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => {
                    panic!("the pull never succeeded after 50 quick retries: {error}")
                }
            }
        }
        unreachable!("loop above always returns or panics")
    });

    sender_service
        .offer_send(&source_path, "receiver-device")
        .await
        .expect("a granted, accepted offer must succeed");

    let outcome = racer.await.expect("the racing pull task must not panic");
    assert_eq!(outcome.bytes_received, content.len() as u64);
    assert_eq!(outcome.files_received, vec!["race.txt".to_string()]);
}
