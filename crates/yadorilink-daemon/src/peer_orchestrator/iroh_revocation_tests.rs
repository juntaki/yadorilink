//! What a whole-device revocation must do to iroh connections that are
//! already up.
//!
//! Admission is checked when a connection is accepted, and nowhere after.
//! Withdrawing a device's signing key therefore refuses its NEXT connection
//! and, by itself, says nothing to the one it already has. Two things hold
//! the line for the connection that is already up. What each lane serves is
//! authorized again per stream, from the live netmap, so a revoked device is
//! told nothing on reconciliation, block or service streams. And revocation
//! closes the connection itself -- the one the device dialled, the one this
//! device dialled and cached, and every one it accepted -- so no stream opens
//! on it and the link cache never hands it out again. Without the second, a
//! stream served without re-authorization would be reachable by any device
//! that happened to be connected at the moment of revocation.
//!
//! Each test below starts from the same state -- two authorized devices, an
//! open iroh connection in each direction, one reconciliation already run
//! over the stack -- revokes the peer through `teardown_peer`, the
//! production whole-device path a netmap without that device takes, and then
//! asks one question about what is still possible. Every question has a
//! precondition proving it was possible before the revocation, so a test
//! that passes is not passing because the setup never worked.
//!
//! Only the reconciliation stack is used: `SyncStack` over iroh, with the
//! lanes served by `serve_peer_lanes`, dispatching to a session built over
//! that stack's transports; nothing here dials the legacy QUIC transport.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_protocol::ports::{GroupId, PeerKey, PortError, ReplicaPort};
use yadorilink_sync_protocol::{OpaqueBundle, Reconciled, Role, SessionConfig};
use yadorilink_sync_substrate::{AddressDirectory as _, Lane, NetworkConfig, PeerId, PeerLink};

use super::{peer_sync_session_deps, teardown_peer};
use crate::daemon_state::DaemonState;
use crate::sync_adapter::sync_stack::{SyncAttempt, SyncStack};
use crate::test_support::sync_stack_fixture::{
    change_touching, device, honest_bundle, init_staging_schema, pin, stage, FixtureAuthenticator,
    GROUP,
};

/// How long any single network step may take before it counts as "no answer".
const STEP: Duration = Duration::from_secs(10);

/// How long a revocation gets to reach a connection that is already up.
///
/// Closing a QUIC connection takes one packet to the far side; seconds is
/// generous. Waiting at all is what keeps these tests from demanding that a
/// close be synchronous, which it cannot be.
const REVOCATION_REACHES_THE_CONNECTION: Duration = Duration::from_secs(5);

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";

/// Two authorized devices with live iroh connections in both directions.
///
/// Alice is the device that revokes; Bob is the device being revoked. What
/// Bob can still do is asked from Bob's side, because a revoked device is by
/// definition not one whose own code can be trusted to stop.
struct Established {
    alice: Arc<DaemonState>,
    alice_stack: Arc<SyncStack>,
    bob_stack: Arc<SyncStack>,
    /// Bob's cached connection to Alice: dialled by Bob, accepted by Alice.
    bob_link: Arc<PeerLink>,
    /// Alice's cached connection to Bob: dialled by Alice.
    alice_link: Arc<PeerLink>,
    /// Every connection Alice's endpoint accepted, as Alice holds it.
    accepted_by_alice: Arc<Mutex<Vec<PeerLink>>>,
    next_seq: i64,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    _bob: Arc<DaemonState>,
}

impl Established {
    async fn new() -> Self {
        let group = FolderGroupId(GROUP.into());
        let (alice, alice_dir) = device(ALICE, 11);
        let (bob, bob_dir) = device(BOB, 22);
        for state in [&alice, &bob] {
            init_staging_schema(state);
        }
        pin(&alice, BOB, 22);
        pin(&bob, ALICE, 11);

        let alice_stack = Arc::new(
            SyncStack::spawn(
                alice.clone(),
                Arc::new(FixtureAuthenticator),
                NetworkConfig::direct_only(),
            )
            .await
            .expect("alice's stack starts"),
        );
        let bob_stack = Arc::new(
            SyncStack::spawn(
                bob.clone(),
                Arc::new(FixtureAuthenticator),
                NetworkConfig::direct_only(),
            )
            .await
            .expect("bob's stack starts"),
        );

        let accepted_by_alice = Arc::new(Mutex::new(Vec::new()));
        {
            let accepted = accepted_by_alice.clone();
            alice_stack.when_link_accepted(Arc::new(move |link: &PeerLink| {
                accepted.lock().unwrap().push(link.clone());
            }));
        }
        SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
        alice_stack.serve_peer_lanes();
        bob_stack.serve_peer_lanes();
        register_session_for_peer(&alice, &alice_stack, BOB);

        // One reconciliation over the stack, so the pair is past first
        // contact rather than merely able to reach each other.
        let first = change_touching(&["before-revocation.txt"]);
        stage(&alice, honest_bundle(first), 1);
        let summary = tokio::time::timeout(STEP, bob_stack.sync_with(ALICE, &group))
            .await
            .expect("the first reconciliation must not hang")
            .expect("the first reconciliation must succeed")
            .expect_ran("the first reconciliation ran");
        assert_eq!(summary.staged, 1, "setup: the first reconciliation must carry the Change");

        let bob_link = tokio::time::timeout(STEP, bob_stack.link_to(ALICE))
            .await
            .expect("bob's dial must not hang")
            .expect("bob reaches alice");
        let alice_link = tokio::time::timeout(STEP, alice_stack.link_to(BOB))
            .await
            .expect("alice's dial must not hang")
            .expect("alice reaches bob");

        let this = Self {
            alice,
            alice_stack,
            bob_stack,
            bob_link,
            alice_link,
            accepted_by_alice,
            next_seq: 2,
            _dirs: (alice_dir, bob_dir),
            _bob: bob,
        };
        assert!(
            eventually(STEP, || !this.live_links_alice_accepted_from_bob().is_empty()).await,
            "setup: alice must hold the connection bob dialled"
        );
        this
    }

    fn bob_peer(&self) -> PeerId {
        self.bob_stack.peer_id()
    }

    /// The connections Alice accepted from Bob that are still open.
    fn live_links_alice_accepted_from_bob(&self) -> Vec<PeerLink> {
        let bob = self.bob_peer();
        self.accepted_by_alice
            .lock()
            .unwrap()
            .iter()
            .filter(|link| link.peer() == bob && link.is_alive())
            .cloned()
            .collect()
    }

    /// Whole-device revocation of Bob on Alice, as a netmap that no longer
    /// lists Bob applies it.
    fn revoke_bob(&self) {
        teardown_peer(&self.alice, BOB);
        assert!(
            self.alice.authority.peer_signing_key(BOB).is_none(),
            "setup: revocation must withdraw the key, or nothing below means anything"
        );
    }

    /// A Change Alice comes to hold after the revocation.
    fn alice_learns_something_new(&mut self, path: &str) {
        stage(&self.alice, honest_bundle(change_touching(&[path])), self.next_seq);
        self.next_seq += 1;
    }
}

/// The session Alice keeps for a peer, as the orchestrator builds one, so the
/// block and service lanes `serve_peer_lanes` dispatches have somewhere to
/// go.
fn register_session_for_peer(state: &Arc<DaemonState>, stack: &Arc<SyncStack>, peer: &str) {
    let store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let session = yadorilink_peer_session::peer_session::PeerSyncSession::over_substrate(
        state.device_id.clone(),
        peer.to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        crate::replica_coordinator::engine_ports::build_peer_replica_engine(
            &state.replica_coordinator,
            store.clone(),
        ),
        store,
        vec![GROUP.to_string()],
        std::collections::HashMap::new(),
        stack.transports_for(peer),
        None,
        peer_sync_session_deps(state),
    );
    state.peers.register_session(peer.to_string(), session, state.local_convergence());
}

/// A replica that holds nothing and will talk to anyone: the far end of a
/// reconciliation whose only question is what the other side still tells it.
struct HoldsNothing;

impl ReplicaPort for HoldsNothing {
    async fn may_disclose(&self, _peer: PeerKey, _group: GroupId) -> Result<bool, PortError> {
        Ok(true)
    }

    /// On the group's original history, as every device in this test is.
    async fn base_advertisement(
        &self,
        _peer: PeerKey,
        group: GroupId,
    ) -> Result<Vec<u8>, PortError> {
        use yadorilink_replica_domain::base_negotiation::{AdvertisedBase, BaseAdvertisement};
        use yadorilink_replica_domain::ids::FolderGroupId;
        BaseAdvertisement::new(FolderGroupId(group.0), AdvertisedBase::Genesis, Vec::new())
            .map(|advertisement| advertisement.encode())
            .map_err(PortError::new)
    }

    async fn negotiate_base(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        _ours: Vec<u8>,
        _theirs: Vec<u8>,
    ) -> Result<yadorilink_sync_protocol::BaseVerdict, PortError> {
        Ok(yadorilink_sync_protocol::BaseVerdict::SameBase)
    }

    async fn servable(
        &self,
        _peer: PeerKey,
        _group: GroupId,
    ) -> Result<Vec<yadorilink_rbsr::ItemId>, PortError> {
        Ok(Vec::new())
    }

    async fn load_bundles(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        _hashes: Vec<yadorilink_rbsr::ItemId>,
    ) -> Result<Vec<OpaqueBundle>, PortError> {
        Ok(Vec::new())
    }

    async fn stage_bundles(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        _bundles: Vec<OpaqueBundle>,
    ) -> Result<Vec<yadorilink_rbsr::ItemId>, PortError> {
        Ok(Vec::new())
    }
}

/// Reconcile over `link` itself rather than a fresh dial, as the far end
/// that holds nothing: whatever comes back as `want` is what the other side
/// still disclosed over that connection.
async fn reconcile_over(link: &PeerLink) -> Result<Reconciled, String> {
    let group = GroupId(GROUP.into());
    let run = async {
        let mut lane = link.open_lane(Lane::Reconciliation).await.map_err(|e| e.to_string())?;
        yadorilink_sync_protocol::session::open_lane(&mut lane, &group)
            .await
            .map_err(|e| e.to_string())?;
        yadorilink_sync_protocol::reconcile(
            &mut lane,
            &HoldsNothing,
            PeerKey(*link.peer().as_bytes()),
            &group,
            Role::Initiator,
            &SessionConfig::default(),
        )
        .await
        .map_err(|e| e.to_string())
        .and_then(|outcome| match outcome {
            yadorilink_sync_protocol::ReconcileOutcome::Reconciled(reconciled) => Ok(reconciled),
            yadorilink_sync_protocol::ReconcileOutcome::MergeRequired => {
                Err("the far end stands on a different history base".to_string())
            }
        })
    };
    tokio::time::timeout(STEP, run).await.map_err(|_| "timed out".to_string())?
}

/// Ask for a block over `link`. `Some` is the response header: the far end
/// answered, whatever it said.
async fn block_answer_over(link: &PeerLink) -> Option<Vec<u8>> {
    use yadorilink_peer_session::ports::PeerBlockStream as _;
    let run = async {
        let mut lane = link.open_lane_for(Lane::Block, GROUP).await.ok()?;
        yadorilink_sync_protocol::session::open_lane(&mut lane, &GroupId(GROUP.into()))
            .await
            .ok()?;
        let mut stream = yadorilink_lane_ports::LaneBlockStream::new(lane);
        let header = yadorilink_sync_wire::ProtobufPeerWireCodec
            .encode_block_request_header(yadorilink_sync_wire::BlockRequestHeaderFrame {
                folder_group_id: GROUP.to_string(),
                file_path: "before-revocation.txt".to_string(),
                block_hash: vec![0x42; 32],
            })
            .ok()?;
        stream.send_message(&header).await.ok()?;
        stream.finish_send();
        stream.recv_message(yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES).await.ok()
    };
    tokio::time::timeout(STEP, run).await.ok().flatten()
}

/// Make one service RPC over `link`. `Some` is the decoded response: the far
/// end answered, whatever it said.
async fn service_answer_over(
    link: &PeerLink,
) -> Option<yadorilink_peer_session::service_rpc::ServiceResponse> {
    use yadorilink_peer_session::ports::PeerServiceStream as _;
    use yadorilink_peer_session::service_rpc::{decode_response, encode_request, ServiceRequest};
    let run = async {
        let mut lane = link.open_lane_for(Lane::Service, GROUP).await.ok()?;
        yadorilink_sync_protocol::session::open_lane(&mut lane, &GroupId(GROUP.into()))
            .await
            .ok()?;
        let mut stream = yadorilink_lane_ports::LaneServiceStream::new(lane);
        stream
            .send_request(&encode_request(&ServiceRequest::GroupDurabilitySummary {
                group_id: GROUP.to_string(),
            }))
            .await
            .ok()?;
        let bytes =
            stream.recv_message(yadorilink_lane_ports::MAX_SERVICE_MESSAGE_BYTES).await.ok()?;
        decode_response(&bytes).ok()
    };
    tokio::time::timeout(STEP, run).await.ok().flatten()
}

/// Polls `condition` until it holds or `within` passes. Revocation reaching
/// a connection is asynchronous by nature; this is the bounded wait for it,
/// not a sleep standing in for an event.
async fn eventually(within: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if condition() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A revoked device learns nothing further through reconciliation: not by
/// dialling again, not by being dialled, and not over the connection it
/// already had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_device_can_no_longer_reconcile() {
    let mut pair = Established::new().await;
    let group = FolderGroupId(GROUP.into());

    let before =
        reconcile_over(&pair.bob_link).await.expect("setup: the live connection reconciles");
    assert_eq!(before.want.len(), 1, "setup: over the live connection bob learns alice's Change");

    pair.revoke_bob();
    pair.alice_learns_something_new("after-revocation.txt");

    // Alice no longer names Bob, so she has nobody to dial.
    let from_alice = pair.alice_stack.sync_with(BOB, &group).await;
    assert!(
        matches!(from_alice, Ok(SyncAttempt::NoAddress)),
        "alice must not reconcile with a device she revoked, got {from_alice:?}"
    );

    // A fresh dial from Bob is refused at admission.
    let fresh = tokio::time::timeout(STEP, pair.bob_stack.sync_with(ALICE, &group))
        .await
        .expect("a refused dial must not hang");
    assert!(
        !matches!(&fresh, Ok(SyncAttempt::Ran(summary)) if summary.wanted > 0),
        "a revoked device must learn nothing over a new connection, got {fresh:?}"
    );

    // And over the connection Bob already had, Alice discloses nothing.
    let over_old = reconcile_over(&pair.bob_link).await;
    assert!(
        over_old.as_ref().map_or(true, |reconciled| reconciled.want.is_empty()),
        "a revoked device must learn nothing over the connection it already had, got {:?}",
        over_old.map(|reconciled| reconciled.want.len())
    );
}

/// A revoked device is sent no block, over the connection it already had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_device_can_no_longer_fetch_a_block() {
    let pair = Established::new().await;

    assert!(
        block_answer_over(&pair.bob_link).await.is_some(),
        "setup: before revocation alice answers bob's block requests"
    );

    pair.revoke_bob();

    let answer = block_answer_over(&pair.bob_link).await;
    assert!(
        answer.is_none(),
        "a revoked device must get no answer on the block lane, got a {}-byte response header",
        answer.map_or(0, |header| header.len())
    );
}

/// A revoked device is answered no service RPC, over the connection it
/// already had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_device_can_no_longer_use_the_service_lane() {
    let pair = Established::new().await;

    assert!(
        service_answer_over(&pair.bob_link).await.is_some(),
        "setup: before revocation alice answers bob's service requests"
    );

    pair.revoke_bob();

    let answer = service_answer_over(&pair.bob_link).await;
    assert!(
        answer.is_none(),
        "a revoked device must get no answer on the service lane, got {answer:?}"
    );
}

/// Neither side can open another stream on a connection between a device and
/// the device it revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_new_stream_opens_on_a_connection_to_a_revoked_device() {
    let pair = Established::new().await;

    pair.revoke_bob();
    eventually(REVOCATION_REACHES_THE_CONNECTION, || {
        !pair.bob_link.is_alive() && !pair.alice_link.is_alive()
    })
    .await;

    let from_bob = pair.bob_link.open_lane(Lane::Service).await;
    assert!(
        from_bob.is_err(),
        "the revoked device must not open a stream on the connection it dialled before revocation"
    );
    let from_alice = pair.alice_link.open_lane(Lane::Service).await;
    assert!(
        from_alice.is_err(),
        "the revoking device must not open a stream on its connection to the revoked device"
    );
}

/// The link cache does not hand out a connection to a revoked device, and
/// the connection it cached is closed rather than merely forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_link_cache_does_not_reuse_a_connection_to_a_revoked_device() {
    let pair = Established::new().await;

    pair.revoke_bob();

    let reused = pair.alice_stack.link_to(BOB).await;
    assert!(
        reused.is_err(),
        "the link cache handed out a connection to a revoked device: {:?}",
        reused.map(|link| link.peer())
    );
    assert!(
        eventually(REVOCATION_REACHES_THE_CONNECTION, || !pair.alice_link.is_alive()).await,
        "the cached connection to a revoked device must be closed, not left open"
    );
}

/// A connection the revoked device had already had accepted is closed.
/// Admission only ever ran on it once, at accept time; revocation is the
/// only thing left that can end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_the_revoked_device_already_had_accepted_is_closed() {
    let pair = Established::new().await;

    pair.revoke_bob();

    assert!(
        eventually(REVOCATION_REACHES_THE_CONNECTION, || pair
            .live_links_alice_accepted_from_bob()
            .is_empty())
        .await,
        "alice still holds {} open connection(s) she accepted from the device she revoked",
        pair.live_links_alice_accepted_from_bob().len()
    );
    assert!(
        eventually(REVOCATION_REACHES_THE_CONNECTION, || !pair.bob_link.is_alive()).await,
        "the revoked device still sees its connection to alice as open"
    );
}

/// Nothing this device knows still says where a revoked device answers: not
/// the reachability the plane reported, not the endpoint directory, and not
/// a local-network announcement, which is resolved only for a device that is
/// still authorized.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_device_has_no_usable_address_left() {
    let pair = Established::new().await;
    let bob = pair.bob_peer();
    pair.alice.record_peer_substrate_reachability(
        BOB,
        Some(crate::coordination_client::SubstrateReachability {
            direct: vec!["192.0.2.7:4433".parse().expect("a socket address")],
            relays: Vec::new(),
        }),
    );
    assert!(
        pair.alice.peer_connectivity.substrate_reachability(BOB).is_some(),
        "setup: alice records the reachability the plane reported for bob"
    );
    assert!(
        pair.alice_stack.address_directory().resolve(bob).is_some(),
        "setup: alice's directory knows where bob answers"
    );
    assert!(
        pair.alice.authority.is_authorized_lan_peer(bob.as_bytes()),
        "setup: bob is a device alice would look up on the LAN"
    );

    pair.revoke_bob();

    assert!(
        pair.alice.peer_connectivity.substrate_reachability(BOB).is_none(),
        "the reachability reported for a revoked device must be forgotten"
    );
    assert!(
        pair.alice_stack.address_directory().resolve(bob).is_none(),
        "the directory must not name an address for a revoked device"
    );
    assert!(
        !pair.alice.authority.is_authorized_lan_peer(bob.as_bytes()),
        "a revoked device must not be resolved from a LAN announcement"
    );
}
