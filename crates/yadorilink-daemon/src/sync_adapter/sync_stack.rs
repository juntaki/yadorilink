//! Assembling the reconciliation stack from this device's own state.
//!
//! ```text
//!   netmap                         who a peer is, what they may be told,
//!     │                            where to reach them
//!     ▼
//!   SyncStack
//!     ├─ IrohEndpoint              iroh, identified by the device signing key,
//!     │                            bound by PeerConnectivityRuntime; also
//!     │                            answers Track Send, served elsewhere
//!     ├─ SqliteReplicaPort         verification, possession, disclosure
//!     ├─ AdmissionCoordinator      promotion, event-driven
//!     └─ AsyncReplicaStore         bounded threads in front of SQLite
//! ```
//!
//! Nothing here is new policy. The authority resolver is the same
//! `NetmapChangeAuthenticator` the existing receive path uses, so both paths
//! resolve checkpoint signers identically — which is what makes comparing
//! them meaningful rather than a comparison of two policies.

use std::sync::Arc;

use yadorilink_peer_session::peer_session::ChangeAuthenticator;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_protocol::ports::GroupId;
use yadorilink_sync_runtime::{SyncOutcome, SyncRuntime, SyncSummary};
use yadorilink_sync_substrate::{
    HistoryStreamKind, Lane, NetworkConfig, PeerAddress, PeerId, PeerLink,
};

use crate::daemon_state::DaemonState;
use crate::peer_connectivity_runtime::IrohEndpoint;

use super::admission::AdmissionCoordinator;
use super::async_store::{AsyncReplicaStore, StoreLimits};
use super::daemon_directory::DaemonPeerDirectory;
use super::foreign_base::ForeignBaseClaims;
use super::replica_port::SqliteReplicaPort;
use yadorilink_lane_ports::LaneBlockStream;
use yadorilink_lane_ports::LaneServiceStream;
use yadorilink_lane_ports::PreparedSnapshots;

#[derive(Debug, thiserror::Error)]
pub enum SyncStackError {
    #[error("this device has no signing key, so it has no transport identity")]
    NoDeviceIdentity,

    #[error(transparent)]
    Substrate(#[from] yadorilink_sync_substrate::SubstrateError),

    #[error(transparent)]
    Runtime(#[from] yadorilink_sync_runtime::SyncRuntimeError),

    #[error("the netmap carries no address for {0}, so it cannot be dialled")]
    Unreachable(String),
}

/// The reconciliation stack, running.
pub struct SyncStack {
    runtime: Arc<SyncRuntime<SqliteReplicaPort<DaemonPeerDirectory>>>,
    store: AsyncReplicaStore,
    possession: Arc<std::sync::Mutex<Option<super::replica_port::PossessionObserver>>>,
    /// Peers whose last negotiation found them on another history base.
    foreign_bases: Arc<ForeignBaseClaims>,
    /// This device's iroh endpoint: admission, address lookup, the per-peer
    /// link cache and endpoint-id resolution. Bound by the connectivity
    /// runtime and held here so the endpoint lives exactly as long as the
    /// stack that drives it.
    endpoint: IrohEndpoint,
    /// Snapshots this device has signed a manifest against and is willing to
    /// hand over. Owned here because it is per-daemon and per-connection
    /// state, and deliberately not durable.
    prepared: Arc<PreparedSnapshots>,
    admission: Arc<AdmissionCoordinator>,
    state: Arc<DaemonState>,
    serving: yadorilink_sync_runtime::ServeHandle,
}

/// What one `sync_with` call actually did.
///
/// These were previously all `Ok(None)`, which made two very different
/// conditions indistinguishable to the caller: "this node holds no address
/// for that peer, so nothing was attempted and nothing ever will be until
/// the netmap changes" and "a flight for this pair is already in progress".
/// The caller's arm for `Ok(None)` was empty, so a permanently unreachable
/// peer looked exactly like healthy coalescing.
#[derive(Debug)]
pub enum SyncAttempt {
    /// No pinned address/signing key for this peer -- nothing was attempted.
    NoAddress,
    /// A flight for this exact (peer, group) was already running.
    Coalesced,
    /// A reconciliation ran to completion.
    Ran(SyncSummary),
    /// The peer stands on a different history base. Nothing was exchanged
    /// and nothing about this device's base changed; the peer's claim is
    /// recorded in [`SyncStack::foreign_bases`] for a merge to act on.
    MergeRequired,
}

impl SyncAttempt {
    /// The summary of a reconciliation that actually ran, or a panic naming
    /// which of the two non-running outcomes occurred instead. For tests
    /// that require a real reconciliation; the point of this enum is that
    /// those two are no longer interchangeable.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn expect_ran(self, message: &str) -> SyncSummary {
        match self {
            SyncAttempt::Ran(summary) => summary,
            SyncAttempt::Coalesced => {
                panic!("{message}: coalesced into a flight already running for this pair")
            }
            SyncAttempt::NoAddress => {
                panic!("{message}: no address for this peer, so nothing was attempted")
            }
            SyncAttempt::MergeRequired => {
                panic!("{message}: the peer stands on a different history base")
            }
        }
    }
}

impl SyncStack {
    /// Start the stack for `state`.
    ///
    /// The endpoint identity is this device's signing key, so the netmap
    /// already publishes the binding peers need to recognise it — see
    /// `SubstrateNode::spawn_as_device`.
    pub async fn spawn(
        state: Arc<DaemonState>,
        authenticator: Arc<dyn ChangeAuthenticator>,
        config: NetworkConfig,
    ) -> Result<Self, SyncStackError> {
        let signing_key = state.device_signing_key().ok_or(SyncStackError::NoDeviceIdentity)?;

        // The iroh endpoint, its admission policy and its address lookup are
        // the connectivity runtime's; this stack only drives reconciliation
        // over it.
        let (endpoint, inbound) = state
            .peer_connectivity
            .bind_endpoint(
                signing_key.to_bytes(),
                &state.authority,
                crate::send_transfer::track_send_admission(&state),
                config,
            )
            .await?;

        let store =
            AsyncReplicaStore::new(state.replica_coordinator.database(), StoreLimits::default());
        let metrics_store = store.clone();
        // What promotion has to wake. These are the same three the legacy
        // admission path raised the moment it admitted a batch; each has its
        // own periodic backstop, so their absence would not break
        // convergence, only delay it by that backstop's interval.
        //
        // Weak, because the driver that owns this stack is itself owned by
        // `DaemonState`.
        let waiting = Arc::downgrade(&state);
        let admission = Arc::new(AdmissionCoordinator::new(store.clone()).notifying(Arc::new(
            move |group: &FolderGroupId| {
                let Some(state) = waiting.upgrade() else {
                    return;
                };
                state.replica_coordinator.notify_materialization_wake();
                state.replica_coordinator.notify_retirement_wake(&group.0);
                state.replica_coordinator.notify_hazard_recheck_wake(&group.0);
            },
        )));

        let port = SqliteReplicaPort::new(
            store,
            Arc::new(DaemonPeerDirectory::new(state.clone())),
            Arc::new(move |group: &str, key_id: &[u8; 32], policy_head: &[u8; 32]| {
                authenticator.resolve_authority_key(group, key_id, policy_head)
            }),
        )
        .waking(admission.clone());
        let possession = port.possession_slot();
        let foreign_bases = port.foreign_bases();

        let runtime = Arc::new(SyncRuntime::new(endpoint.node(), Arc::new(port)));
        let serving = runtime.serve(inbound);

        Ok(Self {
            runtime,
            store: metrics_store,
            possession,
            foreign_bases,
            endpoint,
            prepared: Arc::new(PreparedSnapshots::new()),
            admission,
            state,
            serving,
        })
    }

    /// This device's transport identity, which is also its signing key's
    /// public half — what a peer's netmap already pins for it.
    pub fn peer_id(&self) -> PeerId {
        self.endpoint.peer_id()
    }

    /// The address a peer's netmap should record for this device.
    pub fn local_address(&self) -> PeerAddress {
        self.endpoint.local_address()
    }

    /// This device's address, updated as the substrate learns more of it.
    ///
    /// What the endpoint report publishes has to follow this rather than
    /// sample it: the home relay is assigned after the endpoint binds, so a
    /// report built at startup would advertise no relay at all — and to a peer
    /// that cannot reach this device directly, that is indistinguishable from
    /// this device not existing.
    pub fn watch_local_address(&self) -> tokio::sync::watch::Receiver<PeerAddress> {
        self.endpoint.watch_local_address()
    }

    /// This stack's iroh endpoint, for the connectivity runtime's projection
    /// of recorded peer reachability into its address directory.
    pub(crate) fn endpoint(&self) -> &IrohEndpoint {
        &self.endpoint
    }

    /// How hard this device's storage boundary has been pushed -- chiefly
    /// the high-water mark of concurrent blocking calls, which is what says
    /// whether the permit bounds are doing anything.
    pub fn store_metrics(&self) -> super::async_store::StoreMetrics {
        self.store.metrics()
    }

    /// Peers whose last negotiation found them on another history base --
    /// the merge-required state. Claims only; see
    /// [`ForeignBaseClaims`] for what they may and may not be used for.
    pub fn foreign_bases(&self) -> &Arc<ForeignBaseClaims> {
        &self.foreign_bases
    }

    /// Promote whatever is promotable in `group`, to a fixed point.
    pub fn admission(&self) -> &Arc<AdmissionCoordinator> {
        &self.admission
    }

    /// Where to reach `device_id`, from the netmap.
    ///
    /// `None` when the netmap has not pinned that device's signing key.
    ///
    /// An endpoint id IS the device's signing key, so this is the whole of the
    /// identity resolution: with no pinned key there is nothing to dial, and
    /// dialling something this device cannot name is not a thing to attempt.
    ///
    /// Deliberately no addresses. Where that endpoint currently answers is the
    /// address lookup's question -- see `yadorilink_sync_substrate::directory`
    /// for why feeding the netmap's candidate list to the substrate could not
    /// work: that list is also the legacy peer-session transport's, the two
    /// speak different protocols on different sockets, and neither consumer
    /// can tell which entry is meant for it.
    pub fn peer_id_of(&self, device_id: &str) -> Option<PeerId> {
        self.endpoint.peer_id_of(device_id)
    }

    /// Reconcile with one peer for one group, then fetch what is missing.
    ///
    /// `None` means the call was coalesced into a reconciliation already
    /// running for this peer and group.
    pub async fn sync_with(
        &self,
        device_id: &str,
        group: &FolderGroupId,
    ) -> Result<SyncAttempt, SyncStackError> {
        let Some(peer) = self.peer_id_of(device_id) else {
            return Ok(SyncAttempt::NoAddress);
        };
        Ok(match self.runtime.sync_with(peer, &GroupId(group.0.clone())).await? {
            Some(SyncOutcome::Synced(summary)) => SyncAttempt::Ran(summary),
            Some(SyncOutcome::MergeRequired) => SyncAttempt::MergeRequired,
            None => SyncAttempt::Coalesced,
        })
    }

    /// Route inbound block, service and snapshot streams to the session that
    /// owns that peer.
    ///
    /// The peer is resolved from its endpoint identity through the netmap on
    /// every stream, never from anything remembered when the connection
    /// opened: a device unpinned since then resolves to nothing and is served
    /// nothing.
    pub fn serve_peer_lanes(self: &Arc<Self>) {
        let prepared = self.prepared.clone();
        let stack = Arc::downgrade(self);
        let for_history = stack.clone();
        let prepared_for_history = prepared.clone();

        self.runtime.when_lane_stream(Arc::new(move |peer, group, lane, stream| {
            let stack = stack.clone();
            Box::pin(async move {
                let Some(stack) = stack.upgrade() else { return };
                let Some(session) = stack.session_for(&peer) else {
                    tracing::debug!(?lane, "no session for this peer; closing the stream");
                    return;
                };
                match lane {
                    Lane::Block => {
                        session.serve_block_stream(Box::new(LaneBlockStream::new(stream))).await
                    }
                    Lane::Service => {
                        session
                            .serve_service_stream(
                                group.as_str(),
                                Box::new(LaneServiceStream::new(stream)),
                            )
                            .await
                    }
                    _ => {}
                }
            })
        }));

        self.runtime.when_history_stream(Arc::new(move |peer, group, kind, stream| {
            let stack = for_history.clone();
            let prepared = prepared_for_history.clone();
            Box::pin(async move {
                let Some(stack) = stack.upgrade() else { return };
                if kind != HistoryStreamKind::RebootstrapSnapshot {
                    return;
                }
                yadorilink_lane_ports::serve_snapshot_stream(
                    stream,
                    peer.as_bytes(),
                    group.as_str(),
                    &DaemonPeerDirectory::new(stack.state.clone()),
                    prepared.as_ref(),
                )
                .await;
            })
        }));
    }

    /// The substrate transports for a session reaching `peer_device_id`.
    ///
    /// From here that session's blocks, service RPCs and snapshots ride the
    /// substrate's lanes, and nothing below it knows: the ports were always
    /// the seam. Resolved BEFORE a session is constructed now, not attached
    /// after -- `SessionTransports` is a required constructor parameter (see
    /// its own doc comment), so there is no longer a window in which a
    /// session exists but cannot yet reach its peer, and therefore nothing
    /// left to serialize a backfill against.
    pub fn transports_for(
        self: &Arc<Self>,
        peer_device_id: &str,
    ) -> yadorilink_peer_session::ports::SessionTransports {
        let transports =
            Arc::new(yadorilink_lane_ports::PeerTransports::new(Arc::new(StackLink {
                stack: self.clone(),
                device_id: peer_device_id.to_string(),
            })));
        yadorilink_peer_session::ports::SessionTransports {
            blocks: transports.clone(),
            service: transports.clone(),
            prepared_snapshots: self.prepared.clone(),
            snapshot_fetch: transports,
        }
    }

    /// The live session for this endpoint identity, if the netmap still
    /// attributes it to a device this daemon has one for.
    fn session_for(
        &self,
        peer: &PeerId,
    ) -> Option<Arc<yadorilink_peer_session::peer_session::PeerSyncSession>> {
        let device = self.state.authority.device_id_for_signing_key(peer.as_bytes())?;
        self.state.peers.session(&device)
    }

    /// Say what to do when a peer's reconciliation reveals that *this*
    /// device is the one that is behind -- see
    /// `SyncRuntime::when_behind`.
    pub fn when_behind(&self, hook: yadorilink_sync_runtime::BehindHook) {
        self.runtime.when_behind(hook);
    }

    /// Say who sees each link a reconciliation dials, before it carries
    /// anything. The only way to witness the path a real transfer took --
    /// see `yadorilink_sync_runtime::DialedLinkHook`.
    pub fn when_link_dialed(&self, hook: yadorilink_sync_runtime::DialedLinkHook) {
        self.runtime.when_link_dialed(hook);
    }

    /// Say who sees each link this stack accepts. The other half of
    /// [`Self::when_link_dialed`] -- see
    /// `yadorilink_sync_runtime::AcceptedLinkHook`.
    pub fn when_link_accepted(&self, hook: yadorilink_sync_runtime::AcceptedLinkHook) {
        self.runtime.when_link_accepted(hook);
    }

    /// Say who sees every connect attempt against a peer, whether or not it
    /// succeeds. See `yadorilink_sync_runtime::DialAttemptHook`.
    pub fn when_dial_attempted(&self, hook: yadorilink_sync_runtime::DialAttemptHook) {
        self.runtime.when_dial_attempted(hook);
    }

    /// Test-only: shortens THIS stack's own reconciliation connect deadline,
    /// so a test with a genuinely unreachable peer does not have to wait out
    /// the full production budget. Per-instance -- see
    /// `yadorilink_sync_runtime::SyncRuntime::set_connect_deadline_for_tests`
    /// for why this is not a process-wide override.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_connect_deadline_for_tests(&self, deadline: std::time::Duration) {
        self.runtime.set_connect_deadline_for_tests(deadline);
    }

    /// Say what to do when this device's possession of a group grows.
    pub fn when_possession_grows(&self, observer: super::replica_port::PossessionObserver) {
        *self.possession.lock().expect("possession observer poisoned") = Some(observer);
    }

    /// Stop serving and close the substrate endpoint.
    ///
    /// A peer learns that this device has gone away from the connection
    /// closing, and from nothing else. Leave the endpoint open and the peer
    /// keeps a connection to a socket nobody answers on any more -- and since
    /// iroh sends every datagram for a remote down that connection's selected
    /// path, including the handshake of a BRAND NEW dial, the peer cannot
    /// reach this device again until that dead connection reaches its own
    /// idle timeout.
    ///
    /// Deliberately not `Drop`: closing is asynchronous, and it has to happen
    /// while the runtime the endpoint's tasks live on is still running.
    pub async fn shutdown(&self) {
        self.serving.abort();
        self.endpoint.shutdown().await;
    }

    /// The connection to `device_id`, dialled if there is not a live one.
    ///
    /// Dialled through this stack's runtime, so the dial is seen by the same
    /// observers as a reconciliation's own; cached by the endpoint.
    pub async fn link_to(&self, device_id: &str) -> Result<Arc<PeerLink>, SyncStackError> {
        self.endpoint
            .link_to(device_id, |peer| async move {
                self.runtime.connect(peer).await.map_err(SyncStackError::from)
            })
            .await?
            .ok_or_else(|| SyncStackError::Unreachable(device_id.to_string()))
    }

    /// Test-only: teach two stacks where the other's substrate answers.
    ///
    /// Production gets this from the coordination plane. Every test fixture
    /// used to do it with `record_peer_candidate_addresses`, which is the
    /// LEGACY peer-session transport's list and no longer reaches
    /// reconciliation -- the two transports listen on different sockets with
    /// different ALPNs, and one list could not serve both. This exists so the
    /// correct wiring has a single name: patching each call site individually
    /// is how the same coupling reappeared in three separate fixtures.
    #[cfg(any(test, feature = "test-support"))]
    pub fn teach_each_other_for_tests(a: &Self, b: &Self) {
        for (from, to) in [(a, b), (b, a)] {
            let address = from.local_address();
            to.address_directory().record(
                address.peer(),
                address.direct_addrs().copied().collect(),
                address.relay_urls().map(ToString::to_string).collect(),
            );
        }
    }

    /// Where this device publishes and resolves substrate endpoint addresses.
    ///
    /// Exposed so the netmap-push path can record a peer's substrate address
    /// as the plane reports it. Deliberately NOT fed from
    /// `peer_candidate_addresses`: that is the legacy transport's list, and
    /// mixing the two is what made both unreachable.
    pub fn address_directory(
        &self,
    ) -> &Arc<super::address_directory::CoordinationAddressDirectory> {
        self.endpoint.address_directory()
    }

    /// The device this endpoint identity belongs to, per the netmap.
    pub fn device_for_peer(&self, peer: &PeerId) -> Option<String> {
        self.endpoint.device_for_peer(peer)
    }

    /// Note that local possession of `group` changed, so connected peers are
    /// worth reconciling with again.
    pub fn note_local_change(&self, peer: PeerId, group: &FolderGroupId) {
        self.runtime.note_local_change(peer, &GroupId(group.0.clone()));
    }
}

impl Drop for SyncStack {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// One peer's connection, resolved through the netmap and this stack's link
/// cache.
///
/// The production answer to [`PeerLinkSource`]: which device, and where the
/// netmap currently says it is. A test dialling a peer it already has an
/// address for answers the same question differently and gets the same
/// transports — that is the point of the trait.
struct StackLink {
    stack: Arc<SyncStack>,
    device_id: String,
}

#[async_trait::async_trait]
impl yadorilink_lane_ports::PeerLinkSource for StackLink {
    async fn link(
        &self,
    ) -> Result<Arc<yadorilink_sync_substrate::PeerLink>, yadorilink_transport::TransportError>
    {
        self.stack
            .link_to(&self.device_id)
            .await
            .map_err(|error| yadorilink_transport::TransportError::NoRoute(error.to_string()))
    }
}
