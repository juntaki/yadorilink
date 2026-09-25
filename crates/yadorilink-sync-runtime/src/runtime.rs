//! Driving reconciliation sessions over the substrate.

use std::sync::Arc;

use tokio::task::JoinHandle;
use yadorilink_sync_protocol::ports::{GroupId, PeerKey, ReplicaPort};
use yadorilink_sync_protocol::session::{
    accept_lane, open_lane, reconcile, request_bundles, serve_bundles, ReconcileOutcome, Role,
    SessionConfig,
};
use yadorilink_sync_protocol::single_flight::{Flight, SingleFlight};
use yadorilink_sync_substrate::{
    HistoryStreamKind, Lane, LaneStream, PeerAddress, PeerId, PeerLink, SubstrateError,
    SubstrateNode,
};

/// The task [`SyncRuntime::serve`] returns.
///
/// Named here so a caller can hold it without naming `tokio` itself.
pub type ServeHandle = JoinHandle<()>;

#[derive(Debug, thiserror::Error)]
pub enum SyncRuntimeError {
    #[error(transparent)]
    Substrate(#[from] SubstrateError),

    #[error("history stream io: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Protocol(#[from] yadorilink_sync_protocol::ProtocolError),

    /// A network-facing step of one reconciliation did not finish inside its
    /// deadline. The attempt ends; the pair is re-driven by the ordinary
    /// wake/backstop path.
    #[error("reconciliation timed out in {stage} after {seconds}s")]
    NetworkTimeout { stage: &'static str, seconds: u64 },
}

/// Deadlines for the NETWORK-facing steps of one reconciliation.
///
/// These exist to bound how long a single flight can hold its
/// `SingleFlight<(PeerId, GroupId)>` key, not to make the protocol faster.
/// The key is released only when `sync_once` returns, so a step that never
/// returns silently disables that pair forever: every later attempt --
/// including the responder-side "you are behind" rescue, which deliberately
/// uses the same single-flighted path -- coalesces into `Ok(None)` and is
/// dropped. Confirmed in the field: three flights observed stuck in
/// `connect` for 94s and still stuck at 207s, while their devices sat at a
/// divergent frontier.
///
/// Only network steps are bounded. Local verification and SQLite staging
/// are deliberately NOT, because this repository has measured legitimate
/// writer-gate waits of tens of seconds and aborting real local work would
/// trade a stall for corruption of a different kind.
///
/// Generous on purpose: exceeding one of these means the step is not going
/// to finish, not that it is slow. Ending the attempt costs one re-dial,
/// which the pump already does on its own cadence.
const CONNECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const LANE_OPEN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const RECONCILE_EXCHANGE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Applies one network deadline, turning expiry into a real error so it
/// unwinds through `SingleFlight`'s `ReleaseOnDrop` and frees the key.
async fn with_deadline<T, E>(
    stage: &'static str,
    deadline: std::time::Duration,
    work: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, SyncRuntimeError>
where
    SyncRuntimeError: From<E>,
{
    match tokio::time::timeout(deadline, work).await {
        Ok(result) => result.map_err(SyncRuntimeError::from),
        Err(_) => Err(SyncRuntimeError::NetworkTimeout { stage, seconds: deadline.as_secs() }),
    }
}

/// What one sync with one peer achieved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncSummary {
    /// Identifiers the peer held that this node did not, at reconciliation
    /// time.
    pub wanted: usize,
    /// Identifiers newly staged as a result.
    pub staged: usize,
    /// Reconciliation rounds exchanged.
    pub rounds: usize,
}

/// How one sync with one peer ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Both sides stand on the same history base; change sets were
    /// compared and whatever was missing was fetched.
    Synced(SyncSummary),
    /// The peer stands on a different history base. Nothing was compared
    /// or fetched, and nothing about this node's own base changed: merging
    /// the two histories is required, and is not started here.
    MergeRequired,
}

impl SyncOutcome {
    /// The summary of a sync between peers known to share a base.
    pub fn expect_synced(self, message: &str) -> SyncSummary {
        match self {
            Self::Synced(summary) => summary,
            Self::MergeRequired => panic!("{message}: the peers stand on different bases"),
        }
    }
}

/// Told that this node is behind a peer for a group, and should pull.
///
/// See [`SyncRuntime::when_behind`].
pub type BehindHook = Arc<dyn Fn(PeerId, GroupId) + Send + Sync>;

/// Notified with each link a reconciliation dials, before any lane is
/// opened on it.
///
/// Exists because a reconciliation's link is not reachable any other way.
/// `sync_once` dials its own connection and drops it when the pass ends;
/// `SubstrateNode::connect` and `SyncStack::link_to` both hand out a
/// *different* one, so anything asking "which path did that transfer
/// use?" from outside is answering about a connection the transfer never
/// touched. Observing has to happen here or not at all.
///
/// Two limits a measurement has to respect. This observes links that are
/// *dialled*, so an inbound connection this node accepted is not offered
/// here -- for the question "which carrier moved the payload" that no
/// longer matters, because a witness counts both directions of the link
/// it is on, but a caller wanting every connection to a peer still has to
/// account for accepted ones separately. And `SyncStack::link_to` returns
/// a cached link without dialling when one is already alive, so a hook
/// installed after a link exists never sees it: a measurement must start
/// from a cold daemon, before any reconciliation or bulk link has been
/// opened, or it will silently be reusing an unwatched connection.
///
/// Called for *every* link this runtime dials, before its first lane
/// opens. Both halves matter: subscribing before the first lane is what
/// lets a [`PathWatcher`](yadorilink_sync_substrate::PathWatcher) cover a
/// transfer whole rather than from whenever it happened to start, and
/// seeing every link is what stops it from covering one connection's
/// traffic and being read as the total. Reconciliation and the bulk lanes
/// dial separately, so a peer's traffic is spread over more than one
/// connection.
pub type DialedLinkHook = Arc<dyn Fn(&PeerLink) + Send + Sync>;

/// Notified with each link this runtime *accepted* -- the other half of
/// [`DialedLinkHook`]'s own explicit limit: "an inbound connection this node
/// accepted is not offered here... a caller wanting every connection to a
/// peer still has to account for accepted ones separately."
///
/// Found necessary live, not designed in advance: the 1 GiB direct-path
/// canary's path-witness tool watched only dialled links on each side, so
/// the side that already held the content (never having to dial the bulk
/// connection the other side pulled it over) reported almost no bytes and a
/// `not_direct` verdict for a transfer that was, in fact, entirely direct --
/// correct only because the OTHER side happened to be checked too. A witness
/// that watches only one direction cannot be trusted alone for a pass/fail
/// gate: it can read a genuine direct transfer as a failure whenever this
/// node is the one being pulled from rather than the one pulling.
pub type AcceptedLinkHook = Arc<dyn Fn(&PeerLink) + Send + Sync>;

/// Called at the *start* of every `sync_once` connect attempt, success or
/// failure, before the dial itself runs.
///
/// [`DialedLinkHook`] cannot stand in for this: it hands over a live
/// `PeerLink`, so it fires only once a dial has already succeeded and says
/// nothing about attempts that time out or are refused -- exactly the ones a
/// dead-peer backoff test needs to count. Unused in production (nothing
/// installs it outside tests today), same as this crate's other hooks when
/// their one caller has nothing to say.
pub type DialAttemptHook = Arc<dyn Fn(PeerId) + Send + Sync>;

/// Handles a history stream this crate does not own.
///
/// The history lane is a flow-control class, not one protocol: proof bundles
/// ride it, and so do re-bootstrap snapshots. This crate owns the first and
/// knows nothing about the second, so a stream whose kind is not
/// `ProofBundle` is handed here, whole, along with the group its hello named.
pub type HistoryStreamHook =
    Arc<dyn Fn(PeerId, GroupId, HistoryStreamKind, LaneStream) -> BoxFuture + Send + Sync>;

type BoxFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Handles a stream on a lane this crate does not own.
///
/// Blocks and service RPCs ride their own lanes for flow-control reasons, but
/// neither protocol belongs here: this crate moves bytes and compares sets. A
/// stream on either is handed over whole, with the peer and the group its
/// hello named.
pub type LaneStreamHook = Arc<dyn Fn(PeerId, GroupId, Lane, LaneStream) -> BoxFuture + Send + Sync>;

/// Owns the transport and the per-peer scheduling.
pub struct SyncRuntime<P: ReplicaPort + 'static> {
    node: SubstrateNode,
    port: Arc<P>,
    flight: Arc<SingleFlight<(PeerId, GroupId)>>,
    config: SessionConfig,
    /// Shared with every serving task rather than copied into them: the
    /// hook is installed after `serve` has already started (the driver that
    /// owns it is built on top of this runtime), so a task holding a
    /// snapshot would hold `None` for the life of the process.
    behind: Arc<std::sync::Mutex<Option<BehindHook>>>,
    /// Shared and read live, for the same reason as `behind`.
    history: Arc<std::sync::Mutex<Option<HistoryStreamHook>>>,
    lanes: Arc<std::sync::Mutex<Option<LaneStreamHook>>>,
    dialed: Arc<std::sync::Mutex<Option<DialedLinkHook>>>,
    accepted: Arc<std::sync::Mutex<Option<AcceptedLinkHook>>>,
    dial_attempted: Arc<std::sync::Mutex<Option<DialAttemptHook>>>,
    /// Milliseconds, not a `Duration` directly, so it fits an `AtomicU64` --
    /// per-instance rather than a process-global override, so a test that
    /// shortens this to exercise a genuinely unreachable peer cannot also
    /// shorten it out from under some unrelated test's own, unrelated
    /// `SyncRuntime` racing on another thread in the same test binary.
    connect_deadline_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl<P: ReplicaPort + 'static> SyncRuntime<P> {
    pub fn new(node: SubstrateNode, port: Arc<P>) -> Self {
        Self {
            node,
            port,
            flight: Arc::new(SingleFlight::new()),
            config: SessionConfig::default(),
            behind: Arc::new(std::sync::Mutex::new(None)),
            history: Arc::new(std::sync::Mutex::new(None)),
            lanes: Arc::new(std::sync::Mutex::new(None)),
            dialed: Arc::new(std::sync::Mutex::new(None)),
            accepted: Arc::new(std::sync::Mutex::new(None)),
            dial_attempted: Arc::new(std::sync::Mutex::new(None)),
            connect_deadline_ms: Arc::new(std::sync::atomic::AtomicU64::new(
                CONNECT_DEADLINE.as_millis() as u64,
            )),
        }
    }

    /// Test-only: this instance's own connect deadline, not a process-wide
    /// default -- see [`Self::connect_deadline_ms`]'s own doc comment.
    pub fn set_connect_deadline_for_tests(&self, deadline: std::time::Duration) {
        self.connect_deadline_ms
            .store(deadline.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    fn connect_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.connect_deadline_ms.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Say who sees every connect *attempt* against a peer, whether or not
    /// it succeeds. See [`DialAttemptHook`] for why [`Self::when_link_dialed`]
    /// cannot answer this.
    pub fn when_dial_attempted(&self, hook: DialAttemptHook) {
        *self.dial_attempted.lock().expect("dial-attempt hook poisoned") = Some(hook);
    }

    /// Say what to do when *this* node turns out to be the one that is
    /// behind.
    ///
    /// One reconciliation tells both sides the whole difference between
    /// them, in both directions. But only the side that opened the session
    /// fetches: it knows what it wants, and it has the connection. The
    /// responder ends the session knowing exactly what it is missing and
    /// doing nothing about it — so a Change authored on A would reach B only
    /// when B next happened to reconcile for some other reason.
    ///
    /// The responder could instead pull back down the same connection, but
    /// that would require the initiator to be accepting streams on a link it
    /// is itself mid-session on, and the initiator does not accept there.
    /// Pushing instead would put the sender in charge of what the receiver
    /// stores.
    ///
    /// So the responder does what any other component that learns it is
    /// behind does: it schedules its own reconciliation, through the same
    /// single-flighted path everything else uses. That costs one extra round
    /// trip and keeps every fetch a pull, initiated by the node that wants
    /// the data.
    ///
    /// Like every other wake in this design, this is latency and not
    /// correctness. Dropping it entirely would only mean B waits for its next
    /// reconciliation; it could not lose the Change, because the difference
    /// is recomputed from durable sets every time.
    pub fn when_behind(&self, hook: BehindHook) {
        *self.behind.lock().expect("behind hook poisoned") = Some(hook);
    }

    /// Say who sees each link a reconciliation dials. See [`DialedLinkHook`].
    pub fn when_link_dialed(&self, hook: DialedLinkHook) {
        *self.dialed.lock().expect("dialed hook poisoned") = Some(hook);
    }

    /// Say who sees each link this runtime accepts. See [`AcceptedLinkHook`].
    pub fn when_link_accepted(&self, hook: AcceptedLinkHook) {
        *self.accepted.lock().expect("accepted hook poisoned") = Some(hook);
    }

    /// Say who handles a history stream that is not a proof bundle.
    pub fn when_history_stream(&self, hook: HistoryStreamHook) {
        *self.history.lock().expect("history hook poisoned") = Some(hook);
    }

    /// Say who handles a stream on a lane this crate does not own.
    pub fn when_lane_stream(&self, hook: LaneStreamHook) {
        *self.lanes.lock().expect("lane hook poisoned") = Some(hook);
    }

    pub fn peer_id(&self) -> PeerId {
        self.node.peer_id()
    }

    /// Dial a peer, for a caller that needs the connection itself rather than
    /// a reconciliation over it — the lanes this crate does not own.
    pub async fn connect(&self, peer: PeerId) -> Result<PeerLink, SyncRuntimeError> {
        self.dial(peer).await
    }

    /// Dial `peer` and show the link to the observer, if any, before it has
    /// carried anything.
    ///
    /// Every link this runtime opens goes through here. That is the point:
    /// reconciliation dials its own connection and the bulk lanes dial
    /// another through `connect`, so an observer wired to only one of them
    /// sees a fraction of the traffic to that peer and reports it as the
    /// whole. Which fraction is the dangerous part -- reconciliation's link
    /// carries the Change, the other carries the file blocks, and a
    /// throughput measurement that watched the wrong one would be reporting
    /// on metadata.
    async fn dial(&self, peer: PeerId) -> Result<PeerLink, SyncRuntimeError> {
        let link = self.node.connect(peer).await?;
        let hook = self.dialed.lock().expect("dialed hook poisoned").clone();
        if let Some(hook) = hook {
            hook(&link);
        }
        Ok(link)
    }

    pub fn local_address(&self) -> PeerAddress {
        self.node.local_address()
    }

    /// Close this node's substrate endpoint and every connection on it.
    ///
    /// Must be awaited while the runtime the endpoint's own tasks were spawned
    /// on is still running -- see [`SubstrateNode::shutdown`].
    pub async fn shutdown(&self) {
        self.node.shutdown().await;
    }

    /// This node's address, updated as the substrate learns more of it.
    pub fn watch_local_address(&self) -> tokio::sync::watch::Receiver<PeerAddress> {
        self.node.watch_local_address()
    }

    /// Mark this node's possession of `group` as changed.
    ///
    /// Cheap and non-blocking. If a reconciliation with `peer` is already
    /// running, it will make one further pass rather than a second session
    /// being started alongside it.
    ///
    /// This is a latency optimisation and never a correctness mechanism. A
    /// wake-up that is lost costs the time until the next reconciliation and
    /// nothing more, because the difference is always recomputed from the two
    /// peers' durable sets.
    pub fn note_local_change(&self, peer: PeerId, group: &GroupId) {
        self.flight.wake(&(peer, group.clone()));
    }

    /// Serve inbound connections for as long as the returned task lives.
    ///
    /// Each accepted connection gets its own task, and each lane stream within
    /// it gets its own task, so a peer that stalls one lane stalls only that
    /// lane.
    pub fn serve(&self, mut inbound: tokio::sync::mpsc::Receiver<PeerLink>) -> ServeHandle {
        let port = self.port.clone();
        let behind = self.behind.clone();
        let history = self.history.clone();
        let lanes = self.lanes.clone();
        let accepted = self.accepted.clone();
        tokio::spawn(async move {
            while let Some(link) = inbound.recv().await {
                if let Some(hook) = accepted.lock().expect("accepted hook poisoned").clone() {
                    hook(&link);
                }
                let port = port.clone();
                let behind = behind.clone();
                let history = history.clone();
                let lanes = lanes.clone();
                tokio::spawn(async move { serve_link(link, port, behind, history, lanes).await });
            }
        })
    }

    /// Reconcile with one peer for one group, then fetch whatever is missing.
    ///
    /// At most one of these runs per (peer, group) at a time. A concurrent
    /// call is coalesced into the running one rather than opening a second
    /// set of lanes against the same peer.
    pub async fn sync_with(
        &self,
        peer: PeerId,
        group: &GroupId,
    ) -> Result<Option<SyncOutcome>, SyncRuntimeError> {
        let key = (peer, group.clone());

        // The closure may run more than once — a wake-up during a pass earns
        // exactly one further pass — so the summary reported is the last
        // pass's, which is the one describing current state.
        let last = std::sync::Mutex::new(None);

        let flight = self.flight.clone();
        let outcome = flight
            .run(key, || async {
                let summary = self.sync_once(peer, group).await?;
                *last.lock().expect("summary slot poisoned") = Some(summary);
                Ok::<_, SyncRuntimeError>(())
            })
            .await?;

        match outcome {
            Flight::Ran { .. } => Ok(last.into_inner().expect("summary slot poisoned")),
            // Distinct from "this node has no address for that peer", which
            // the caller reports separately: coalescing means a flight for
            // this exact pair is already running, so this call has nothing
            // to add.
            Flight::Coalesced => Ok(None),
        }
    }

    async fn sync_once(
        &self,
        peer_id: PeerId,
        group: &GroupId,
    ) -> Result<SyncOutcome, SyncRuntimeError> {
        if let Some(hook) = self.dial_attempted.lock().expect("dial-attempt hook poisoned").clone()
        {
            hook(peer_id);
        }
        let link = with_deadline("connect", self.connect_deadline(), self.dial(peer_id)).await?;
        let peer = link.peer();

        // Reconciliation runs on its own stream, opened first and kept
        // separate from any bulk traffic that follows.
        let reconciled = {
            let mut lane = with_deadline(
                "reconciliation lane open",
                LANE_OPEN_DEADLINE,
                link.open_lane(Lane::Reconciliation),
            )
            .await?;
            with_deadline(
                "reconciliation lane hello",
                LANE_OPEN_DEADLINE,
                open_lane(&mut lane, group),
            )
            .await?;
            with_deadline(
                "reconciliation exchange",
                RECONCILE_EXCHANGE_DEADLINE,
                reconcile(
                    &mut lane,
                    self.port.as_ref(),
                    PeerKey(*peer.as_bytes()),
                    group,
                    Role::Initiator,
                    &self.config,
                ),
            )
            .await?
        };
        let reconciled = match reconciled {
            ReconcileOutcome::Reconciled(reconciled) => reconciled,
            ReconcileOutcome::MergeRequired => {
                link.close();
                return Ok(SyncOutcome::MergeRequired);
            }
        };

        let mut staged = 0usize;
        if !reconciled.want.is_empty() {
            let mut lane = with_deadline(
                "history lane open",
                LANE_OPEN_DEADLINE,
                link.open_lane(Lane::History),
            )
            .await?;
            with_deadline("history lane hello", LANE_OPEN_DEADLINE, open_lane(&mut lane, group))
                .await?;
            // Which protocol this history stream speaks. The bundle protocol
            // below never sees this byte.
            with_deadline(
                "history kind write",
                LANE_OPEN_DEADLINE,
                write_history_kind(&mut lane, HistoryStreamKind::ProofBundle),
            )
            .await?;
            // Deliberately NOT deadlined: `request_bundles` interleaves
            // network reads with local verification and SQLite staging, and
            // bounding it would abort legitimate local work. Bounding the
            // steps above is what guarantees the single-flight key cannot be
            // held forever by a peer that never answers.
            staged = request_bundles(
                &mut lane,
                self.port.as_ref(),
                PeerKey(*peer.as_bytes()),
                group,
                &reconciled.want,
                &self.config,
            )
            .await?
            .len();
        }

        link.close();

        Ok(SyncOutcome::Synced(SyncSummary {
            wanted: reconciled.want.len(),
            staged,
            rounds: reconciled.rounds,
        }))
    }
}

/// Read a history stream's kind byte.
///
/// `None` covers both an unreadable stream and an unknown kind: neither is a
/// thing to guess at, and both end the stream.
async fn read_history_kind(lane: &mut LaneStream) -> Option<HistoryStreamKind> {
    use tokio::io::AsyncReadExt;
    let mut tag = [0u8; 1];
    match lane.read_exact(&mut tag).await {
        Ok(_) => HistoryStreamKind::from_tag(tag[0]),
        Err(_) => None,
    }
}

/// Write a history stream's kind byte, as its opener.
pub async fn write_history_kind(
    lane: &mut LaneStream,
    kind: HistoryStreamKind,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    lane.write_all(&[kind.tag()]).await?;
    lane.flush().await
}

/// Accept lane streams from one peer until the connection ends.
async fn serve_link<P: ReplicaPort + 'static>(
    link: PeerLink,
    port: Arc<P>,
    behind: Arc<std::sync::Mutex<Option<BehindHook>>>,
    history: Arc<std::sync::Mutex<Option<HistoryStreamHook>>>,
    lanes: Arc<std::sync::Mutex<Option<LaneStreamHook>>>,
) {
    let peer = link.peer();
    let config = SessionConfig::default();

    while let Ok(mut lane) = link.accept_lane().await {
        let port = port.clone();
        let behind = behind.clone();
        let history = history.clone();
        let lanes = lanes.clone();
        let kind = lane.lane();
        tokio::spawn(async move {
            let group = match accept_lane(&mut lane).await {
                Ok(group) => group,
                Err(error) => {
                    tracing::debug!(%peer, ?kind, %error, "peer opened a lane without a usable hello");
                    return;
                }
            };

            let result = match kind {
                // Under the same deadline as an outbound exchange. The
                // responder reads its own state before the peer says
                // anything, and a peer that opens lanes and then goes quiet
                // would otherwise keep each one, and what it read, for as
                // long as the connection lives.
                Lane::Reconciliation => match tokio::time::timeout(
                    RECONCILE_EXCHANGE_DEADLINE,
                    reconcile(
                        &mut lane,
                        port.as_ref(),
                        PeerKey(*peer.as_bytes()),
                        &group,
                        Role::Responder,
                        &config,
                    ),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        Err(yadorilink_sync_protocol::ProtocolError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "inbound reconciliation exchange exceeded its deadline",
                        )))
                    }
                }
                .map(|outcome| {
                    // A peer on another base has nothing this side could
                    // fetch; the port has already recorded the claim.
                    let ReconcileOutcome::Reconciled(reconciled) = outcome else { return };
                    // This side learned what it is missing too. It does not
                    // fetch here — see `when_behind`.
                    if !reconciled.want.is_empty() {
                        let hook = behind.lock().expect("behind hook poisoned").clone();
                        if let Some(hook) = hook {
                            hook(peer, group.clone());
                        }
                    }
                }),
                Lane::History => {
                    // The lane is a class; the first byte after the hello
                    // says which protocol this stream speaks. Read here and
                    // nowhere below: the
                    // bundle protocol must not learn that re-bootstrap
                    // exists, and re-bootstrap must not learn how bundles are
                    // framed.
                    match read_history_kind(&mut lane).await {
                        Some(HistoryStreamKind::ProofBundle) => serve_bundles(
                            &mut lane,
                            port.as_ref(),
                            PeerKey(*peer.as_bytes()),
                            &group,
                        )
                        .await
                        .map(|_| ()),
                        Some(other) => {
                            let hook = history.lock().expect("history hook poisoned").clone();
                            match hook {
                                Some(hook) => {
                                    hook(peer, group.clone(), other, lane).await;
                                    return;
                                }
                                None => {
                                    tracing::debug!(
                                        %peer, ?other,
                                        "no handler for this history stream kind; closing"
                                    );
                                    Ok(())
                                }
                            }
                        }
                        // An unknown kind fails the stream closed rather than
                        // guessing which protocol a peer meant.
                        None => Ok(()),
                    }
                }
                // Neither protocol belongs to this crate, so a stream on
                // either is handed over whole.
                Lane::Block | Lane::Service => {
                    let hook = lanes.lock().expect("lane hook poisoned").clone();
                    match hook {
                        Some(hook) => {
                            hook(peer, group.clone(), kind, lane).await;
                            return;
                        }
                        None => {
                            tracing::debug!(%peer, ?kind, "no handler for this lane; closing");
                            Ok(())
                        }
                    }
                }
            };

            if let Err(error) = result {
                // Nothing here is repaired in place. The session ends and the
                // next one recomputes the difference from durable state.
                tracing::debug!(%peer, ?kind, %group, %error, "sync lane ended");
            }
        });
    }
}

#[cfg(test)]
mod deadline_tests;
