//! Public construction and protocol boundary for peer sessions.
//!
//! The implementation remains in `peer_session_impl`; this module prevents a
//! partially-wired session from escaping its constructor and performs an exact
//! current-generation handshake before the implementation loop starts.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::block_serve::BlockServeEngine;
use crate::error::PeerSessionError;
use crate::rate_limiter::RateLimiters;
use yadorilink_replica_domain::change::ChangeAuth;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::rebootstrap::RebootstrapRequired;
use yadorilink_replica_engine::conflict::PathHead;

#[cfg(madsim)]
pub use crate::peer_session_impl::set_test_clock_override;
use crate::peer_session_impl::PeerSyncSessionOneTimeDeps;
pub use crate::peer_session_impl::RetirementAttempt;
pub use crate::peer_session_impl::{
    disk_race_fingerprint, BlockWriteActivityProvider, ChangeAuthenticator, HandoffLeaseResponder,
    HandoffTicketResponder, HydrationOutcome, PeerHandoffLeaseGrant, PeerHandoffTicketGrant,
    PendingLocalChangeFlush, PendingLocalFlushOutcome, PreparedRebootstrap, ProjectionAttempt,
    RebootstrapHandler, RelayReplySink, RelaySessionHandler, RootCommitAuthorityProvider,
    SettlementEvidence, DEFAULT_HYDRATION_TIMEOUT, DEFAULT_MAINTENANCE_RECONCILE_INTERVAL,
};

use crate::peer_session_impl::PeerSyncSession as InnerPeerSyncSession;

#[derive(Clone)]
pub struct PeerSyncSessionDeps {
    pub rate_limiters: Arc<RateLimiters>,
    pub block_serve_engine: Arc<BlockServeEngine>,
    pub headroom_override_bytes: Option<u64>,
    pub headroom_enforced: bool,
    pub maintenance_reconcile_interval: Duration,
    pub pending_local_change_flush: Arc<dyn PendingLocalChangeFlush>,
    pub change_authenticator: Arc<dyn ChangeAuthenticator>,
    pub handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
    pub rebootstrap_handler: Arc<dyn RebootstrapHandler>,
    pub block_write_activity_provider: Arc<dyn BlockWriteActivityProvider>,
    pub handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    pub root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
    /// M3 Pass 5: see `RelaySessionHandler`'s own doc comment.
    pub relay_session_handler: Arc<dyn RelaySessionHandler>,
    /// Lets this session author a captured change for content its own
    /// materialize path displaces during custody transfer (see
    /// `PeerSyncSession::set_change_emitter`'s doc comment). A device that
    /// has not yet been provisioned a signing key is left with no emitter --
    /// the same fail-closed default the field itself documents -- so a
    /// future caller must retain rather than author in that case; it never
    /// falls back to an unsigned or wrong-identity write.
    pub change_emitter: Option<Arc<yadorilink_replica_domain::admission::ChangeEmitter>>,
}

impl PeerSyncSessionDeps {
    /// Explicit standalone/test integrations. Network-facing capabilities that
    /// require daemon or coordination-plane state deny requests; bookkeeping
    /// hooks that have no standalone owner are no-ops. Nothing is represented
    /// by absence.
    pub fn standalone() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        Self {
            rate_limiters: Arc::new(RateLimiters::unlimited()),
            block_serve_engine: BlockServeEngine::new(64 * GIB, 16 * GIB, 32 * GIB, 64),
            headroom_override_bytes: None,
            headroom_enforced: false,
            maintenance_reconcile_interval: DEFAULT_MAINTENANCE_RECONCILE_INTERVAL,
            pending_local_change_flush: Arc::new(NoopPendingLocalChangeFlush),
            change_authenticator: Arc::new(DenyAllChangeAuthenticator),
            handoff_lease_responder: Arc::new(DenyHandoffLeaseResponder),
            rebootstrap_handler: Arc::new(DenyRebootstrapHandler),
            block_write_activity_provider: Arc::new(NoopBlockWriteActivityProvider),
            handoff_ticket_responder: Arc::new(DenyHandoffTicketResponder),
            root_commit_authority_provider: Arc::new(DenyRootCommitAuthorityProvider),
            relay_session_handler: Arc::new(DenyRelaySessionHandler),
            change_emitter: None,
        }
    }

    /// This session's one-time, construction-only capability injections,
    /// in the shape `InnerPeerSyncSession::new_with_forwarding` takes them.
    fn one_time_deps(&self) -> PeerSyncSessionOneTimeDeps {
        PeerSyncSessionOneTimeDeps {
            pending_local_change_flush: self.pending_local_change_flush.clone(),
            root_commit_authority_provider: self.root_commit_authority_provider.clone(),
            change_authenticator: self.change_authenticator.clone(),
            handoff_lease_responder: self.handoff_lease_responder.clone(),
            rebootstrap_handler: self.rebootstrap_handler.clone(),
            block_write_activity_provider: self.block_write_activity_provider.clone(),
            handoff_ticket_responder: self.handoff_ticket_responder.clone(),
            relay_session_handler: self.relay_session_handler.clone(),
            change_emitter: self.change_emitter.clone(),
        }
    }
}

pub struct PeerSyncSession {
    inner: Arc<InnerPeerSyncSession>,
    started: AtomicBool,
}

impl PeerSyncSession {
    pub fn new(
        channel: Arc<dyn crate::ports::PeerMessageChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<dyn crate::ports::PeerReplicaStatePort>,
        store: Arc<dyn crate::ports::BlockContentStore>,
        shared_group_ids: Vec<String>,
        sync_roots: HashMap<String, PathBuf>,
    ) -> Arc<Self> {
        Self::new_with_dependencies(
            channel,
            local_device_id,
            peer_device_id,
            state,
            store,
            shared_group_ids,
            sync_roots,
            None,
            PeerSyncSessionDeps::standalone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_forwarding(
        channel: Arc<dyn crate::ports::PeerMessageChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<dyn crate::ports::PeerReplicaStatePort>,
        store: Arc<dyn crate::ports::BlockContentStore>,
        shared_group_ids: Vec<String>,
        sync_roots: HashMap<String, PathBuf>,
        forward_tx: Option<mpsc::UnboundedSender<(String, FileRecord)>>,
    ) -> Arc<Self> {
        Self::new_with_dependencies(
            channel,
            local_device_id,
            peer_device_id,
            state,
            store,
            shared_group_ids,
            sync_roots,
            forward_tx,
            PeerSyncSessionDeps::standalone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_dependencies(
        channel: Arc<dyn crate::ports::PeerMessageChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<dyn crate::ports::PeerReplicaStatePort>,
        store: Arc<dyn crate::ports::BlockContentStore>,
        shared_group_ids: Vec<String>,
        sync_roots: HashMap<String, PathBuf>,
        forward_tx: Option<mpsc::UnboundedSender<(String, FileRecord)>>,
        dependencies: PeerSyncSessionDeps,
    ) -> Arc<Self> {
        let one_time_deps = dependencies.one_time_deps();
        let inner = InnerPeerSyncSession::new_with_forwarding(
            channel,
            local_device_id,
            peer_device_id,
            state,
            store,
            shared_group_ids,
            sync_roots,
            forward_tx,
            one_time_deps,
        );
        inner.set_rate_limiters(dependencies.rate_limiters.clone());
        inner.set_block_serve_engine(dependencies.block_serve_engine.clone());
        inner.set_headroom_override_bytes(dependencies.headroom_override_bytes);
        inner.set_headroom_enforced(dependencies.headroom_enforced);
        inner.set_maintenance_reconcile_interval(dependencies.maintenance_reconcile_interval);
        Arc::new(Self { inner, started: AtomicBool::new(false) })
    }

    fn assert_not_started(&self) {
        assert!(
            !self.started.load(Ordering::Acquire),
            "PeerSyncSession dependencies are immutable after run() starts"
        );
    }

    pub fn set_rate_limiters(&self, value: Arc<RateLimiters>) {
        self.assert_not_started();
        self.inner.set_rate_limiters(value);
    }

    pub fn set_block_serve_engine(&self, value: Arc<BlockServeEngine>) {
        self.assert_not_started();
        self.inner.set_block_serve_engine(value);
    }

    pub fn set_headroom_override_bytes(&self, value: Option<u64>) {
        self.assert_not_started();
        self.inner.set_headroom_override_bytes(value);
    }

    pub fn set_headroom_enforced(&self, value: bool) {
        self.assert_not_started();
        self.inner.set_headroom_enforced(value);
    }

    pub fn set_maintenance_reconcile_interval(&self, value: Duration) {
        self.assert_not_started();
        self.inner.set_maintenance_reconcile_interval(value);
    }

    /// M3 Pass 5: sends a `RelayOpen` over this channel, asking the peer
    /// on the other end to act as relay -- see `InnerPeerSyncSession::
    /// send_relay_open`'s own doc comment.
    pub async fn send_relay_open(
        &self,
        open: yadorilink_sync_wire::RelayOpenFrame,
    ) -> Result<(), PeerSessionError> {
        self.inner.send_relay_open(open).await
    }

    /// M3 Pass 5: sends a `RelayData` over this channel -- used by BOTH
    /// directions of the relay protocol: the requester ("A") sending a
    /// datagram toward the destination through this relay, and (via
    /// `RelayReplySink`, `self.inner`'s own trait impl) the relay itself
    /// forwarding a reply back. Exposed on the wrapper so a requester can
    /// drive its own outbound side directly, symmetric with `send_relay_
    /// open` above.
    ///
    /// Returns whether the channel took it. The requesting side needs that
    /// answer where the forwarding side does not: it is standing in for a
    /// UDP socket on behalf of a QUIC connection, and a carrier that
    /// silently discards is indistinguishable to that connection from one
    /// that works, so a refusal has to be visible rather than inferred from
    /// the traffic that never arrives.
    pub fn send_relay_data(&self, session_id: u64, payload: Vec<u8>) -> bool {
        self.inner.try_send_relay_data(session_id, payload)
    }

    pub fn send_relay_close(&self, session_id: u64, reason: &str) -> bool {
        self.inner.send_relay_close_frame(session_id, reason)
    }

    /// Handshake consolidation (2026-09-02): this facade used to run its
    /// own separate handshake preflight here (`peer_handshake_preflight`,
    /// `validate_peer_handshake`) BEFORE ever calling `self.inner.run()`
    /// -- a second, outer "send ClusterConfig, wait for the peer's first
    /// frame, validate it" cycle layered on top of `PeerSyncSession::run`
    /// (`peer_session_impl`)'s own, already-complete one. Worse than
    /// merely redundant: the outer preflight's own `channel.recv()` READ
    /// AND DISCARDED the peer's genuinely first `ClusterConfig` off the
    /// wire without ever feeding it into the inner session's
    /// `handle_cluster_config`/`peer_handshake_received` state, so that
    /// state could only ever become true from a SECOND, wasted exchange
    /// (see `peer_session_impl::wait_for_and_process_peer_first_frame`'s
    /// own doc comment for the full history and the confirmed-real test
    /// workaround this forced). The inner implementation now owns the
    /// whole handshake -- send, receive, first-frame validation
    /// (including the exact serve-budget check this facade used to do),
    /// and the state transition -- so this is a pure passthrough again.
    pub async fn run(self: Arc<Self>) -> Result<(), PeerSessionError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(PeerSessionError::InvalidInput(
                "PeerSyncSession::run may only be started once".to_string(),
            ));
        }
        self.inner.clone().run().await
    }

    pub async fn reconcile_local_materialization_audit(
        self: Arc<Self>,
        group_id: &str,
    ) -> Result<bool, PeerSessionError> {
        self.inner.clone().reconcile_local_materialization_audit(group_id).await
    }

    /// See `peer_session_impl::PeerSyncSession::retire_conflict_copies_only`'s
    /// own doc comment.
    pub async fn retire_conflict_copies_only(
        self: Arc<Self>,
        group_id: &str,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        self.inner.clone().retire_conflict_copies_only(group_id).await
    }

    pub async fn reconcile_paths_directly(
        &self,
        group_id: &str,
        paths: BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        self.inner.reconcile_paths_directly(group_id, paths).await
    }

    /// See `peer_session_impl::PeerSyncSession::zero_work_settlement_for_path`'s
    /// own doc comment.
    pub fn zero_work_settlement_for_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        self.inner.zero_work_settlement_for_path(group_id, path)
    }

    /// The current recommended number of concurrent in-flight `fetch_block`
    /// requests to this peer, per this session's `AdaptiveWindow`.
    pub fn fetch_window(&self) -> usize {
        self.inner.fetch_window()
    }

    /// Records that a `fetch_block` request to this peer went unanswered
    /// within the caller's own timeout.
    pub fn record_fetch_timeout(&self) {
        self.inner.record_fetch_timeout()
    }

    /// Whether `group_id` is one this session's peer is currently
    /// authorized to sync with us.
    pub fn shares_group(&self, group_id: &str) -> bool {
        self.inner.shares_group(group_id)
    }

    /// Withdraws this peer's authorization for `group_id`.
    pub fn revoke_group(&self, group_id: &str) {
        self.inner.revoke_group(group_id)
    }

    /// The inverse of `revoke_group`: grants (or re-grants) this peer's
    /// authorization for `group_id`.
    pub fn grant_group(&self, group_id: &str) {
        self.inner.grant_group(group_id)
    }

    /// Replaces the entire live-authorized-group set at once.
    pub fn set_authorized_groups(&self, group_ids: impl IntoIterator<Item = String>) {
        self.inner.set_authorized_groups(group_ids)
    }

    /// Diagnostic-only public wrapper over this path's combined live heads,
    /// for out-of-band snapshot tooling. Reads purely local state, so the
    /// result is identical regardless of which peer session it's called
    /// through.
    pub fn diagnostic_path_heads(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<PathHead>, PeerSessionError> {
        self.inner.diagnostic_path_heads(group_id, path)
    }

    /// Public wrapper over the pure ignore-policy verdict alone -- see
    /// `is_path_locally_ignored`'s own doc comment on the inner type for
    /// why the Convergence Engine's ignore-recheck sweep must use this
    /// instead of a reconcile/materialize attempt.
    pub fn is_path_locally_ignored(&self, group_id: &str, path: &str) -> bool {
        self.inner.is_path_locally_ignored(group_id, path)
    }

    /// Sends a `VersionPresentQuery` to this peer and awaits its answer,
    /// bounded by a fixed timeout. Fails closed (`false`) on any timeout or
    /// non-answer.
    pub async fn request_version_present(
        &self,
        group_id: &str,
        file_path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
        for_handoff: bool,
    ) -> bool {
        self.inner
            .request_version_present(group_id, file_path, version_hash, blocks, for_handoff)
            .await
    }

    /// Cumulative block body bytes received from this peer so far -- see
    /// `InnerPeerSyncSession::content_bytes_received`'s own doc comment.
    pub fn content_bytes_received(&self) -> u64 {
        self.inner.content_bytes_received()
    }

    /// True once the peer has sent any cluster configuration.
    pub fn peer_handshake_received(&self) -> bool {
        self.inner.peer_handshake_received()
    }

    /// See `InnerPeerSyncSession::mark_peer_handshake_received_for_tests`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn mark_peer_handshake_received_for_tests(&self) {
        self.inner.mark_peer_handshake_received_for_tests()
    }

    /// Announces this device's current DAG heads for `group_id` to the peer.
    /// Only announces to a peer whose own handshake has already arrived.
    pub async fn announce_local_commit(&self, group_id: &str) -> Result<(), PeerSessionError> {
        self.inner.announce_local_commit(group_id).await
    }

    pub async fn fetch_block(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> Result<Option<Bytes>, PeerSessionError> {
        self.inner.fetch_block(group_id, file_path, hash).await
    }

    /// Like `fetch_block`, sized to `expected_size` -- see
    /// `InnerPeerSyncSession::fetch_block_sized`'s own doc comment.
    pub async fn fetch_block_sized(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
        expected_size: u64,
    ) -> Result<Option<Bytes>, PeerSessionError> {
        self.inner.fetch_block_sized(group_id, file_path, hash, expected_size).await
    }

    /// See `InnerPeerSyncSession::fetch_response_timeout_for`'s own doc
    /// comment. A free-standing size-to-deadline computation (no `&self`
    /// needed), forwarded here so callers outside this crate that only
    /// ever see the public `PeerSyncSession` (this wrapper, not the
    /// doc-hidden inner type) can still reach it as `PeerSyncSession::
    /// fetch_response_timeout_for(..)`.
    pub fn fetch_response_timeout_for(expected_size: u64) -> std::time::Duration {
        InnerPeerSyncSession::fetch_response_timeout_for(expected_size)
    }

    /// On-access hydration: fetches a placeholder file's blocks from this
    /// peer and materializes its full content.
    pub async fn hydrate_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        self.inner.hydrate_file(group_id, path).await
    }

    /// Like `hydrate_file`, with an explicit timeout.
    pub async fn hydrate_file_with_timeout(
        &self,
        group_id: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        self.inner.hydrate_file_with_timeout(group_id, path, timeout).await
    }

    /// Sends a `HandoffLeaseRequest` to this peer and awaits the
    /// `HandoffLeaseGrant` reply.
    pub async fn request_handoff_lease_from_peer(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffLeaseGrant> {
        self.inner.request_handoff_lease_from_peer(group_id).await
    }

    /// Best-effort, one-way release of a lease this peer granted earlier.
    pub async fn release_handoff_lease_to_peer(
        &self,
        group_id: &str,
        lease_id: &str,
    ) -> Result<(), PeerSessionError> {
        self.inner.release_handoff_lease_to_peer(group_id, lease_id).await
    }

    /// Sends a `HandoffTicketRequest` to this peer (the device being
    /// removed/revoked) and awaits the `HandoffTicketGrant` reply.
    pub async fn request_handoff_ticket_from_peer(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        self.inner.request_handoff_ticket_from_peer(group_id).await
    }

    /// Best-effort cancellation of a removed-device ticket.
    pub async fn release_handoff_ticket_to_peer(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) -> Result<(), PeerSessionError> {
        self.inner.release_handoff_ticket_to_peer(group_id, target_device_id, lease_id).await
    }
}

struct NoopPendingLocalChangeFlush;

impl PendingLocalChangeFlush for NoopPendingLocalChangeFlush {
    fn flush_pending_local_change<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }
}

struct DenyAllChangeAuthenticator;

impl ChangeAuthenticator for DenyAllChangeAuthenticator {
    fn signing_key(&self, _device_id: &str) -> Option<[u8; 32]> {
        None
    }

    fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
        false
    }

    fn accepts_change_auth(
        &self,
        _device_id: &str,
        _group_id: &str,
        _signing_key_fingerprint: [u8; 32],
        _auth: ChangeAuth,
    ) -> bool {
        false
    }
}

struct DenyRelaySessionHandler;

impl RelaySessionHandler for DenyRelaySessionHandler {
    fn handle_relay_open<'a>(
        &'a self,
        open: yadorilink_sync_wire::RelayOpenFrame,
        _authenticated_peer_device_id: &'a str,
        _reply_sink: Arc<dyn RelayReplySink>,
    ) -> Pin<Box<dyn Future<Output = yadorilink_sync_wire::RelayOpenedFrame> + Send + 'a>> {
        Box::pin(async move {
            yadorilink_sync_wire::RelayOpenedFrame {
                grant_id: open.grant_id,
                granted: false,
                session_id: 0,
            }
        })
    }

    fn handle_relay_data<'a>(
        &'a self,
        _data: yadorilink_sync_wire::RelayDataFrame,
        _authenticated_peer_device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn handle_relay_close<'a>(
        &'a self,
        _close: yadorilink_sync_wire::RelayCloseFrame,
        _authenticated_peer_device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn handle_relay_opened<'a>(
        &'a self,
        _opened: yadorilink_sync_wire::RelayOpenedFrame,
        _authenticated_peer_device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct DenyHandoffLeaseResponder;

impl HandoffLeaseResponder for DenyHandoffLeaseResponder {
    fn request_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct DenyHandoffTicketResponder;

impl HandoffTicketResponder for DenyHandoffTicketResponder {
    fn request_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
        _target_device_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct DenyRebootstrapHandler;

impl RebootstrapHandler for DenyRebootstrapHandler {
    fn prepare_rebootstrap(
        &self,
        _group_id: &str,
        _requested_hash: ChangeHash,
    ) -> Result<Option<PreparedRebootstrap>, PeerSessionError> {
        Ok(None)
    }

    fn verify_rebootstrap(&self, _required: &RebootstrapRequired) -> Result<(), PeerSessionError> {
        Err(PeerSessionError::InvalidInput(
            "re-bootstrap is unavailable without an explicit trust integration".to_string(),
        ))
    }

    fn install_rebootstrap(
        &self,
        _required: &RebootstrapRequired,
        _snapshot_bytes: &[u8],
    ) -> Result<(), PeerSessionError> {
        Err(PeerSessionError::InvalidInput(
            "re-bootstrap is unavailable without an explicit trust integration".to_string(),
        ))
    }
}

struct NoopBlockWriteActivityProvider;

impl BlockWriteActivityProvider for NoopBlockWriteActivityProvider {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }
}

struct DenyRootCommitAuthorityProvider;

impl RootCommitAuthorityProvider for DenyRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        None
    }
}
