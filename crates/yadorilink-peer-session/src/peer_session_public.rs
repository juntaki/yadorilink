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
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::block_serve::BlockServeEngine;
use yadorilink_replica_domain::change::ChangeAuth;
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_sync_wire::PeerWireCodec;
use crate::error::PeerSessionError;
use crate::rate_limiter::RateLimiters;
use yadorilink_replica_domain::rebootstrap::RebootstrapRequired;
use yadorilink_replica_domain::file::FileRecord;

#[cfg(madsim)]
pub use crate::peer_session_impl::set_test_clock_override;
pub use crate::peer_session_impl::{
    disk_race_fingerprint, BlockWriteActivityProvider, ChangeAuthenticator, HandoffLeaseResponder,
    HandoffTicketResponder, HydrationOutcome, PeerHandoffLeaseGrant, PeerHandoffTicketGrant,
    PendingLocalChangeFlush, PreparedRebootstrap, ProjectionAttempt, RebootstrapHandler,
    RootCommitAuthorityProvider, DEFAULT_HYDRATION_TIMEOUT, DEFAULT_MAINTENANCE_RECONCILE_INTERVAL,
};
use crate::peer_session_impl::PeerSyncSessionOneTimeDeps;

use crate::peer_session_impl::PeerSyncSession as InnerPeerSyncSession;

const EXACT_HANDSHAKE_ATTEMPTS: u32 = 4;
const EXACT_HANDSHAKE_BASE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct PeerSyncSessionDeps {
    pub rate_limiters: Arc<RateLimiters>,
    pub block_serve_engine: Arc<BlockServeEngine>,
    pub headroom_override_bytes: Option<u64>,
    pub headroom_enforced: bool,
    pub full_index_resync_interval: Duration,
    pub pending_local_change_flush: Arc<dyn PendingLocalChangeFlush>,
    pub change_authenticator: Arc<dyn ChangeAuthenticator>,
    pub handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
    pub rebootstrap_handler: Arc<dyn RebootstrapHandler>,
    pub block_write_activity_provider: Arc<dyn BlockWriteActivityProvider>,
    pub handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    pub root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
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
            full_index_resync_interval: DEFAULT_MAINTENANCE_RECONCILE_INTERVAL,
            pending_local_change_flush: Arc::new(NoopPendingLocalChangeFlush),
            change_authenticator: Arc::new(DenyAllChangeAuthenticator),
            handoff_lease_responder: Arc::new(DenyHandoffLeaseResponder),
            rebootstrap_handler: Arc::new(DenyRebootstrapHandler),
            block_write_activity_provider: Arc::new(NoopBlockWriteActivityProvider),
            handoff_ticket_responder: Arc::new(DenyHandoffTicketResponder),
            root_commit_authority_provider: Arc::new(DenyRootCommitAuthorityProvider),
            change_emitter: None,
        }
    }

    /// This session's 8 one-time, construction-only capability injections,
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
            change_emitter: self.change_emitter.clone(),
        }
    }
}

pub struct PeerSyncSession {
    inner: Arc<InnerPeerSyncSession>,
    channel: Arc<dyn crate::ports::PeerMessageChannel>,
    codec: yadorilink_sync_wire::ProtobufPeerWireCodec,
    exact_cluster_config: StdMutex<yadorilink_sync_wire::ClusterConfigOutboundFrame>,
    started: AtomicBool,
}

impl PeerSyncSession {
    /// The raw implementation also emits this value. Breaking compatibility is
    /// expressed by requiring the complete current capability set below; using
    /// a wrapper-only generation would be self-contradictory because the inner
    /// session re-announces its own `ClusterConfig` after this preflight.
    pub const PROTOCOL_VERSION: u32 = InnerPeerSyncSession::PROTOCOL_VERSION;

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
        let hints = dependencies.block_serve_engine.advertised_hints();
        let exact_cluster_config = yadorilink_sync_wire::ClusterConfigOutboundFrame {
            folder_group_ids: shared_group_ids.clone(),
            known_peer_device_ids: vec![local_device_id.clone()],
            supported_compression: vec![yadorilink_sync_wire::COMPRESSION_ZSTD],
            supports_reliable_delivery: true,
            acked_peer_cluster_config: false,
            supports_change_dag: true,
            supports_version_present: true,
            supports_version_hash_exact: true,
            max_inflight_requests: hints.max_inflight_requests,
            max_inflight_bytes: hints.max_inflight_bytes,
            available_worker_slots: hints.available_worker_slots,
            estimated_queue_delay_ms: hints.estimated_queue_delay_ms,
            protocol_version: Self::PROTOCOL_VERSION,
        };
        let one_time_deps = dependencies.one_time_deps();
        let inner = InnerPeerSyncSession::new_with_forwarding(
            channel.clone(),
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
        inner.set_full_index_resync_interval(dependencies.full_index_resync_interval);
        Arc::new(Self {
            inner,
            channel,
            codec: yadorilink_sync_wire::ProtobufPeerWireCodec,
            exact_cluster_config: StdMutex::new(exact_cluster_config),
            started: AtomicBool::new(false),
        })
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
        let hints = value.advertised_hints();
        self.inner.set_block_serve_engine(value);
        let mut config = self.exact_cluster_config.lock().unwrap_or_else(|p| p.into_inner());
        config.max_inflight_requests = hints.max_inflight_requests;
        config.max_inflight_bytes = hints.max_inflight_bytes;
        config.available_worker_slots = hints.available_worker_slots;
        config.estimated_queue_delay_ms = hints.estimated_queue_delay_ms;
    }

    pub fn set_headroom_override_bytes(&self, value: Option<u64>) {
        self.assert_not_started();
        self.inner.set_headroom_override_bytes(value);
    }

    pub fn set_headroom_enforced(&self, value: bool) {
        self.assert_not_started();
        self.inner.set_headroom_enforced(value);
    }

    pub fn set_full_index_resync_interval(&self, value: Duration) {
        self.assert_not_started();
        self.inner.set_full_index_resync_interval(value);
    }

    fn validate_exact_peer_config(
        config: &yadorilink_sync_wire::ClusterConfigFrame,
    ) -> Result<(), PeerSessionError> {
        let supports_zstd =
            config.supported_compression.contains(&yadorilink_sync_wire::COMPRESSION_ZSTD);
        let exact = config.protocol_version == Self::PROTOCOL_VERSION
            && config.supports_reliable_delivery
            && config.supports_change_dag
            && config.supports_version_present
            && config.supports_version_hash_exact
            && supports_zstd
            && config.max_inflight_requests > 0
            && config.max_inflight_bytes > 0;
        if exact {
            return Ok(());
        }
        Err(PeerSessionError::InvalidInput(format!(
            "peer protocol is not the exact current generation {}: version={}, reliable={}, \
             dag={}, custody={}, exact_hash={}, zstd={}, max_requests={}, max_bytes={}",
            Self::PROTOCOL_VERSION,
            config.protocol_version,
            config.supports_reliable_delivery,
            config.supports_change_dag,
            config.supports_version_present,
            config.supports_version_hash_exact,
            supports_zstd,
            config.max_inflight_requests,
            config.max_inflight_bytes,
        )))
    }

    async fn exact_generation_preflight(&self) -> Result<(), PeerSessionError> {
        for attempt in 0..EXACT_HANDSHAKE_ATTEMPTS {
            let config =
                self.exact_cluster_config.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let bytes = self
                .codec
                .encode(yadorilink_sync_wire::OutboundFrame::ClusterConfig(config))
                .map_err(|e| PeerSessionError::InvalidInput(e.to_string()))?;
            self.channel.send(bytes).await?;

            let multiplier = 1u32 << attempt.min(2);
            let timeout = EXACT_HANDSHAKE_BASE_TIMEOUT * multiplier;
            match tokio::time::timeout(timeout, self.channel.recv()).await {
                Ok(Some(bytes)) => {
                    let frame = self
                        .codec
                        .decode(bytes.as_slice())
                        .map_err(|e| PeerSessionError::InvalidInput(e.to_string()))?;
                    let config = match frame {
                        yadorilink_sync_wire::InboundFrame::ClusterConfig(config) => config,
                        _ => {
                            return Err(PeerSessionError::InvalidInput(
                                "first peer message was not ClusterConfig".to_string(),
                            ));
                        }
                    };
                    Self::validate_exact_peer_config(&config)?;
                    self.channel.enable_reliable_delivery();
                    return Ok(());
                }
                Ok(None) => {
                    return Err(PeerSessionError::InvalidInput(
                        "peer channel closed before the exact-generation handshake".to_string(),
                    ));
                }
                Err(_) => {}
            }
        }
        Err(PeerSessionError::InvalidInput(
            "peer did not complete the exact-generation handshake after bounded retries"
                .to_string(),
        ))
    }

    pub async fn run(self: Arc<Self>) -> Result<(), PeerSessionError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(PeerSessionError::InvalidInput(
                "PeerSyncSession::run may only be started once".to_string(),
            ));
        }
        self.exact_generation_preflight().await?;
        self.inner.clone().run().await
    }

    pub async fn reconcile_local_materialization_audit(
        self: Arc<Self>,
        group_id: &str,
    ) -> Result<bool, PeerSessionError> {
        self.inner.clone().reconcile_local_materialization_audit(group_id).await
    }

    pub async fn reconcile_paths_directly(
        &self,
        group_id: &str,
        paths: BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        self.inner.reconcile_paths_directly(group_id, paths).await
    }

    /// Whether this peer has advertised support for the
    /// `VersionPresentQuery`/`VersionPresentAck` exchange.
    pub fn version_present_negotiated(&self) -> bool {
        self.inner.version_present_negotiated()
    }

    /// Whether this peer has advertised that its `VersionPresentQuery`
    /// responder enforces an exact `change::VersionHash` match.
    pub fn version_hash_exact_negotiated(&self) -> bool {
        self.inner.version_hash_exact_negotiated()
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

    pub async fn replace_coordination_candidates(&self, candidates: Vec<std::net::SocketAddr>) {
        self.inner.replace_coordination_candidates(candidates).await
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

    /// Whether this session reconciles via the change-history DAG -- reduces
    /// to "has the peer advertised support too."
    pub fn change_dag_negotiated(&self) -> bool {
        self.inner.change_dag_negotiated()
    }

    /// True once the peer has sent any cluster configuration.
    pub fn peer_handshake_received(&self) -> bool {
        self.inner.peer_handshake_received()
    }

    /// Announces this device's current DAG heads for `group_id` to the peer.
    /// Only announces to a peer this session has negotiated the DAG with.
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

    /// Whether this session should compress outgoing block/index payloads
    /// to this peer.
    pub fn compression_negotiated(&self) -> bool {
        self.inner.compression_negotiated()
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
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
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
    fn root_lease_for(&self, _group_id: &str) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        None
    }
}
