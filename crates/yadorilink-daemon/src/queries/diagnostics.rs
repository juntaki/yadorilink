//! `ConnectivityDoctor`/`ListConnectionTraces`/
//! `ListLanDiscoveredCandidates`'s read model. Like
//! `crate::queries::health`, this slice's dependencies (`RuntimeTelemetry`,
//! `SyncState`, `ObservationLog`, `PeerRegistry`, and the
//! `LanCandidateObserver` cell) are already narrow/cheap-clone owner
//! types, so no `DaemonState` strangler adapter is needed at all.

use std::sync::Arc;

use yadorilink_transport::ObservationLog;

use crate::connection_trace::DoctorCategory;
use crate::peer_orchestrator::LanCandidateObserver;
use crate::peer_registry::PeerRegistry;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::runtime_telemetry::RuntimeTelemetry;

pub(crate) struct DiagnosticsQueryService {
    telemetry: Arc<RuntimeTelemetry>,
    sync_state: Arc<ReplicaCoordinator>,
    nat_observations: ObservationLog,
    /// See `DaemonState::lan_candidate_observer`. Empty until
    /// `peer_orchestrator::run` has published one, which is why this is the
    /// cell rather than the view: the control socket is answering requests
    /// well before -- and, on a daemon that never reaches the peer
    /// orchestrator at all, instead of -- that publication.
    lan_candidates: Arc<tokio::sync::OnceCell<LanCandidateObserver>>,
    peers: Arc<PeerRegistry>,
}

impl DiagnosticsQueryService {
    pub(crate) fn new(
        telemetry: Arc<RuntimeTelemetry>,
        sync_state: Arc<ReplicaCoordinator>,
        nat_observations: ObservationLog,
        lan_candidates: Arc<tokio::sync::OnceCell<LanCandidateObserver>>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        Self { telemetry, sync_state, nat_observations, lan_candidates, peers }
    }

    pub(crate) fn connectivity_doctor(&self) -> Vec<DoctorCategory> {
        crate::connection_trace::run_connectivity_doctor(
            &self.telemetry,
            &self.sync_state,
            &self.nat_observations,
        )
    }

    pub(crate) fn recent_connection_traces(
        &self,
        peer_device_id: Option<&str>,
    ) -> Vec<crate::connection_trace::ConnectionAttemptTrace> {
        self.telemetry.recent_connection_attempts(peer_device_id)
    }

    /// The LAN-discovered addresses this device is currently holding as
    /// dial candidates -- the announced-but-not-necessarily-connected half
    /// of LAN troubleshooting, which `recent_connection_traces` above
    /// cannot show because a trace exists only once an attempt has
    /// resolved. Empty before `peer_orchestrator::run` has published its
    /// observer.
    pub(crate) fn lan_discovered_candidates(
        &self,
        peer_device_id: Option<&str>,
    ) -> Vec<crate::connection_trace::LanDiscoveredCandidate> {
        let peers = self.peers.clone();
        self.lan_candidates
            .get()
            .map(|observer| observer.snapshot(peer_device_id, &move |peer| peers.has_session(peer)))
            .unwrap_or_default()
    }
}
