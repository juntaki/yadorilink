//! `ConnectivityDoctor`/`ListConnectionTraces`'s read model. Like
//! `crate::queries::health`, this slice's dependencies (`RuntimeTelemetry`
//! and `SyncState`) are already narrow/cheap-clone owner types, so no
//! `DaemonState` strangler adapter is needed at all.

use std::sync::Arc;

use crate::connection_trace::DoctorCategory;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::runtime_telemetry::RuntimeTelemetry;

pub(crate) struct DiagnosticsQueryService {
    telemetry: Arc<RuntimeTelemetry>,
    sync_state: Arc<ReplicaCoordinator>,
    device_id: String,
}

impl DiagnosticsQueryService {
    pub(crate) fn new(
        telemetry: Arc<RuntimeTelemetry>,
        sync_state: Arc<ReplicaCoordinator>,
        device_id: String,
    ) -> Self {
        Self { telemetry, sync_state, device_id }
    }

    pub(crate) fn connectivity_doctor(&self) -> Vec<DoctorCategory> {
        crate::connection_trace::run_connectivity_doctor(
            &self.telemetry,
            &self.sync_state,
            &self.device_id,
        )
    }

    pub(crate) fn recent_connection_traces(
        &self,
        peer_device_id: Option<&str>,
    ) -> Vec<crate::connection_trace::ConnectionAttemptTrace> {
        self.telemetry.recent_connection_attempts(peer_device_id)
    }
}
