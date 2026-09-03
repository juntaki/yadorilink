//! Concrete implementations of `application`'s ports, plus the composition
//! root (`build_application_services`) that wires them together from a real
//! `Arc<DaemonState>`. Deliberately a SIBLING of `application`, not nested
//! under it: `application` owns the port TRAITS; it must never appear to
//! own their implementations too, or the dependency direction this whole
//! module tree exists to enforce (`application` -> ports only, adapters ->
//! application + concrete infrastructure) would be backwards for anyone
//! reading the tree alone.
//!
//! Phase 2 Commit 2: `control_socket::handle_request` calls this once per
//! request (not once per daemon lifetime -- see `DaemonContext`'s own doc
//! comment for why the fuller "build exactly once, thread a context
//! through the transport layer" shape is deferred rather than landed here).
//! The cost is a handful of `Arc::clone`s, no I/O, so building it fresh per
//! request is cheap.

pub mod block_store_ports;
mod coordination;
mod persistence;
pub(crate) mod query;
pub mod runtime;

use std::sync::Arc;

use crate::application::{
    ApplicationServices, DaemonLifecycleService, DurabilityCommandService,
    EnrollmentRecoveryService, EnrollmentService, GcCommandService, GovernanceCommandService,
    HandoffCommandService, LinkLifecycleService, MaterializationService, PauseResumeService,
    ReplicaMembershipService, ReplicaRoleService, ReportingCommandService, UpdateCommandService,
    VersionRestoreService,
};
use crate::daemon_state::DaemonState;
use crate::queries::link_status::LinkStatusQueryService;
use crate::queries::QueryServices;

pub(crate) fn build_application_services(state: Arc<DaemonState>) -> Arc<ApplicationServices> {
    let controller =
        Arc::new(runtime::link_runtime_controller::LinkRuntimeController::new(state.clone()));

    let link_lifecycle = Arc::new(LinkLifecycleService::new(
        Arc::new(runtime::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(runtime::link_lifecycle::DaemonLinkWatcherAdapter::new(
            state.clone(),
            controller.clone(),
        )),
    ));

    let enrollment_repository =
        Arc::new(persistence::enrollment::SyncStateEnrollmentRepository::new(
            state.replica_coordinator.clone(),
        ));
    let enrollment_coordination =
        Arc::new(coordination::enrollment::HttpEnrollmentCoordination::new(state.clone()));
    let enrollment_link = Arc::new(runtime::enrollment_link::DaemonEnrollmentLinkAdapter::new(
        state.clone(),
        link_lifecycle.clone(),
        controller.clone(),
    ));
    let enrollment_attempts =
        Arc::new(runtime::enrollment_attempts::DaemonEnrollmentAttemptTracker::new(state.clone()));

    let enrollment = Arc::new(EnrollmentService::new(
        state.device_id.clone(),
        enrollment_repository.clone(),
        enrollment_coordination.clone(),
        enrollment_link.clone(),
    ));
    let enrollment_recovery = Arc::new(EnrollmentRecoveryService::new(
        enrollment_repository,
        enrollment_coordination,
        enrollment_link,
        enrollment_attempts,
    ));

    let materialization_port =
        Arc::new(runtime::materialization::DaemonMaterializationAdapter::new(state.clone()));
    let materialization = Arc::new(MaterializationService::new(materialization_port));

    let membership_repository =
        Arc::new(persistence::membership::SyncStateMembershipRepository::new(state.clone()));
    let membership_coordination =
        Arc::new(coordination::membership::HttpMembershipCoordination::new(state.clone()));
    let handoff_tickets =
        Arc::new(runtime::handoff_ticket::DaemonHandoffTicketAdapter::new(state.clone()));
    let replica_readiness =
        Arc::new(runtime::replica_readiness::DaemonReplicaReadinessAdapter::new(state.clone()));
    let membership = Arc::new(ReplicaMembershipService::new(
        state.device_id.clone(),
        membership_repository,
        membership_coordination,
        handoff_tickets,
        replica_readiness,
    ));

    let replica_role_repository =
        Arc::new(persistence::replica_role::SyncStateReplicaRoleRepository::new(state.clone()));
    let role_loss_journal =
        Arc::new(runtime::role_loss_journal::DaemonRoleLossJournal::new(state.clone()));
    let handoff_readiness =
        Arc::new(runtime::handoff_readiness::DaemonHandoffReadinessAdapter::new(state.clone()));
    let role_loss_coordination =
        Arc::new(coordination::role_loss::HttpRoleLossCoordination::new(state.clone()));
    let link_runtime =
        Arc::new(runtime::link_watch::DaemonLinkRuntimeAdapter::new(controller.clone()));
    let placeholder_pipeline = Arc::new(
        runtime::placeholder_pipeline::DaemonPlaceholderPipelineAdapter::new(state.clone()),
    );
    let replica_role = Arc::new(ReplicaRoleService::new(
        state.device_id.clone(),
        replica_role_repository,
        role_loss_journal,
        handoff_readiness,
        role_loss_coordination,
        link_runtime,
        placeholder_pipeline,
    ));

    let pause_resume = Arc::new(PauseResumeService::new(Arc::new(
        runtime::runtime_control::DaemonPauseResumeAdapter::new(state.clone(), controller.clone()),
    )));
    let gc = Arc::new(GcCommandService::new(Arc::new(
        runtime::runtime_control::DaemonGcAdapter::new(state.clone()),
    )));
    let lifecycle = Arc::new(DaemonLifecycleService::new(Arc::new(
        runtime::runtime_control::DaemonLifecycleAdapter::new(state.clone()),
    )));
    let durability = Arc::new(DurabilityCommandService::new(Arc::new(
        runtime::handoff::DaemonDurabilityCommandAdapter::new(state.clone()),
    )));
    let handoff = Arc::new(HandoffCommandService::new(Arc::new(
        runtime::handoff::DaemonHandoffCommandAdapter::new(state.clone()),
    )));
    let version_restore = Arc::new(VersionRestoreService::new(Arc::new(
        runtime::version_restore::DaemonVersionRestoreAdapter::new(state.clone()),
    )));
    let governance = Arc::new(GovernanceCommandService::new(Arc::new(
        runtime::governance::DaemonGovernanceCommandAdapter::new(
            state.governance_config.clone(),
            state.rate_limiters.clone(),
            state.block_store.clone(),
        ),
    )));
    let reporting = Arc::new(ReportingCommandService::new(Arc::new(
        runtime::reporting::DaemonReportingCommandAdapter::new(state.reporting.clone()),
    )));
    let update = Arc::new(UpdateCommandService::new(Arc::new(
        runtime::update::DaemonUpdateCommandAdapter::new(state.clone()),
    )));

    Arc::new(ApplicationServices {
        enrollment,
        enrollment_recovery,
        materialization,
        membership,
        replica_role,
        pause_resume,
        gc,
        lifecycle,
        durability,
        handoff,
        version_restore,
        governance,
        reporting,
        update,
        link_lifecycle,
    })
}

pub(crate) fn build_query_services(state: Arc<DaemonState>) -> Arc<QueryServices> {
    let health = Arc::new(crate::queries::health::HealthQueryService::new(
        state.telemetry.clone(),
        state.peers.clone(),
    ));
    let diagnostics = Arc::new(crate::queries::diagnostics::DiagnosticsQueryService::new(
        state.telemetry.clone(),
        state.replica_coordinator.clone(),
        state.nat_observations.clone(),
    ));
    let update_status = Arc::new(crate::queries::update_status::UpdateStatusQueryService::new(
        state.update_manager.clone(),
    ));
    let link_status_reader =
        Arc::new(query::link_status::DaemonLinkStatusReader::new(state.clone()));
    let link_status = Arc::new(LinkStatusQueryService::new(link_status_reader));
    let runtime_status = Arc::new(crate::queries::runtime_status::RuntimeStatusQueryService::new(
        link_status.clone(),
        update_status.clone(),
        state.peers.clone(),
        state.clone() as Arc<dyn crate::queries::runtime_status::RelayCapabilityPort>,
        state.telemetry.clone(),
        state.governance_config.clone(),
        state.block_store.clone(),
        state.gc.clone(),
        state.rate_limiters.clone(),
    ));
    let linked_path = Arc::new(crate::queries::linked_path::LinkedPathResolver::new(
        state.replica_coordinator.clone(),
    ));
    let file_history = Arc::new(crate::queries::file_history::FileHistoryQueryService::new(
        state.replica_coordinator.clone(),
        linked_path.clone(),
    ));
    let governance = Arc::new(crate::queries::governance::GovernanceQueryService::new(
        state.governance_config.clone(),
    ));
    let reporting =
        Arc::new(crate::queries::reporting::ReportingQueryService::new(state.reporting.clone()));
    let coordination_config =
        Arc::new(query::recovery::DaemonCoordinationConfig::new(state.clone()));
    let recovery = Arc::new(crate::queries::recovery::RecoveryQueryService::new(
        state.replica_coordinator.clone(),
        coordination_config,
    ));

    let diagnostics_bundle =
        Arc::new(crate::queries::diagnostics_bundle::DiagnosticsBundleQueryService::new(
            Arc::new(query::diagnostics_bundle::DaemonRuntimeDiagnostics::new(
                state.clone(),
                link_status.clone(),
                runtime_status.clone(),
                state.governance_config.clone(),
            )),
            Arc::new(query::diagnostics_bundle::DaemonHealthDiagnostics::new(health.clone())),
            Arc::new(query::diagnostics_bundle::DaemonUpdateDiagnostics::new(
                update_status.clone(),
            )),
            Arc::new(query::diagnostics_bundle::DaemonConfigurationDiagnostics::new(
                update_status.clone(),
            )),
            Arc::new(query::diagnostics_bundle::DaemonLogDiagnostics::new(state.reporting.clone())),
        ));

    let handoff_readiness =
        Arc::new(crate::queries::handoff_readiness::HandoffReadinessQueryService::new(Arc::new(
            query::handoff_readiness::DaemonHandoffReadinessReader::new(state.clone()),
        )));

    Arc::new(QueryServices {
        link_status,
        health,
        diagnostics,
        runtime_status,
        linked_path,
        file_history,
        governance,
        reporting,
        recovery,
        diagnostics_bundle,
        handoff_readiness,
        update_status,
    })
}

#[cfg(test)]
mod ports_reachability {
    //! Proof that `yadorilink-daemon` composes every capability port: each
    //! port trait is nameable from this crate, and constructible as
    //! `Arc<dyn Trait>` from a real production type this crate already
    //! holds (`ReplicaCoordinator`, this crate's `BlockStorePortsAdapter`
    //! wrapping its actual `BlockStore` instance type, and `PeerChannel`).
    //! No consumer switches to holding these traits yet -- this only
    //! establishes the composition seam is real and compiles, which is what
    //! activating the ports requires before any consumer migration can
    //! follow.

    use std::sync::Arc;

    use crate::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_capture::ports::LocalMutationStore;
    use yadorilink_local_storage::{BlockContentStore, BlockReclamationStore};
    use yadorilink_peer_session::ports::{PeerMessageChannel, PeerReplicaStatePort};
    use yadorilink_sync_sqlite::MaterializationStatePort;

    use crate::adapters::block_store_ports::BlockStorePortsAdapter;

    #[tokio::test]
    async fn every_capability_port_is_constructible_from_daemon_types() {
        // `ReplicaCoordinator` backs all three of `PeerReplicaStatePort`/
        // `MaterializationStatePort`/`LocalMutationStore` directly
        // (`replica_coordinator/{peer_replica_state,materialization_state,
        // local_mutation}.rs`) -- `SyncState` backed the first two during
        // the transitional coexistence period before Phase 7D-10's final
        // sync-core deletion pass, but `ReplicaCoordinator` is now this
        // crate's sole implementor of all three.
        let coordinator: Arc<ReplicaCoordinator> =
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let _peer_replica: Arc<dyn PeerReplicaStatePort> = coordinator.clone();
        let _materialization: Arc<dyn MaterializationStatePort> = coordinator.clone();
        let _local_mutation: Arc<dyn LocalMutationStore> = coordinator;

        // The daemon's actual `block_store` type is already type-erased to
        // `Arc<dyn BlockStore + Send + Sync>`, which needs
        // `BlockStorePortsAdapter` (not a direct coercion -- see that
        // module's doc comment) to reach these two ports.
        let dir = tempfile::tempdir().unwrap();
        let block_store: Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync> =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(dir.path()).unwrap());
        let _block_content: Arc<dyn BlockContentStore> =
            Arc::new(BlockStorePortsAdapter::new(block_store.clone()));
        let _block_reclamation: Arc<dyn BlockReclamationStore> =
            Arc::new(BlockStorePortsAdapter::new(block_store));

        // `QuicPeerChannel` backs `PeerMessageChannel` directly. Proving the
        // coercion needs a real connection, since a QUIC channel wraps one
        // that has already completed a handshake.
        use yadorilink_transport::{
            ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint, TransportHub,
        };
        let dialer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let acceptor_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let acceptor_addr = acceptor_socket.local_addr().unwrap();
        let dialer_key = DeviceSigningKeyPair::generate();
        let acceptor_key = DeviceSigningKeyPair::generate();
        let dialer_public = dialer_key.public_bytes();
        let acceptor_public = acceptor_key.public_bytes();
        let dialer =
            QuicPeerEndpoint::new(TransportHub::from_socket(dialer_socket), dialer_key).unwrap();
        let acceptor =
            QuicPeerEndpoint::new(TransportHub::from_socket(acceptor_socket), acceptor_key)
                .unwrap();
        dialer.authorize(acceptor_public);
        acceptor.authorize(dialer_public);
        let connection = dialer.connect(acceptor_addr, acceptor_public).await.unwrap();
        let channel = QuicPeerChannel::new(connection, ConnectRole::Dial);
        let _peer_message: Arc<dyn PeerMessageChannel> = channel;
    }
}
