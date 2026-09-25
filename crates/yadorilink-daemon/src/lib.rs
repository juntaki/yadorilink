//! Library surface for `yadorilink-daemon`, split out so integration tests
//! (and `main.rs`) share the same modules.

pub mod adapters;
pub mod app;
pub mod application;
pub mod background_custody;
pub mod change_auth;
pub mod change_policy;
pub mod checkpoint_source;
pub mod connection_trace;
pub mod control_context;
pub mod control_socket;
pub mod convergence;
pub mod coordination_client;
pub mod credential_store;
pub mod daemon_runtime;
pub mod daemon_state;
pub mod dag_import;
pub mod device_config;
pub mod diagnostics_ipc;
pub mod durability_service;
pub mod error;
pub mod gc;
pub mod gc_state;
pub mod governance_config;
pub mod handoff_proof;
pub mod hydration;
pub mod hydration_single_flight;
pub mod link_registry;
pub mod link_runtime;
pub mod local_convergence;
pub(crate) mod maintenance;
pub mod maintenance_coordinator;
pub mod materialization_intent;
pub mod metrics;
#[cfg(test)]
pub(crate) mod obligation_tick_metrics;
pub mod path_witness_sink;
pub mod peer_connectivity_runtime;
pub mod peer_orchestrator;
pub mod peer_registry;
#[cfg(windows)]
pub mod placeholder_backend_windows;
#[cfg(windows)]
pub mod placeholder_dehydrate_windows;
#[cfg(windows)]
pub mod placeholder_inspect_windows;
pub mod queries;
pub mod rebootstrap_handler;
pub mod recent_errors;
pub mod recovery;
pub mod recovery_diagnosis;
pub mod recovery_evidence;
pub mod recovery_snapshot;
/// `ReplicaCoordinator` -- see that module's own doc comment for what it
/// is.
pub mod replica_coordinator;
pub mod reporting;
pub mod reporting_ipc;
pub mod reporting_retry;
pub mod rewind;
pub mod root_commit_authority;
pub mod route;
pub mod runtime_telemetry;
pub mod sync_adapter;
pub mod sync_runtime;
pub mod write_lease;
// Exclusive OS locks on the block-store root and sync-state database.
pub mod resource_lock;
pub mod send_transfer;
pub mod shell_context;
pub mod shell_ipc;
pub mod shell_status;
pub mod supervise;
pub mod sync_error;
// Test-harness boundary, not product surface. `peer_session_fixture` is the
// `ReplicaCoordinator`-backed peer-session fixture, shared during the test
// ownership move with `yadorilink-peer-session`'s own integration binaries
// through their existing dev-dependency on this crate. Nothing outside these
// two cfgs can name anything in here.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod transfer_progress;
pub mod update;
pub mod update_ipc;
#[cfg(windows)]
pub mod windows_pipe_security;
