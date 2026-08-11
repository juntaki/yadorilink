//! Library surface for `yadorilink-daemon`, split out so integration tests
//! (and `main.rs`) share the same modules.

pub mod adapters;
pub mod app;
pub mod application;
pub mod change_auth;
pub mod change_policy;
pub mod commit_orchestration;
pub mod connection_trace;
pub mod control_context;
pub mod control_socket;
pub mod convergence;
pub mod coordination_client;
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
pub mod hydration;
pub mod link_registry;
pub mod link_runtime;
pub(crate) mod local_session_channel;
pub(crate) mod maintenance;
pub mod maintenance_coordinator;
pub mod materialization_intent;
pub mod metrics;
pub mod metrics_config;
// NAT traversal binds real UDP sockets, resolves DNS, and probes the local
// gateway — none of which the deterministic simulator models — so the whole
// module is production-only, matching the single (production-gated) place it
// is spawned from in `app`.
#[cfg(not(madsim))]
pub mod nat_traversal;
pub mod peer_orchestrator;
pub mod peer_registry;
pub mod queries;
pub mod rebootstrap_handler;
pub mod recent_errors;
pub mod recovery;
pub mod recovery_diagnosis;
pub mod recovery_evidence;
pub mod recovery_snapshot;
/// `ReplicaCoordinator` (Phase 7D-10.2) -- see that module's own doc
/// comment for what it is and why it is additive alongside `SyncState`,
/// not a replacement for it, in this sub-phase.
pub mod replica_coordinator;
pub mod reporting;
pub mod reporting_ipc;
pub mod reporting_retry;
pub mod root_commit_authority;
pub mod runtime_telemetry;
pub mod sync_runtime;
// Exclusive OS locks on the block-store root and sync-state database. Not built
// under the deterministic simulator, whose many in-process daemon instances use
// isolated per-instance paths and must not contend on real filesystem locks.
#[cfg(windows)]
pub mod placeholder_backend_windows;
#[cfg(windows)]
pub mod placeholder_inspect_windows;
#[cfg(not(madsim))]
pub mod resource_lock;
pub mod shell_ipc;
pub mod shell_status;
pub mod supervise;
pub mod sync_error;
#[cfg(test)]
pub(crate) mod test_support;
pub mod token_store;
pub mod transfer_progress;
pub mod update;
pub mod update_ipc;
#[cfg(windows)]
pub mod windows_pipe_security;
pub mod work_class_queue;
