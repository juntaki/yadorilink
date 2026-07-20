//! Library surface for `yadorilink-daemon`, split out so integration tests
//! (and `main.rs`) share the same modules.

pub mod app;
pub mod change_auth;
pub mod change_policy;
pub mod connection_trace;
pub mod control_socket;
pub mod coordination_client;
pub mod daemon_state;
pub mod device_config;
pub mod diagnostics_ipc;
pub mod error;
pub mod gc;
pub mod governance_config;
pub mod hydration;
pub mod link_manager;
pub mod metrics;
pub mod metrics_config;
// NAT traversal binds real UDP sockets, resolves DNS, and probes the local
// gateway — none of which the deterministic simulator models — so the whole
// module is production-only, matching the single (production-gated) place it
// is spawned from in `app`.
#[cfg(not(madsim))]
pub mod nat_traversal;
pub mod peer_orchestrator;
pub mod pending_enrollment;
pub mod rebootstrap_handler;
pub mod recent_errors;
pub mod reporting;
pub mod reporting_ipc;
// Exclusive OS locks on the block-store root and sync-state database. Not built
// under the deterministic simulator, whose many in-process daemon instances use
// isolated per-instance paths and must not contend on real filesystem locks.
#[cfg(not(madsim))]
pub mod resource_lock;
pub mod shell_ipc;
pub mod shell_status;
pub mod supervise;
#[cfg(test)]
pub(crate) mod test_support;
pub mod token_store;
pub mod transfer_progress;
pub mod update;
pub mod update_ipc;
#[cfg(windows)]
pub mod windows_pipe_security;
