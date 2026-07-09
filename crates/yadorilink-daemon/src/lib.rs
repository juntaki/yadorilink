//! Library surface for `yadorilink-daemon`, split out so integration tests
//! (and `main.rs`) share the same modules.

pub mod connection_trace;
pub mod control_socket;
pub mod daemon_state;
pub mod device_config;
pub mod diagnostics_ipc;
pub mod error;
pub mod folder_ops;
pub mod gc;
pub mod governance_config;
pub mod hydration;
pub mod link_manager;
pub mod metrics;
pub mod metrics_config;
pub mod peer_orchestrator;
pub mod recent_errors;
pub mod reporting;
pub mod reporting_ipc;
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
