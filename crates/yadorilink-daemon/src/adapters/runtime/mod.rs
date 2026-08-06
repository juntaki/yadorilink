//! `DaemonState`/`LinkRuntimeController`/`hydration`-backed implementations of the
//! remaining application ports (local link commit, materialization,
//! handoff leases, replica-role local runtime actions) -- everything that
//! isn't durable-storage or coordination-plane HTTP. Populated alongside
//! each service's own Phase 2 commit.

pub(crate) mod custody;
pub(crate) mod enrollment_attempts;
pub(crate) mod enrollment_link;
pub(crate) mod governance;
pub(crate) mod handoff;
pub(crate) mod handoff_readiness;
pub(crate) mod handoff_ticket;
pub(crate) mod link_lifecycle;
pub mod link_runtime_controller;
pub(crate) mod link_watch;
pub(crate) mod materialization;
pub(crate) mod placeholder_pipeline;
pub(crate) mod replica_readiness;
pub(crate) mod reporting;
pub(crate) mod role_loss_journal;
pub(crate) mod runtime_control;
pub(crate) mod update;
pub(crate) mod version_restore;
