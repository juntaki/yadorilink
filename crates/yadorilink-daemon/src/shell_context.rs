//! Everything the shell-extension IPC handlers (`shell_ipc`) may reach,
//! built once by the composition root (`app.rs`) and handed down through
//! every connection -- the shell-extension counterpart of
//! `ControlContext`. Deliberately has NO `Arc<DaemonState>` field:
//!
//! - hydrate / pin / evict go through the same `ApplicationServices`
//!   materialization operations the control socket drives for
//!   `yadorilink hydrate`/`pin`/`evict`, and absolute paths resolve through
//!   the same `LinkedPathResolver` query, so a shell context-menu action and
//!   the equivalent CLI command can never diverge;
//! - `replica_coordinator` is used for read-only snapshots (overlay status,
//!   on-demand folder and per-folder file listings);
//! - `links` reaches a running link's own entry points (a File Provider
//!   local-write notification is captured exactly like a watcher event,
//!   and a Windows placeholder generation is minted by the runtime that
//!   owns it) -- never the sync engine's state directly;
//! - `telemetry` supplies the status-push stream.
//!
//! Per-item pause/resume goes through `application.pause_resume`, like the
//! control socket's link-level pause: the pause is durable daemon state
//! owned there, not something this context holds.
//!
//! A future handler that seems to need `DaemonState` directly is a signal
//! to route it through an application service or query instead, not to
//! widen this struct.
//!
//! `pub`, not `pub(crate)`: `shell_ipc::*_transport::serve` are themselves
//! `pub` (the integration tests under `tests/` call them directly), so
//! their `Arc<ShellContext>` parameter must be constructible from outside
//! this crate too -- see `from_state`.

use std::sync::Arc;

use crate::application::ApplicationServices;
use crate::link_registry::LinkRegistry;
use crate::queries::QueryServices;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::runtime_telemetry::RuntimeTelemetry;

pub struct ShellContext {
    pub(crate) application: Arc<ApplicationServices>,
    pub(crate) queries: Arc<QueryServices>,
    pub(crate) replica_coordinator: Arc<ReplicaCoordinator>,
    pub(crate) links: Arc<LinkRegistry>,
    pub(crate) telemetry: Arc<RuntimeTelemetry>,
}

impl ShellContext {
    /// Production construction: `application`/`queries` are the SAME
    /// instances the control socket's `ControlContext` holds, so the shell
    /// extension and the CLI share one materialization service.
    pub(crate) fn new(
        control: &crate::control_context::ControlContext,
        state: &crate::daemon_state::DaemonState,
    ) -> Self {
        Self {
            application: control.application.clone(),
            queries: control.queries.clone(),
            replica_coordinator: state.replica_coordinator.clone(),
            links: state.links.clone(),
            telemetry: state.telemetry.clone(),
        }
    }

    /// For test call sites that only have a `DaemonState` to start from --
    /// same composition as `ControlContext::from_state`.
    pub fn from_state(state: Arc<crate::daemon_state::DaemonState>) -> Self {
        let control = crate::control_context::ControlContext::from_state(state.clone());
        Self::new(&control, &state)
    }
}
