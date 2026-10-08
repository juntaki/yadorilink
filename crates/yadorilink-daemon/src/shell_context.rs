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
    /// The host app's end of the provider channel and the publication machine behind it.
    pub(crate) provider_host: Arc<crate::provider_host_link::ProviderHostLink>,
    pub(crate) publication: Arc<crate::provider_publication::PublicationDriver>,
    /// What the host app last reported the OS holds locally, per root.
    pub(crate) membership: Arc<crate::provider_evidence::ProviderMembership>,
    /// The fixed directory provider items are handed over in; `None` when the daemon was not
    /// given one (a provider root is then never ready to materialize).
    pub(crate) handoff: Arc<crate::provider_handoff::HandoffSlot>,
    /// Which Eager downloads the host app should request next, and the daemon-wide limit on
    /// concurrent assemblies.
    pub(crate) eager: Arc<crate::provider_eager::EagerDriver>,
    /// The idle-only breadth-first prefetch of provider roots.
    pub(crate) prefetch: Arc<crate::provider_prefetch::PrefetchScheduler>,
    /// The author identity, block store and authoring lease the provider write path uses.
    pub(crate) writer: Arc<crate::provider_writer::ProviderWriter>,
}

/// The machine facts the Eager driver reads, from the daemon's own state.
struct DaemonEagerEnvironment {
    state: Arc<crate::daemon_state::DaemonState>,
}

impl crate::provider_eager::EagerEnvironment for DaemonEagerEnvironment {
    fn low_disk(&self, dir: &std::path::Path, bytes: u64) -> bool {
        if !self.state.disk_headroom_enforcement_enabled() {
            return false;
        }
        let headroom_override =
            self.state.governance_config.load_or_default().headroom_override_bytes;
        crate::local_convergence::reserve_volume_headroom(dir, dir, bytes, headroom_override)
            .is_err()
    }

    fn peers_available(&self, group_id: &str) -> bool {
        !crate::hydration::candidate_sessions(&self.state, group_id).is_empty()
    }
}

impl ShellContext {
    /// Production construction: `application`/`queries` are the SAME
    /// instances the control socket's `ControlContext` holds, so the shell
    /// extension and the CLI share one materialization service.
    pub(crate) fn new(
        control: &crate::control_context::ControlContext,
        state: &Arc<crate::daemon_state::DaemonState>,
    ) -> Self {
        let provider_host = Arc::new(crate::provider_host_link::ProviderHostLink::default());
        let eager = Arc::new(crate::provider_eager::EagerDriver::new(
            Arc::new(DaemonEagerEnvironment { state: state.clone() }),
            crate::provider_eager::EagerConfig::default(),
        ));
        let membership: Arc<crate::provider_evidence::ProviderMembership> = Arc::default();
        {
            let (coordinator, eager, membership, host) = (
                state.replica_coordinator.clone(),
                eager.clone(),
                membership.clone(),
                provider_host.clone(),
            );
            let extras_coordinator = coordinator.clone();
            let extras_host = host.clone();
            control.provider_status.install_extras(Arc::new(move || {
                let removals = extras_coordinator
                    .provider_repository()
                    .removals()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| yadorilink_ipc_proto::daemonctl::ProviderRemovalStatus {
                        root_id: r.root_id.chars().take(8).collect(),
                        display_name: r.display_name,
                        removed: !r.requested,
                        preserved_location: r.preserved_location.unwrap_or_default(),
                    })
                    .collect();
                let orphans = extras_host
                    .orphans()
                    .into_iter()
                    .map(|id| id.chars().take(8).collect())
                    .collect();
                (removals, orphans)
            }));
            let pending_coordinator = coordinator.clone();
            control.provider_status.install_pending(Arc::new(move |limit| {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as i64);
                crate::provider_status::pending_items(&pending_coordinator, limit, now_ms)
            }));
            control.provider_status.install(Arc::new(move || {
                let root = host.handoff_root();
                let inputs = crate::provider_eager::EagerInputs {
                    coordinator: &coordinator,
                    membership: &membership,
                    staging_dir: root.as_ref().map(|h| h.staging_dir()),
                    host_attached: host.host_connected(),
                };
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as i64);
                crate::provider_status::provider_root_lines(&coordinator, &eager, &inputs, now_ms)
            }));
        }
        Self {
            application: control.application.clone(),
            queries: control.queries.clone(),
            replica_coordinator: state.replica_coordinator.clone(),
            links: state.links.clone(),
            telemetry: state.telemetry.clone(),
            publication: Arc::new(crate::provider_publication::PublicationDriver::new(
                state.replica_coordinator.clone(),
                provider_host.clone(),
                crate::provider_publication::PublicationConfig::for_shell_context(),
            )),
            provider_host,
            membership,
            handoff: crate::provider_handoff::HandoffSlot::empty(),
            writer: Arc::new(crate::provider_writer::ProviderWriter::new(state.clone())),
            eager,
            prefetch: Arc::new(crate::provider_prefetch::PrefetchScheduler::new(
                crate::provider_prefetch::PrefetchConfig::default(),
            )),
        }
    }

    /// Replaces the Eager driver (tests give it a fake environment and short timings).
    #[cfg(test)]
    pub(crate) fn with_eager(mut self, eager: Arc<crate::provider_eager::EagerDriver>) -> Self {
        self.eager = eager;
        self
    }

    /// Gives the context the daemon's fixed handoff root.
    #[cfg(test)]
    pub(crate) fn with_handoff_root(
        self,
        root: Option<Arc<crate::provider_handoff::HandoffRoot>>,
    ) -> Self {
        self.with_handoff_slot(crate::provider_handoff::HandoffSlot::fixed(root))
    }

    /// Gives the context a handoff root that is resolved lazily (see `HandoffSlot`).
    pub(crate) fn with_handoff_slot(
        mut self,
        slot: Arc<crate::provider_handoff::HandoffSlot>,
    ) -> Self {
        self.provider_host.set_handoff_slot(slot.clone());
        self.handoff = slot;
        self
    }

    /// For test call sites that only have a `DaemonState` to start from --
    /// same composition as `ControlContext::from_state`.
    pub fn from_state(state: Arc<crate::daemon_state::DaemonState>) -> Self {
        let control = crate::control_context::ControlContext::from_state(state.clone());
        Self::new(&control, &state)
    }
}
