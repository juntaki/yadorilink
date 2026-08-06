//! The runtime-owner component bundle (`RuntimeComponents`) and the
//! construction-only result of building a `DaemonState`
//! (`DaemonBuild`) -- used by the composition root (`app::run`) and by
//! test fixtures that need direct `Arc` handles to the owner components
//! rather than reaching through `DaemonState` for everything. Neither type
//! is a service locator: `RuntimeComponents` is a plain field bundle
//! handed to whichever adapters/services actually need one or two of its
//! fields, not passed around wholesale as a stand-in for `DaemonState`.

use std::sync::Arc;

use tokio::sync::mpsc;
use yadorilink_replica_domain::file::FileRecord;

use crate::daemon_state::DaemonState;
use crate::durability_service::DurabilityService;
use crate::link_registry::LinkRegistry;
use crate::peer_registry::PeerRegistry;
use crate::runtime_telemetry::RuntimeTelemetry;

/// `Arc` handles to every runtime-owner component a `DaemonState` builds.
/// See [`DaemonState::runtime_components`]. Not consumed yet in this
/// commit -- `QueryServices`/the composition-root split (next commits)
/// are its first real callers.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct RuntimeComponents {
    pub(crate) peers: Arc<PeerRegistry>,
    pub(crate) links: Arc<LinkRegistry>,
    pub(crate) telemetry: Arc<RuntimeTelemetry>,
    pub(crate) durability: Arc<DurabilityService>,
}

/// The result of [`DaemonState::build`]: `state` itself, fully constructed
/// with zero background-task side effects, plus the receiver half of its
/// forwarding channel that [`crate::maintenance_coordinator::start`] needs
/// to actually start those tasks. Splitting these two lets a composition
/// root sequence "construct state" and "start maintenance" as two
/// explicit, separately-orderable steps instead of one constructor that
/// always does both.
pub(crate) struct DaemonBuild {
    pub(crate) state: Arc<DaemonState>,
    pub(crate) forward_rx: mpsc::UnboundedReceiver<(String, FileRecord)>,
}
