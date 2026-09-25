//! The construction-only result of building a `DaemonState`
//! (`DaemonBuild`), used by the composition root (`app::run`) and by test
//! fixtures to sequence "construct state" and "start maintenance" as two
//! separate steps.

use std::sync::Arc;

use tokio::sync::mpsc;
use yadorilink_replica_domain::file::FileRecord;

use crate::daemon_state::DaemonState;

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
