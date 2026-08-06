//! Production [`PlaceholderPipelineCapabilityPort`] -- delegates to
//! `DaemonState::on_demand_pipeline_is_connected`, which itself falls
//! through to `yadorilink_filesystem_sync::placeholder_backend::
//! on_demand_pipeline_is_connected` (unconditionally `false` in every real
//! build) unless a test override is set. Routing through `DaemonState`
//! rather than calling the free function directly means
//! `set_test_placeholder_pipeline_connected` reaches this port AND
//! `hydration::evict`'s own direct call to the same `DaemonState` method
//! uniformly, from one override -- see that method's own doc comment.

use std::sync::Arc;

use crate::application::ports::PlaceholderPipelineCapabilityPort;
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonPlaceholderPipelineAdapter {
    state: Arc<DaemonState>,
}

impl DaemonPlaceholderPipelineAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl PlaceholderPipelineCapabilityPort for DaemonPlaceholderPipelineAdapter {
    fn is_connected(&self) -> bool {
        self.state.on_demand_pipeline_is_connected()
    }
}
