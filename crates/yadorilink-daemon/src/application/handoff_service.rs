use std::sync::Arc;

use crate::sync_error::SyncError;

use super::ports::{
    DurabilityCommandPort, HandoffCommandPort, HandoffLeaseGrant, HandoffTicketGrant,
};

pub(crate) struct DurabilityCommandService {
    port: Arc<dyn DurabilityCommandPort>,
}

impl DurabilityCommandService {
    pub(crate) fn new(port: Arc<dyn DurabilityCommandPort>) -> Self {
        Self { port }
    }

    pub(crate) fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.port.latch_group_durability_unknown(group_id)
    }
}

pub(crate) struct HandoffCommandService {
    port: Arc<dyn HandoffCommandPort>,
}

impl HandoffCommandService {
    pub(crate) fn new(port: Arc<dyn HandoffCommandPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn request_lease(&self, group_id: &str) -> Option<HandoffLeaseGrant> {
        self.port.request_lease(group_id).await
    }

    pub(crate) async fn obtain_ticket(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Option<HandoffTicketGrant> {
        self.port.obtain_ticket(group_id, device_id).await
    }

    pub(crate) async fn release_ticket(
        &self,
        group_id: &str,
        device_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) {
        self.port.release_ticket(group_id, device_id, target_device_id, lease_id).await;
    }
}
