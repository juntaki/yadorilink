use std::sync::Arc;

use super::ports::{GovernanceCommandPort, GovernanceLimits};

pub(crate) struct GovernanceCommandService {
    port: Arc<dyn GovernanceCommandPort>,
}

impl GovernanceCommandService {
    pub(crate) fn new(port: Arc<dyn GovernanceCommandPort>) -> Self {
        Self { port }
    }

    pub(crate) fn set_limits(
        &self,
        upload_bytes_per_sec: u64,
        download_bytes_per_sec: u64,
    ) -> std::io::Result<GovernanceLimits> {
        self.port.set_limits(upload_bytes_per_sec, download_bytes_per_sec)
    }
}
