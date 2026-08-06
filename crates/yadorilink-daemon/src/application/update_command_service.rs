use std::sync::Arc;

use super::ports::{InstallOutcome, UpdateCommandPort, UpdateConfigCommand, UpdatePolicyView};

pub(crate) struct UpdateCommandService {
    port: Arc<dyn UpdateCommandPort>,
}

impl UpdateCommandService {
    pub(crate) fn new(port: Arc<dyn UpdateCommandPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn check(&self) {
        self.port.check().await;
    }

    pub(crate) async fn install(&self) -> Result<InstallOutcome, String> {
        self.port.install().await
    }

    pub(crate) fn config(&self, command: UpdateConfigCommand) -> Result<UpdatePolicyView, String> {
        self.port.config(command)
    }
}
