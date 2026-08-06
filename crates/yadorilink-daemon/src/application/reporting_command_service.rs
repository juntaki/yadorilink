use std::sync::Arc;

use yadorilink_reporting::consent::ConsentState;

use super::ports::{ConsentCommand, LastErrorReport, ReportingCommandPort, SubmitReportOutcome};

pub(crate) struct ReportingCommandService {
    port: Arc<dyn ReportingCommandPort>,
}

impl ReportingCommandService {
    pub(crate) fn new(port: Arc<dyn ReportingCommandPort>) -> Self {
        Self { port }
    }

    pub(crate) fn generate_usage_report(&self) -> String {
        self.port.generate_usage_report()
    }

    pub(crate) fn generate_last_error_report(
        &self,
        report_id: Option<String>,
    ) -> Result<LastErrorReport, String> {
        self.port.generate_last_error_report(report_id)
    }

    pub(crate) fn delete_queue_item(&self, report_id: &str) -> Result<bool, String> {
        self.port.delete_queue_item(report_id)
    }

    pub(crate) fn flush_queue(&self) -> Result<u32, String> {
        self.port.flush_queue()
    }

    pub(crate) async fn submit_report(
        &self,
        report_json: &str,
    ) -> Result<SubmitReportOutcome, String> {
        self.port.submit_report(report_json).await
    }

    pub(crate) fn update_consent(&self, command: ConsentCommand) -> Result<ConsentState, String> {
        self.port.update_consent(command)
    }
}
