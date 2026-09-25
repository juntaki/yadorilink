//! Send and receive, storage, limits, diagnostics, the daemon's lifecycle,
//! updates, and the account's own records.

use std::path::Path;

use super::ClientCore;
use crate::dto::{
    self, AccountDeletionRequest, AccountDeletionStatus, BandwidthLimits, DaemonStartOutcome,
    DiagnosticsCollectionMode, DiagnosticsExport, GcReport, IncomingTransfer, ReceivedTransfer,
    SentTransfer, UpdateConfig, UpdateInstallMode, UpdateInstallOutcome, UpdateStatus,
};
use crate::error::{CoreError, DaemonUnavailableReason, DesktopError};
use crate::ops;
use crate::ops::diagnostics::BundleRequest;

fn limits(up: u64, down: u64) -> BandwidthLimits {
    BandwidthLimits {
        upload_bytes_per_sec: (up > 0).then_some(up),
        download_bytes_per_sec: (down > 0).then_some(down),
    }
}

fn collection_mode(raw: &str) -> DiagnosticsCollectionMode {
    match raw {
        "daemon" => DiagnosticsCollectionMode::Daemon,
        "daemon-partial" => DiagnosticsCollectionMode::DaemonPartial,
        _ => DiagnosticsCollectionMode::OfflineFallback,
    }
}

/// Writes a diagnostics bundle to `destination`, creating its directory.
fn write_bundle(destination: &Path, bundle: &serde_json::Value) -> Result<(), CoreError> {
    let contents = serde_json::to_string_pretty(bundle)?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CoreError::Io(e.to_string()))?;
    }
    std::fs::write(destination, contents).map_err(|e| CoreError::Io(e.to_string()))
}

impl ClientCore {
    // ---- send and receive --------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn send_to_device(
        &self,
        source_path: String,
        target_device_id: String,
    ) -> Result<SentTransfer, DesktopError> {
        Ok(dto::sent_transfer(ops::transfers::send_file(source_path, target_device_id).await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_inbox(&self) -> Result<Vec<IncomingTransfer>, DesktopError> {
        Ok(ops::transfers::list_inbox().await?.iter().map(dto::incoming_transfer).collect())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn receive_transfer(
        &self,
        transfer_id: String,
        destination_dir: Option<String>,
    ) -> Result<ReceivedTransfer, DesktopError> {
        let received = ops::transfers::receive_transfer(transfer_id, destination_dir).await?;
        Ok(dto::received_transfer(received))
    }

    // ---- storage and limits ----------------------------------------------------------

    /// # Errors
    /// Daemon failures, including a refusal while a sweep or sync is running.
    pub async fn run_gc(&self, dry_run: bool) -> Result<GcReport, DesktopError> {
        Ok(dto::gc_report(dry_run, &ops::storage::run_gc(dry_run).await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn bandwidth_limits(&self) -> Result<BandwidthLimits, DesktopError> {
        let current = ops::storage::bandwidth_limits().await?;
        Ok(limits(current.upload_bytes_per_sec, current.download_bytes_per_sec))
    }

    /// Sets both limits (`None` is unlimited) and returns what was applied.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn set_bandwidth_limits(
        &self,
        requested: BandwidthLimits,
    ) -> Result<BandwidthLimits, DesktopError> {
        let applied = ops::storage::set_bandwidth_limits(
            requested.upload_bytes_per_sec.unwrap_or(0),
            requested.download_bytes_per_sec.unwrap_or(0),
        )
        .await?;
        Ok(limits(applied.upload_bytes_per_sec, applied.download_bytes_per_sec))
    }

    // ---- diagnostics and the daemon -------------------------------------------------

    /// Writes a redacted diagnostics bundle to `destination_path`. Works when
    /// the daemon is down, with a limited bundle.
    ///
    /// # Errors
    /// A daemon failure other than being down, or the file write.
    pub async fn export_diagnostics(
        &self,
        destination_path: String,
    ) -> Result<DiagnosticsExport, DesktopError> {
        let collected = ops::diagnostics::collect_bundle(BundleRequest::Export).await?;
        write_bundle(Path::new(&destination_path), &collected.bundle)?;
        Ok(DiagnosticsExport {
            path: destination_path,
            collection_mode: collection_mode(&collected.collection_mode),
            redaction_count: u32::try_from(collected.redaction_count).unwrap_or(u32::MAX),
        })
    }

    /// Brings the daemon up with this core's launch strategy, unless it
    /// already answers.
    ///
    /// # Errors
    /// `DaemonUnavailable{NotRunning}` naming what was tried when it could
    /// not be brought up; `DaemonUnavailable{Unresponsive}`, launching
    /// nothing, when a daemon is running but does not answer.
    pub async fn start_daemon(&self) -> Result<DaemonStartOutcome, DesktopError> {
        match ops::daemon::start_daemon_with(&self.config().daemon_launch).await {
            Ok(ops::daemon::DaemonStartOutcome::AlreadyRunning) => {
                Ok(DaemonStartOutcome::AlreadyRunning)
            }
            Ok(ops::daemon::DaemonStartOutcome::Started) => Ok(DaemonStartOutcome::Started),
            Err(CoreError::Other(message)) => Err(DesktopError::DaemonUnavailable {
                message,
                reason: DaemonUnavailableReason::NotRunning,
            }),
            Err(other) => Err(other.into()),
        }
    }

    /// Asks the daemon to exit; under launchd it is started again, so this
    /// is also how the daemon is restarted.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn stop_daemon(&self) -> Result<(), DesktopError> {
        Ok(ops::daemon::stop_daemon().await?)
    }

    // ---- updates -------------------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn update_status(&self) -> Result<UpdateStatus, DesktopError> {
        Ok(dto::update_status(&ops::updates::update_status().await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn check_for_updates(&self) -> Result<UpdateStatus, DesktopError> {
        let check = ops::updates::check_for_updates().await?;
        let status = check.status.ok_or_else(|| {
            DesktopError::from(CoreError::Other("the update check returned no status".into()))
        })?;
        Ok(dto::update_status(&status))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn install_update(&self) -> Result<UpdateInstallOutcome, DesktopError> {
        Ok(dto::update_install_outcome(&ops::updates::install_update().await?))
    }

    /// Changes either setting; `None` leaves it as it is.
    ///
    /// # Errors
    /// Daemon failures, including an install mode the daemon refuses.
    pub async fn set_update_config(
        &self,
        automatic_checks: Option<bool>,
        install_mode: Option<UpdateInstallMode>,
    ) -> Result<UpdateConfig, DesktopError> {
        let mode = install_mode.map(|mode| match mode {
            UpdateInstallMode::Automatic => "automatic".to_owned(),
            UpdateInstallMode::Manual => "manual".to_owned(),
            UpdateInstallMode::Other { raw } => raw,
        });
        Ok(dto::update_config(&ops::updates::set_update_config(automatic_checks, mode).await?))
    }

    // ---- account -------------------------------------------------------------------

    /// # Errors
    /// Coordination failures.
    pub async fn account_deletion_status(&self) -> Result<AccountDeletionStatus, DesktopError> {
        Ok(dto::account_deletion_status(&ops::account::deletion_status().await?))
    }

    /// Asks for account deletion; nothing is deleted until it is confirmed
    /// with the returned token.
    ///
    /// # Errors
    /// Coordination failures.
    pub async fn request_account_deletion(&self) -> Result<AccountDeletionRequest, DesktopError> {
        let requested = ops::account::request_deletion().await?;
        Ok(AccountDeletionRequest { confirmation_token: requested.confirmation_token })
    }

    /// # Errors
    /// Coordination failures.
    pub async fn confirm_account_deletion(
        &self,
        confirmation_token: String,
    ) -> Result<AccountDeletionStatus, DesktopError> {
        let status = ops::account::confirm_deletion(confirmation_token).await?;
        Ok(dto::account_deletion_status(&status))
    }

    /// # Errors
    /// Coordination failures.
    pub async fn cancel_account_deletion(&self) -> Result<AccountDeletionStatus, DesktopError> {
        Ok(dto::account_deletion_status(&ops::account::cancel_deletion().await?))
    }

    /// The account's server-side records as pretty-printed JSON; the front
    /// end saves it where the person chooses.
    ///
    /// # Errors
    /// Coordination failures.
    pub async fn export_account_data(&self) -> Result<String, DesktopError> {
        Ok(ops::account::export_account_json().await?)
    }
}
