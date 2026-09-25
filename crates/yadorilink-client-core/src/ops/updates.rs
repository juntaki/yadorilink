//! Application updates, owned by the daemon's update pipeline.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    UpdateCheckRequest, UpdateCheckResponse, UpdateConfigRequest, UpdateConfigResponse,
    UpdateInstallRequest, UpdateInstallResponse, UpdateStatusRequest, UpdateStatusResponse,
};

use crate::daemon::control;
use crate::error::CoreError;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Current version, channel, last check, state, any available update, and
/// the automatic-check and install settings.
pub async fn update_status() -> Result<UpdateStatusResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateStatus(UpdateStatusRequest {})).await?;
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(status)
}

/// Checks for an available update now.
pub async fn check_for_updates() -> Result<UpdateCheckResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateCheck(UpdateCheckRequest {})).await?;
    let Some(RespPayload::UpdateCheck(check)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(check)
}

/// Installs a previously checked update. The daemon's own pipeline decides
/// whether and when it actually applies (mandatory, holdback and safe-point
/// gating).
pub async fn install_update() -> Result<UpdateInstallResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateInstall(UpdateInstallRequest {})).await?;
    let Some(RespPayload::UpdateInstall(install)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(install)
}

/// Configures automatic update checks and/or the automatic install mode
/// (`automatic` or `manual`). `None` leaves that setting unchanged.
pub async fn set_update_config(
    automatic_checks_enabled: Option<bool>,
    automatic_install_mode: Option<String>,
) -> Result<UpdateConfigResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateConfig(UpdateConfigRequest {
        automatic_checks_enabled,
        automatic_install_mode,
    }))
    .await?;
    let Some(RespPayload::UpdateConfig(config)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(config)
}
