//! Whole-app status and per-folder sync control.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{PauseRequest, ResumeRequest, StatusRequest, StatusResponse};

use crate::daemon::control;
use crate::error::CoreError;
use crate::ops::links::list_links;

/// The daemon's whole-app status: folders, peers, transfers, limits,
/// storage, updates and recent errors.
pub async fn status() -> Result<StatusResponse, CoreError> {
    let resp = control::send(ReqPayload::Status(StatusRequest {})).await?;
    let Some(RespPayload::Status(status)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(status)
}

/// Pauses sync for one linked folder.
pub async fn pause_folder(local_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::Pause(PauseRequest { local_path })).await?;
    Ok(())
}

/// Resumes sync for one linked folder.
pub async fn resume_folder(local_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::Resume(ResumeRequest { local_path })).await?;
    Ok(())
}

/// Pauses every currently linked folder. The control protocol tracks pause
/// per link, so this lists the links and pauses each, rather than adding a
/// "pause everything" daemon request.
pub async fn pause_all() -> Result<(), CoreError> {
    for link in list_links().await? {
        pause_folder(link.local_path).await?;
    }
    Ok(())
}

/// Resumes every currently linked folder.
pub async fn resume_all() -> Result<(), CoreError> {
    for link in list_links().await? {
        resume_folder(link.local_path).await?;
    }
    Ok(())
}
