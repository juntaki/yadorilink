//! One-shot file transfers to and from another device on this account,
//! separate from linked-folder sync.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    CancelTransferRequest, InboxTransfer, ListInboxRequest, ReceiveTransferRequest,
    ReceiveTransferResponse, RetryTransferRequest, SendFileRequest, SendFileResponse,
};

use crate::daemon::control;
use crate::error::CoreError;
use crate::ops::paths;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Offers a file or directory to another device on this account.
pub async fn send_file(
    source_path: String,
    target_device: String,
) -> Result<SendFileResponse, CoreError> {
    // The daemon's working directory is not the user's, so it must never see
    // a relative path.
    let source_path = paths::absolute_path(&source_path)?;
    let resp =
        control::send(ReqPayload::SendFile(SendFileRequest { source_path, target_device })).await?;
    let Some(RespPayload::SendFile(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Every transfer other devices have offered to this device, received or
/// not.
pub async fn list_inbox() -> Result<Vec<InboxTransfer>, CoreError> {
    let resp = control::send(ReqPayload::ListInbox(ListInboxRequest {})).await?;
    let Some(RespPayload::ListInbox(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.transfers)
}

/// Accepts an inbound transfer into `destination_dir`, or the daemon's
/// default inbox directory when `None`. Resumable.
pub async fn receive_transfer(
    transfer_id: String,
    destination_dir: Option<String>,
) -> Result<ReceiveTransferResponse, CoreError> {
    let destination_dir = match destination_dir {
        Some(dir) => paths::absolute_path(&dir)?,
        None => String::new(),
    };
    let resp = control::send(ReqPayload::ReceiveTransfer(ReceiveTransferRequest {
        transfer_id,
        destination_dir,
    }))
    .await?;
    let Some(RespPayload::ReceiveTransfer(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Stops an inbound transfer. Idempotent for one already canceled or completed.
pub async fn cancel_transfer(transfer_id: String) -> Result<(), CoreError> {
    let resp =
        control::send(ReqPayload::CancelTransfer(CancelTransferRequest { transfer_id })).await?;
    let Some(RespPayload::CancelTransfer(_)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(())
}

/// Resumes a failed or canceled inbound transfer once the daemon has re-validated the sender,
/// the manifest and the destination.
pub async fn retry_transfer(transfer_id: String) -> Result<ReceiveTransferResponse, CoreError> {
    let resp =
        control::send(ReqPayload::RetryTransfer(RetryTransferRequest { transfer_id })).await?;
    let Some(RespPayload::RetryTransfer(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(ReceiveTransferResponse {
        destination_dir: result.destination_dir,
        files_received: result.files_received,
        bytes_received: result.bytes_received,
    })
}
