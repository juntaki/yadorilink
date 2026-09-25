//! One-shot file transfers to and from another device on this account,
//! separate from linked-folder sync.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    InboxTransfer, ListInboxRequest, ReceiveTransferRequest, ReceiveTransferResponse,
    SendFileRequest, SendFileResponse,
};

use crate::daemon::control;
use crate::error::CoreError;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Offers a file or directory to another device on this account.
pub async fn send_file(
    source_path: String,
    target_device: String,
) -> Result<SendFileResponse, CoreError> {
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
    let resp = control::send(ReqPayload::ReceiveTransfer(ReceiveTransferRequest {
        transfer_id,
        destination_dir: destination_dir.unwrap_or_default(),
    }))
    .await?;
    let Some(RespPayload::ReceiveTransfer(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}
