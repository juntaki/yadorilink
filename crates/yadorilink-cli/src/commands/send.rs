//! Track Send CLI commands: `send`, `inbox`, `receive` -- a one-shot P2P
//! file transfer to/from another same-account device, entirely separate
//! from linked-folder sync. See `yadorilink-send`'s own crate doc comment
//! for why.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{ListInboxRequest, ReceiveTransferRequest, SendFileRequest};

use crate::control_client;
use crate::error::CliError;

pub async fn send(source_path: String, target_device: String) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::SendFile(SendFileRequest { source_path, target_device }))
            .await?;
    let Some(RespPayload::SendFile(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Offered transfer {}", result.transfer_id);
    for file in &result.files_offered {
        println!("  {file}");
    }
    println!("Total {} bytes", result.total_size);
    Ok(())
}

pub async fn inbox() -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::ListInbox(ListInboxRequest {})).await?;
    let Some(RespPayload::ListInbox(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.transfers.is_empty() {
        println!("Inbox is empty.");
        return Ok(());
    }
    for transfer in &list.transfers {
        println!(
            "{}  from {}  {} file(s), {} bytes  [{}]",
            transfer.transfer_id,
            transfer.sender_device_id,
            transfer.files.len(),
            transfer.total_size,
            transfer.status,
        );
        for file in &transfer.files {
            println!("    {}  ({} bytes)", file.relative_path, file.size);
        }
    }
    Ok(())
}

pub async fn receive(transfer_id: String, to: Option<String>) -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::ReceiveTransfer(ReceiveTransferRequest {
        transfer_id,
        destination_dir: to.unwrap_or_default(),
    }))
    .await?;
    let Some(RespPayload::ReceiveTransfer(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Received into {}", result.destination_dir);
    for file in &result.files_received {
        println!("  {file}");
    }
    println!("Total {} bytes", result.bytes_received);
    Ok(())
}
