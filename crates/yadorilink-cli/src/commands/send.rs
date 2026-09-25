//! Track Send CLI commands: `send`, `inbox`, `receive` -- a one-shot P2P
//! file transfer to/from another same-account device, entirely separate
//! from linked-folder sync. See `yadorilink-send`'s own crate doc comment
//! for why.

use yadorilink_client_core::ops::transfers;

use crate::error::CliError;

pub async fn send(source_path: String, target_device: String) -> Result<(), CliError> {
    let result = transfers::send_file(source_path, target_device).await?;
    println!("Offered transfer {}", result.transfer_id);
    for file in &result.files_offered {
        println!("  {file}");
    }
    println!("Total {} bytes", result.total_size);
    Ok(())
}

pub async fn inbox() -> Result<(), CliError> {
    let transfers = transfers::list_inbox().await?;
    if transfers.is_empty() {
        println!("Inbox is empty.");
        return Ok(());
    }
    for transfer in &transfers {
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
    let result = transfers::receive_transfer(transfer_id, to).await?;
    println!("Received into {}", result.destination_dir);
    for file in &result.files_received {
        println!("  {file}");
    }
    println!("Total {} bytes", result.bytes_received);
    Ok(())
}
