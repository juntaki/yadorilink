//! `on-demand-sync` CLI commands (tasks 5.2/5.3): pin/unpin/evict a file
//! by its local path, resolved by the daemon against its registered links
//! (the same absolute-path resolution the shell-IPC hydration path uses).

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::{EvictRequest, PinRequest, UnpinRequest};

use crate::control_client;
use crate::error::CliError;

fn absolute_path(local_path: &str) -> Result<String, CliError> {
    std::fs::canonicalize(local_path).map(|p| p.to_string_lossy().to_string()).or_else(|_| {
        // A placeholder file, or one not yet materialized, may not
        // resolve via `canonicalize` if the parent itself is missing —
        // but ordinarily the file (even a placeholder) exists on disk
        // with the correct name, so this fallback is mainly for
        // clearer error messages on a genuinely wrong path.
        Ok(local_path.to_string())
    })
}

pub async fn pin(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    control_client::send(ReqPayload::Pin(PinRequest { absolute_path })).await?;
    println!("Pinned {local_path}");
    Ok(())
}

pub async fn unpin(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    control_client::send(ReqPayload::Unpin(UnpinRequest { absolute_path })).await?;
    println!("Unpinned {local_path}");
    Ok(())
}

pub async fn evict(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    control_client::send(ReqPayload::Evict(EvictRequest { absolute_path })).await?;
    println!("Evicted {local_path} (converted to a placeholder)");
    Ok(())
}
