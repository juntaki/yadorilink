//! `on-demand-sync` CLI commands: pin/unpin/evict a file
//! by its local path, resolved by the daemon against its registered links
//! (the same absolute-path resolution the shell-IPC hydration path uses).

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
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

/// M4 Pass 4: reads `EvictResponse.dehydrated` and only ever claims success
/// when it's `true` -- a request that daemon-side silently did nothing
/// (the file is pinned, busy, not yet fully synced, or was just modified)
/// used to print "Evicted" regardless, an unconditional success claim this
/// daemon never actually backed up. See `EvictResponse`'s own proto doc
/// comment for the exact gap this closes.
pub async fn evict(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let resp = control_client::send(ReqPayload::Evict(EvictRequest { absolute_path })).await?;
    match resp.payload {
        Some(RespPayload::Evict(evict)) if evict.dehydrated => {
            println!("Evicted {local_path} (converted to a placeholder)");
        }
        Some(RespPayload::Evict(_)) => {
            println!(
                "{local_path} was not evicted -- it may be pinned, busy, not fully synced, or \
                 was just modified. Nothing was freed."
            );
        }
        _ => {
            return Err(CliError::Other("unexpected daemon response".into()));
        }
    }
    Ok(())
}
