//! On-demand CLI commands: evict a file or show its materialization state
//! by its local path, resolved by the daemon against its registered links
//! (the same absolute-path resolution the shell-IPC hydration path uses).

use yadorilink_client_core::ops::files;
use yadorilink_ipc_proto::daemonctl::local_state_word;

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

/// Reads `EvictResponse.dehydrated` and only ever claims success
/// when it's `true` -- a request that daemon-side silently did nothing
/// (the file is busy, not yet fully synced, or was just modified)
/// used to print "Evicted" regardless, an unconditional success claim this
/// daemon never actually backed up. See `EvictResponse`'s own proto doc
/// comment for the exact gap this closes.
pub async fn evict(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    if files::evict_file(absolute_path).await? {
        println!("Evicted {local_path} (converted to a placeholder)");
    } else {
        println!(
            "{local_path} was not evicted -- it may be busy, not fully synced, or was just \
             modified. Nothing was freed."
        );
    }
    Ok(())
}

/// The per-file analogue of `yadorilink status`'s aggregate
/// hydrated/placeholder/hydrating counts -- what state THIS file is in
/// right now.
pub async fn status(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let status = files::materialization_status(absolute_path).await?;
    if status.known {
        let state = local_state_word(status.local_state.as_ref());
        println!("{local_path}: {state}");
    } else {
        println!("{local_path}: not currently tracked (not indexed, or not under a linked folder)");
    }
    Ok(())
}
