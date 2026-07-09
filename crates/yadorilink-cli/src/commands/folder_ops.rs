//! `add-advanced-sync-operations` section 2 (Folder Operations): CLI
//! surface for divergence summaries, dry-run resolution previews, and
//! confirmation-gated override/revert/mode-change actions — every call
//! goes through the daemon control socket (`yadorilink_daemon::folder_ops`
//! owns the actual logic), matching design.md decision 1 ("operations
//! daemon-authoritative").

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    FolderDivergenceSummaryRequest, FolderResolutionConfirmRequest, FolderResolutionPreviewRequest,
    ListFolderOperationAuditRequest,
};

use crate::control_client;
use crate::error::CliError;

pub async fn divergence(local_path: String) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::FolderDivergenceSummary(FolderDivergenceSummaryRequest {
            local_path,
        }))
        .await?;
    let Some(RespPayload::FolderDivergenceSummary(summary)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!(
        "{}  mode={}{}",
        summary.local_path,
        summary.mode,
        if summary.paused { "  paused" } else { "" }
    );
    println!(
        "  out-of-sync: {} (send-only paths not applied from a peer)",
        summary.out_of_sync_count
    );
    for path in &summary.out_of_sync_sample {
        println!("    {path}");
    }
    println!(
        "  receive-only-changed: {} (receive-only local edits not sent to a peer)",
        summary.receive_only_changed_count
    );
    for path in &summary.receive_only_changed_sample {
        println!("    {path}");
    }
    Ok(())
}

/// `action` is "override" | "revert" | "mode-change"; `target_mode` is
/// required (and only meaningful) for "mode-change" — one of
/// "send-receive" | "send-only" | "receive-only".
pub async fn preview(
    local_path: String,
    action: String,
    target_mode: Option<String>,
) -> Result<(), CliError> {
    let wire_action = match action.as_str() {
        "override" => "override",
        "revert" => "revert",
        "mode-change" => "mode_change",
        other => {
            return Err(CliError::Other(format!(
                "unknown action `{other}`; expected `override`, `revert`, or `mode-change`"
            )))
        }
    };
    let wire_mode = target_mode.as_deref().map(dash_to_db_mode).unwrap_or_default();
    let resp =
        control_client::send(ReqPayload::FolderResolutionPreview(FolderResolutionPreviewRequest {
            local_path,
            action: wire_action.to_string(),
            target_mode: wire_mode,
        }))
        .await?;
    let Some(RespPayload::FolderResolutionPreview(preview)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!(
        "Preview {} for {} ({}{}): {} path(s) affected",
        preview.preview_id,
        preview.local_path,
        preview.action,
        if preview.target_mode.is_empty() {
            String::new()
        } else {
            format!(" -> {}", preview.target_mode)
        },
        preview.affected_count
    );
    for path in &preview.affected_paths_sample {
        println!("    {path}");
    }
    println!("Run `yadorilink folder-ops confirm {}` to apply.", preview.preview_id);
    Ok(())
}

pub async fn confirm(preview_id: String) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::FolderResolutionConfirm(FolderResolutionConfirmRequest {
            preview_id,
        }))
        .await?;
    let Some(RespPayload::FolderResolutionConfirm(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Resolved {} path(s).", result.affected_count);
    Ok(())
}

pub async fn audit(local_path: Option<String>) -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::ListFolderOperationAudit(
        ListFolderOperationAuditRequest { local_path: local_path.unwrap_or_default() },
    ))
    .await?;
    let Some(RespPayload::ListFolderOperationAudit(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.entries.is_empty() {
        println!("No resolution actions recorded yet.");
    }
    for entry in list.entries {
        let target = if entry.target_mode.is_empty() {
            String::new()
        } else {
            format!(" -> {}", entry.target_mode)
        };
        println!(
            "{}  {}{}  {} path(s)  {}",
            entry.local_path,
            entry.action,
            target,
            entry.affected_count,
            entry.resolved_at_unix_nanos
        );
    }
    Ok(())
}

fn dash_to_db_mode(mode: &str) -> String {
    match mode {
        "send-receive" => "send_receive".to_string(),
        "send-only" => "send_only".to_string(),
        "receive-only" => "receive_only".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dash_to_db_mode_translates_every_known_mode() {
        assert_eq!(dash_to_db_mode("send-receive"), "send_receive");
        assert_eq!(dash_to_db_mode("send-only"), "send_only");
        assert_eq!(dash_to_db_mode("receive-only"), "receive_only");
    }
}
