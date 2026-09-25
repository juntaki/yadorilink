//! Linking local folders to folder groups, and the preflight that runs before
//! a link is registered.

use std::path::PathBuf;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    HandoffResult, LinkRequest, LinkStatus, ListLinksRequest, PendingEnrollmentKind, UnlinkRequest,
};
use yadorilink_local_storage::link_preflight::{self, LinkPreflightReport};

use crate::daemon::control;
use crate::error::CoreError;
use crate::ops::shares::resolve_group_name;

/// Runs the shared link preflight for `local_path`: canonicalize the path,
/// gather already-linked paths for nested-link detection, and compute the
/// [`LinkPreflightReport`]. Returns the canonicalized path alongside the
/// report so the caller can pass it straight to [`link_resolved`] without
/// canonicalizing a second time.
pub async fn run_link_preflight(
    local_path: &str,
) -> Result<(PathBuf, LinkPreflightReport), CoreError> {
    let absolute = std::fs::canonicalize(local_path)
        .map_err(|_| CoreError::InvalidInput(format!("no such directory: {local_path}")))?;
    let existing_paths = fetch_existing_link_paths().await;
    let report = link_preflight::run_preflight(&absolute, &existing_paths, None);
    Ok((absolute, report))
}

/// Best-effort: an unreachable daemon (or any other `ListLinks` failure) is
/// treated as "no known existing links" rather than aborting the whole
/// preflight -- nested-link detection then just can't find anything. A real
/// link attempt still fails clearly right after, against the same unreachable
/// daemon.
async fn fetch_existing_link_paths() -> Vec<String> {
    match control::send(ReqPayload::ListLinks(ListLinksRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::ListLinks(list)) => {
                list.links.into_iter().map(|l| l.local_path).collect()
            }
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

/// Registers a link for a caller-resolved `group_id`, eagerly, carrying the
/// caller's aggregate risk acknowledgement. The daemon still re-checks
/// preflight as defense-in-depth, so an unacknowledged risky link is refused
/// there too. A create or join never links through here: those run the
/// crash-safe protocol inside the daemon's `CreateAndLink`/`JoinAndLink`
/// commands.
pub async fn link_resolved(
    absolute_path: PathBuf,
    group_id: String,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    link_resolved_as(absolute_path, group_id, false, acknowledge_risks).await
}

/// [`link_resolved`] in a chosen storage mode: `on_demand` fetches files when
/// they are opened instead of keeping every file on this device.
pub async fn link_resolved_as(
    absolute_path: PathBuf,
    group_id: String,
    on_demand: bool,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    send_link(absolute_path, group_id, on_demand, None, acknowledge_risks).await
}

/// Links an already-preflighted folder to a group named by the user, with an
/// optional on-demand local size cap (meaningful only when `on_demand`; no cap
/// means no automatic eviction). Plain links never run the crash-safe
/// create/join protocol, so there is no pending enrollment to track.
pub async fn link_to_named_group(
    absolute_path: PathBuf,
    group_name: &str,
    on_demand: bool,
    max_local_size_bytes: Option<i64>,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    send_link(absolute_path, group_id, on_demand, max_local_size_bytes, acknowledge_risks).await
}

async fn send_link(
    absolute_path: PathBuf,
    group_id: String,
    on_demand: bool,
    max_local_size_bytes: Option<i64>,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    control::send(ReqPayload::Link(LinkRequest {
        local_path: absolute_path.to_string_lossy().to_string(),
        group_id,
        on_demand,
        max_local_size_bytes,
        acknowledge_risks,
        // A plain link tracks no enrollment.
        pending_enrollment_operation_id: String::new(),
        pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
        pending_enrollment_device_id: String::new(),
    }))
    .await?;
    Ok(())
}

/// Unlinks a folder. If this device is an eager full replica for the
/// folder's group, the daemon refuses fail-closed unless another full replica
/// is confirmed ready to durably hold every file; `force` bypasses that gate
/// for a genuinely dead sole replica, and the daemon audit-logs every forced
/// override. Returns the coordination-plane handoff-commit result when this
/// unlink actually went through one, `None` for every other unlink.
///
/// The daemon's durability refusal is [`CoreError::DurabilityBlocked`], with
/// the daemon's own text.
pub async fn send_unlink(
    local_path: &str,
    force: bool,
) -> Result<Option<HandoffResult>, CoreError> {
    let resp = control::send(ReqPayload::Unlink(UnlinkRequest {
        local_path: local_path.to_string(),
        force,
    }))
    .await
    .map_err(|e| classify_unlink_refusal(e, local_path))?;
    Ok(match resp.payload {
        Some(RespPayload::Unlink(r)) => r.handoff_result,
        _ => None,
    })
}

/// The unlink request answers with plain text, so its durability refusals
/// are recognized by the one shape the daemon gives both of them: they name
/// the folder and offer `--force`. Every other refusal stays as it was.
fn classify_unlink_refusal(error: CoreError, local_path: &str) -> CoreError {
    match error {
        CoreError::DaemonRejected(message)
            if message.starts_with(&format!("refusing to unlink {local_path}: "))
                && message.contains("--force") =>
        {
            CoreError::DurabilityBlocked { message, group_ids: Vec::new() }
        }
        other => other,
    }
}

/// Every folder this device links, with its sync state.
pub async fn list_links() -> Result<Vec<LinkStatus>, CoreError> {
    let resp = control::send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
    let Some(RespPayload::ListLinks(list)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(list.links)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_daemons_durability_refusals_of_this_unlink_become_durability_blocked() {
        let refusal = "refusing to unlink /f/Docs: no other full replica is confirmed ready to \
                       durably hold every file in this group yet. Wait, or re-run with --force \
                       to unlink anyway (data-loss risk).";
        match classify_unlink_refusal(CoreError::DaemonRejected(refusal.into()), "/f/Docs") {
            CoreError::DurabilityBlocked { message, group_ids } => {
                assert_eq!(message, refusal);
                assert!(group_ids.is_empty());
            }
            other => panic!("expected a durability refusal, got {other:?}"),
        }
        let unreadable = "refusing to unlink because the local link table could not be read: x";
        assert!(matches!(
            classify_unlink_refusal(CoreError::DaemonRejected(unreadable.into()), "/f/Docs"),
            CoreError::DaemonRejected(_)
        ));
        assert!(matches!(
            classify_unlink_refusal(CoreError::DaemonRejected(refusal.into()), "/f/Other"),
            CoreError::DaemonRejected(_)
        ));
        assert!(matches!(
            classify_unlink_refusal(CoreError::DaemonNotRunning, "/f/Docs"),
            CoreError::DaemonNotRunning
        ));
    }
}
