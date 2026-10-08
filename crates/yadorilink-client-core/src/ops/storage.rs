//! The local block store: garbage collection and transfer rate limits.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DiscardPreservedRequest, GcRequest, GcResponse, LimitsSetRequest, LimitsSetResponse,
    LimitsShowRequest, LimitsShowResponse, ListPreservedRequest, PreservedItem,
    RestorePreservedRequest, RetryPreservedRequest,
};

use crate::daemon::control;
use crate::error::CoreError;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Runs an immediate block-store mark-and-sweep, or (when `dry_run`) reports
/// what one would reclaim without deleting anything. The daemon refuses a
/// concurrent sweep or one during active sync.
pub async fn run_gc(dry_run: bool) -> Result<GcResponse, CoreError> {
    let resp = control::send(ReqPayload::Gc(GcRequest { dry_run })).await?;
    let Some(RespPayload::Gc(report)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(report)
}

/// What rebootstraps set aside on this device: versions other devices wrote that the replacing
/// state did not contain, and own changes that were not replayed.
pub async fn list_preserved() -> Result<Vec<PreservedItem>, CoreError> {
    let resp = control::send(ReqPayload::ListPreserved(ListPreservedRequest {})).await?;
    let Some(RespPayload::ListPreserved(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.items)
}

/// Provider publications waiting on the OS ("file in use"), up to `limit` per root.
pub async fn list_provider_pending(
    limit: u32,
) -> Result<Vec<yadorilink_ipc_proto::daemonctl::PendingPublication>, CoreError> {
    let resp = control::send(ReqPayload::ListProviderPending(
        yadorilink_ipc_proto::daemonctl::ListProviderPendingRequest { limit },
    ))
    .await?;
    let Some(RespPayload::ListProviderPending(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.items)
}

/// Restores a preserved version as one ordinary new write at its original path.
pub async fn restore_preserved(group_id: &str, item_id: &str) -> Result<(), CoreError> {
    let resp = control::send(ReqPayload::RestorePreserved(RestorePreservedRequest {
        group_id: group_id.into(),
        item_id: item_id.into(),
    }))
    .await?;
    let Some(RespPayload::RestorePreserved(_)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(())
}

/// Re-submits an own unit a rebootstrap held back to the replay.
pub async fn retry_preserved(group_id: &str, item_id: &str) -> Result<(), CoreError> {
    let resp = control::send(ReqPayload::RetryPreserved(RetryPreservedRequest {
        group_id: group_id.into(),
        item_id: item_id.into(),
    }))
    .await?;
    let Some(RespPayload::RetryPreserved(_)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(())
}

/// Deletes one preserved item: the only way an item ever goes.
pub async fn discard_preserved(group_id: &str, item_id: &str) -> Result<(), CoreError> {
    let resp = control::send(ReqPayload::DiscardPreserved(DiscardPreservedRequest {
        group_id: group_id.into(),
        item_id: item_id.into(),
    }))
    .await?;
    let Some(RespPayload::DiscardPreserved(_)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(())
}

/// The currently configured (not measured) global transfer rate limits, in
/// bytes per second; `0` is unlimited.
pub async fn bandwidth_limits() -> Result<LimitsShowResponse, CoreError> {
    let resp = control::send(ReqPayload::LimitsShow(LimitsShowRequest {})).await?;
    let Some(RespPayload::LimitsShow(current)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(current)
}

/// Sets the global upload and download rate limits (bytes per second, `0` is
/// unlimited) and returns what the daemon applied.
pub async fn set_bandwidth_limits(up: u64, down: u64) -> Result<LimitsSetResponse, CoreError> {
    let resp = control::send(ReqPayload::LimitsSet(LimitsSetRequest {
        upload_bytes_per_sec: up,
        download_bytes_per_sec: down,
    }))
    .await?;
    let Some(RespPayload::LimitsSet(applied)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(applied)
}
