//! The local block store: garbage collection and transfer rate limits.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    GcRequest, GcResponse, LimitsSetRequest, LimitsSetResponse, LimitsShowRequest,
    LimitsShowResponse,
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
