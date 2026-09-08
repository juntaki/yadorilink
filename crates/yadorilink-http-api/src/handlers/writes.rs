//! Mutating endpoints. Every one of these is a direct translation of
//! an existing `DaemonControlRequest` variant that already has a CLI
//! counterpart (`yadorilink pause`/`resume`/`pin`/`unpin`/`evict`/`restore`)
//! -- no new daemon capability is introduced. `/api/resume` and
//! `/api/unpin` are added here because they are the direct, symmetric IPC
//! counterparts of `/api/pause` and `/api/pin` (`ResumeRequest`/
//! `UnpinRequest` already exist and are already dispatched by
//! `control_socket.rs`): without them, a caller could pause or pin a folder
//! through this API but never reverse it through the same API. This crate
//! only ever adds an endpoint when it has a direct existing IPC
//! counterpart to translate -- it does not introduce new daemon
//! capabilities.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    EvictRequest, PauseRequest, PinRequest, RestoreVersionRequest, ResumeRequest, UnpinRequest,
};

use crate::error::ApiError;
use crate::AppState;

fn unexpected() -> ApiError {
    ApiError::Internal("daemon returned an unexpected response type for this request".into())
}

#[derive(Deserialize)]
pub struct LocalPathBody {
    path: String,
}

fn require_path(body: &LocalPathBody) -> Result<&str, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    Ok(&body.path)
}

/// `POST /api/pause` `{"path": "<local folder path>"}` -- `PauseRequest`
/// takes the link's local path (not an absolute file path under it), same
/// as `yadorilink pause <path>`.
pub async fn pause(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::Pause(PauseRequest { local_path: path.to_string() }))
        .await?;
    match resp.payload {
        Some(RespPayload::Pause(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/resume` `{"path": "<local folder path>"}`.
pub async fn resume(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::Resume(ResumeRequest { local_path: path.to_string() }))
        .await?;
    match resp.payload {
        Some(RespPayload::Resume(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/pin` `{"path": "<absolute file path>"}`.
pub async fn pin(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp =
        state.control.send(ReqPayload::Pin(PinRequest { absolute_path: path.to_string() })).await?;
    match resp.payload {
        Some(RespPayload::Pin(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/unpin` `{"path": "<absolute file path>"}`.
pub async fn unpin(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::Unpin(UnpinRequest { absolute_path: path.to_string() }))
        .await?;
    match resp.payload {
        Some(RespPayload::Unpin(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}

/// `POST /api/evict` `{"path": "<absolute file path>"}` -- returns whether
/// anything was actually freed (see `EvictResponse.dehydrated`'s own doc
/// comment in the proto: a bare "ok" here would silently overclaim
/// success).
pub async fn evict(
    State(state): State<AppState>,
    Json(body): Json<LocalPathBody>,
) -> Result<Json<Value>, ApiError> {
    let path = require_path(&body)?;
    let resp = state
        .control
        .send(ReqPayload::Evict(EvictRequest { absolute_path: path.to_string() }))
        .await?;
    let Some(RespPayload::Evict(e)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(Json(json!({
        "dehydrated": e.dehydrated,
        "blocks_reclaimed": e.blocks_reclaimed,
        "bytes_reclaimed": e.bytes_reclaimed,
    })))
}

#[derive(Deserialize)]
pub struct RestoreBody {
    path: String,
    /// Absent restores the most recent superseded version, matching
    /// `yadorilink restore <path>` with no `--version` flag.
    version_seq: Option<i64>,
}

/// `POST /api/restore` `{"path": "<absolute file path>", "version_seq": <optional i64>}`.
pub async fn restore(
    State(state): State<AppState>,
    Json(body): Json<RestoreBody>,
) -> Result<Json<Value>, ApiError> {
    if body.path.is_empty() {
        return Err(ApiError::BadRequest("`path` must not be empty".into()));
    }
    let resp = state
        .control
        .send(ReqPayload::RestoreVersion(RestoreVersionRequest {
            absolute_path: body.path,
            version_seq: body.version_seq,
        }))
        .await?;
    match resp.payload {
        Some(RespPayload::RestoreVersion(_)) => Ok(Json(json!({ "ok": true }))),
        _ => Err(unexpected()),
    }
}
