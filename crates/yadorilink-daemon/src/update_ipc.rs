//! Daemon-side handlers for the update IPC surface added to
//! `daemon_control.proto`. Kept in
//! its own module (mirroring `reporting_ipc.rs`'s precedent) rather than
//! inlined into `control_socket.rs`'s match arms, since each handler
//! needs a little translation between wire messages and
//! `update::{manager, policy}` types.

use yadorilink_ipc_proto::daemonctl::{
    UpdateCheckResponse, UpdateConfigRequest, UpdateConfigResponse, UpdateInstallResponse,
    UpdateStatusResponse,
};

use crate::daemon_state::DaemonState;
use crate::update::manager::InstallDispatchOutcome;
use crate::update::policy::{AutoInstallMode, UpdatePolicy, UpdateState};

/// Shared by `StatusResponse`'s embedded update fields
/// (`control_socket::list_link_statuses`'s caller) and
/// `UpdateStatusResponse` itself — both carry the exact same information,
/// see `daemon_control.proto`'s doc comment on why they're two separate
/// flat messages rather than one nested inside the other.
pub fn status_response(state: &DaemonState) -> UpdateStatusResponse {
    let policy = state.update_manager.policy.load_or_default();
    let manager = &state.update_manager;
    UpdateStatusResponse {
        current_version: manager.current_version().to_string(),
        channel: policy.channel.clone(),
        install_source: manager.platform_info().install_source.clone(),
        last_check_unix: policy.last_check_unix.unwrap_or(0),
        state: policy.state.as_str().to_string(),
        available_version: policy.available_version.clone().unwrap_or_default(),
        release_notes_url: policy.available_release_notes_url.clone().unwrap_or_default(),
        mandatory: policy.mandatory,
        holdback_reason: policy.holdback_reason.clone().unwrap_or_default(),
        waiting_for_safe_point: policy.state == UpdateState::Deferred,
        last_error_category: policy.last_error_category.clone().unwrap_or_default(),
        last_error_message: policy.last_error_message.clone().unwrap_or_default(),
        automatic_checks_enabled: policy.automatic_checks_enabled,
        automatic_install_mode: policy.automatic_install_mode.as_str().to_string(),
    }
}

/// `yadorilink update check`: runs an immediate manifest
/// check regardless of `automatic_checks_enabled` (spec "Automatic
/// checks disabled... still allows a user-initiated manual check") and
/// returns the resulting status. A check failure is still reported via
/// the returned status (its `state`/`last_error_*` fields) rather than as
/// an IPC-level error, since "the manifest was unreachable" is itself
/// meaningful status, not a protocol failure.
pub async fn check(state: &DaemonState) -> UpdateCheckResponse {
    let _ = state.update_manager.check_now().await;
    UpdateCheckResponse { status: Some(status_response(state)) }
}

/// `yadorilink update install`: requests installation of a
/// verified update. Consults `DaemonState::is_write_safe_point`
/// so a caller never has to know about safe-point mechanics
/// directly — this is the one and only place that check happens before
/// installation is attempted.
pub async fn install(state: &DaemonState) -> Result<UpdateInstallResponse, String> {
    let safe_point = state.is_write_safe_point();
    match state.update_manager.install_now(safe_point).await {
        Ok(InstallDispatchOutcome::Deferred) => {
            Ok(UpdateInstallResponse { outcome: "deferred".into(), guidance: String::new() })
        }
        Ok(InstallDispatchOutcome::StoreManaged { guidance }) => {
            Ok(UpdateInstallResponse { outcome: "store_managed".into(), guidance })
        }
        Ok(InstallDispatchOutcome::HandoffLaunched) => {
            Ok(UpdateInstallResponse { outcome: "installing".into(), guidance: String::new() })
        }
        Ok(InstallDispatchOutcome::Installed) => {
            Ok(UpdateInstallResponse { outcome: "installing".into(), guidance: String::new() })
        }
        Err(e) => Err(e.to_string()),
    }
}

/// `yadorilink update config`: each optional field left unset
/// leaves that setting unchanged.
pub fn config(
    state: &DaemonState,
    req: UpdateConfigRequest,
) -> Result<UpdateConfigResponse, String> {
    let install_mode = match req.automatic_install_mode {
        Some(raw) => Some(
            AutoInstallMode::parse(&raw)
                .ok_or_else(|| format!("invalid automatic_install_mode: {raw:?}"))?,
        ),
        None => None,
    };
    let policy: UpdatePolicy = crate::update::manager::apply_config(
        &state.update_manager.policy,
        req.automatic_checks_enabled,
        install_mode,
    )
    .map_err(|e| e.to_string())?;
    Ok(UpdateConfigResponse {
        automatic_checks_enabled: policy.automatic_checks_enabled,
        automatic_install_mode: policy.automatic_install_mode.as_str().to_string(),
    })
}
