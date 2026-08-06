//! IPC encode/decode for the update surface added to
//! `daemon_control.proto` -- protobuf request -> application command, and
//! application outcome -> protobuf response. All actual update-manager/
//! policy mutation lives in `UpdateCommandService`
//! (`crate::application::update_command_service`); status reads go
//! through `UpdateStatusQueryService` (`context.queries.update_status`).

use yadorilink_ipc_proto::daemonctl::{
    UpdateCheckResponse, UpdateConfigRequest, UpdateConfigResponse, UpdateInstallResponse,
    UpdateStatusResponse,
};

use crate::application::{InstallOutcome, UpdateConfigCommand};

/// `UpdateStatusView` (`crate::queries::update_status`, `DaemonState`-
/// independent) -> the IPC wire type. Shared by `StatusResponse`'s
/// embedded update fields (`control_socket::encode_runtime_status`) and
/// `UpdateStatusResponse` itself -- both carry the exact same
/// information, see `daemon_control.proto`'s doc comment on why they're
/// two separate flat messages rather than one nested inside the other.
pub(crate) fn encode_update_status(
    view: crate::queries::update_status::UpdateStatusView,
) -> UpdateStatusResponse {
    UpdateStatusResponse {
        current_version: view.current_version,
        channel: view.channel,
        install_source: view.install_source,
        last_check_unix: view.last_check_unix,
        state: view.state,
        available_version: view.available_version,
        release_notes_url: view.release_notes_url,
        mandatory: view.mandatory,
        holdback_reason: view.holdback_reason,
        waiting_for_safe_point: view.waiting_for_safe_point,
        last_error_category: view.last_error_category,
        last_error_message: view.last_error_message,
        automatic_checks_enabled: view.automatic_checks_enabled,
        automatic_install_mode: view.automatic_install_mode,
    }
}

pub(crate) fn encode_check_response(
    status: crate::queries::update_status::UpdateStatusView,
) -> UpdateCheckResponse {
    UpdateCheckResponse { status: Some(encode_update_status(status)) }
}

pub(crate) fn encode_install_response(outcome: InstallOutcome) -> UpdateInstallResponse {
    match outcome {
        InstallOutcome::Deferred => {
            UpdateInstallResponse { outcome: "deferred".into(), guidance: String::new() }
        }
        InstallOutcome::StoreManaged { guidance } => {
            UpdateInstallResponse { outcome: "store_managed".into(), guidance }
        }
        InstallOutcome::HandoffLaunched | InstallOutcome::Installed => {
            UpdateInstallResponse { outcome: "installing".into(), guidance: String::new() }
        }
    }
}

pub(crate) fn decode_config_request(req: UpdateConfigRequest) -> UpdateConfigCommand {
    UpdateConfigCommand {
        automatic_checks_enabled: req.automatic_checks_enabled,
        automatic_install_mode: req.automatic_install_mode,
    }
}

pub(crate) fn encode_config_response(
    policy: crate::application::UpdatePolicyView,
) -> UpdateConfigResponse {
    UpdateConfigResponse {
        automatic_checks_enabled: policy.automatic_checks_enabled,
        automatic_install_mode: policy.automatic_install_mode,
    }
}
