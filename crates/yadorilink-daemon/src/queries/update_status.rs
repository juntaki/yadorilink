//! `UpdateStatus`'s read model, also embedded in `Status`'s own response
//! (`daemon_control.proto`'s doc comment on why they're two separate flat
//! messages rather than one nested inside the other). Depends only on
//! `UpdateManager`, already an owner-shaped `Arc` on `DaemonState` -- no
//! strangler adapter needed.

use std::sync::Arc;

use crate::update::manager::UpdateManager;
use crate::update::policy::UpdateState;

#[derive(Debug, Clone)]
pub(crate) struct UpdateStatusView {
    pub(crate) current_version: String,
    pub(crate) channel: String,
    pub(crate) install_source: String,
    pub(crate) last_check_unix: i64,
    pub(crate) state: String,
    pub(crate) available_version: String,
    pub(crate) release_notes_url: String,
    pub(crate) mandatory: bool,
    pub(crate) holdback_reason: String,
    pub(crate) waiting_for_safe_point: bool,
    pub(crate) last_error_category: String,
    pub(crate) last_error_message: String,
    pub(crate) automatic_checks_enabled: bool,
    pub(crate) automatic_install_mode: String,
}

pub(crate) struct UpdateStatusQueryService {
    manager: Arc<UpdateManager>,
}

impl UpdateStatusQueryService {
    pub(crate) fn new(manager: Arc<UpdateManager>) -> Self {
        Self { manager }
    }

    pub(crate) fn snapshot(&self) -> UpdateStatusView {
        let policy = self.manager.policy.load_or_default();
        UpdateStatusView {
            current_version: self.manager.current_version().to_string(),
            channel: policy.channel.clone(),
            install_source: self.manager.platform_info().install_source.clone(),
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
}
