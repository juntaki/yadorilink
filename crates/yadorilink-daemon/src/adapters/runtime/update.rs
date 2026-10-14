//! `DaemonState`-backed [`UpdateCommandPort`]. Holds `Arc<DaemonState>`
//! (a strangler, like `resume_link`'s own adapter); everything here only
//! needs `state.update_manager`.

use std::sync::Arc;

use crate::application::ports::{
    BoxFuture, UpdateCommandPort, UpdateConfigCommand, UpdatePolicyView,
};
use crate::daemon_state::DaemonState;
use crate::update::policy::AutoInstallMode;

pub(crate) struct DaemonUpdateCommandAdapter {
    state: Arc<DaemonState>,
}

impl DaemonUpdateCommandAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl UpdateCommandPort for DaemonUpdateCommandAdapter {
    fn check(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.state.update_manager.check_now().await;
        })
    }

    fn download_guidance(&self) -> String {
        crate::update::install_source::manual_update_guidance(
            &self.state.update_manager.platform_info().install_source,
        )
    }

    fn download_page_url(&self) -> Option<String> {
        crate::update::install_source::manual_update_page(
            &self.state.update_manager.platform_info().install_source,
        )
        .map(str::to_owned)
    }

    fn config(&self, command: UpdateConfigCommand) -> Result<UpdatePolicyView, String> {
        let install_mode = match command.automatic_install_mode {
            Some(raw) => Some(
                AutoInstallMode::parse(&raw)
                    .ok_or_else(|| format!("invalid automatic_install_mode: {raw:?}"))?,
            ),
            None => None,
        };
        let policy = crate::update::manager::apply_config(
            &self.state.update_manager.policy,
            command.automatic_checks_enabled,
            install_mode,
        )
        .map_err(|e| e.to_string())?;
        Ok(UpdatePolicyView {
            automatic_checks_enabled: policy.automatic_checks_enabled,
            automatic_install_mode: policy.automatic_install_mode.as_str().to_string(),
        })
    }
}
