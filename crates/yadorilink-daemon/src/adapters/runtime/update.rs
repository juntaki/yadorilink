//! `DaemonState`-backed [`UpdateCommandPort`]. Holds `Arc<DaemonState>`
//! (a strangler, like `resume_link`'s own adapter) since `install`
//! consults `DaemonState::is_write_safe_point` -- `check`/`config` only
//! ever need `state.update_manager`, already narrow, but are kept on the
//! same adapter rather than splitting the one port across two adapters.

use std::sync::Arc;

use crate::application::ports::{
    BoxFuture, InstallOutcome, UpdateCommandPort, UpdateConfigCommand, UpdatePolicyView,
};
use crate::daemon_state::DaemonState;
use crate::update::manager::InstallDispatchOutcome;
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

    fn install(&self) -> BoxFuture<'_, Result<InstallOutcome, String>> {
        Box::pin(async move {
            let safe_point = self.state.is_write_safe_point();
            match self.state.update_manager.install_now(safe_point).await {
                Ok(InstallDispatchOutcome::Deferred) => Ok(InstallOutcome::Deferred),
                Ok(InstallDispatchOutcome::StoreManaged { guidance }) => {
                    Ok(InstallOutcome::StoreManaged { guidance })
                }
                Ok(InstallDispatchOutcome::HandoffLaunched) => Ok(InstallOutcome::HandoffLaunched),
                Ok(InstallDispatchOutcome::Installed) => Ok(InstallOutcome::Installed),
                Err(e) => Err(e.to_string()),
            }
        })
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
