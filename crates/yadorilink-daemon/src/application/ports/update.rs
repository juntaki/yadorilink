//! What `UpdateCommandService` needs from `crate::update::{manager,
//! policy}` -- `check`/`install`/`config`. Distinct from
//! `UpdateStatusQueryService` (a read model already independent of
//! `DaemonState`, exposed separately as `context.queries.update_status`):
//! these three mutate update-manager/policy state and return only their
//! own outcome, never a status snapshot -- a caller wanting the
//! post-check/post-config status reads `context.queries.update_status`
//! itself, keeping `application` from depending on `queries`.

use super::common::BoxFuture;

#[derive(Debug, Clone)]
pub(crate) enum InstallOutcome {
    Deferred,
    StoreManaged { guidance: String },
    HandoffLaunched,
    Installed,
}

pub(crate) struct UpdateConfigCommand {
    pub(crate) automatic_checks_enabled: Option<bool>,
    pub(crate) automatic_install_mode: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct UpdatePolicyView {
    pub(crate) automatic_checks_enabled: bool,
    pub(crate) automatic_install_mode: String,
}

pub(crate) trait UpdateCommandPort: Send + Sync {
    /// Runs an immediate manifest check regardless of
    /// `automatic_checks_enabled` (spec "Automatic checks disabled...
    /// still allows a user-initiated manual check") -- a check failure is
    /// reflected in the update manager's own status fields, not
    /// propagated as an `Err` here.
    fn check(&self) -> BoxFuture<'_, ()>;

    fn install(&self) -> BoxFuture<'_, Result<InstallOutcome, String>>;

    fn config(&self, command: UpdateConfigCommand) -> Result<UpdatePolicyView, String>;
}
