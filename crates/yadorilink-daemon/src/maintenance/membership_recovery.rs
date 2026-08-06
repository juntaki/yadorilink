//! `MembershipRecoveryJob` -- fix-saga startup + periodic reconciliation
//! of any membership-related recovery journal left mid-flight by a crash
//! or an unconfirmable coordination-plane call (role-loss, unknown-scope,
//! and ambiguous membership operations -- previously three independent
//! supervised loops on this same interval, collapsed into one so the
//! number of periodic sweep owners doesn't keep growing with every new
//! recovery journal). `async`, unlike `RetentionExpiryJob`: each
//! sub-sweep makes coordination-plane HTTP calls.
//!
//! Delegates to `daemon_state::run_membership_recovery_sweep` rather than
//! duplicating its body here: that function (and the reconciliation
//! sweep it calls into) is also invoked directly by integration tests
//! wanting the real production entry point without racing this job's own
//! interval, so it stays a free function in `daemon_state` rather than
//! moving onto this struct.
//!
//! Holds a full `Arc<DaemonState>`: this job's own `#[cfg(test)]`-only
//! disable flag (`membership_recovery_sweep_disabled_for_test`) lives on
//! `DaemonState` itself, and the sweep it delegates to already needs the
//! full state.

use std::sync::Arc;

use crate::daemon_state::{run_membership_recovery_sweep, DaemonState};
use crate::maintenance::MaintenanceTrigger;

pub(crate) struct MembershipRecoveryJob {
    state: Arc<DaemonState>,
}

impl MembershipRecoveryJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) async fn run_once(&self, _trigger: MaintenanceTrigger) {
        #[cfg(test)]
        let disabled = self
            .state
            .membership_recovery_sweep_disabled_for_test
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let disabled = false;
        if !disabled {
            run_membership_recovery_sweep(&self.state).await;
        }
    }
}
