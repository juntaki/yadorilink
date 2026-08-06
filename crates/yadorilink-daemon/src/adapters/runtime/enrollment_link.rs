//! [`EnrollmentLinkPort`] backed by `LinkLifecycleService` (the same
//! atomic local-link commit the plain `yadorilink link` command uses) plus
//! post-failure journal classification -- see `commit`'s own doc comment
//! for why reading the journal row back is the ONLY safe way to tell a
//! definitely-rolled-back failure apart from one that may still be
//! committed.

use std::sync::Arc;

use yadorilink_replica_domain::session_state::EnrollmentOperationState;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{BoxFuture, EnrollmentLinkPort, EnrollmentLinkRequest};
use crate::application::{
    EnrollmentLinkError, LinkCommand, LinkLifecycleService, PendingEnrollmentLinkCommand,
};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonEnrollmentLinkAdapter {
    state: Arc<DaemonState>,
    link_lifecycle: Arc<LinkLifecycleService>,
    controller: Arc<LinkRuntimeController>,
}

impl DaemonEnrollmentLinkAdapter {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        link_lifecycle: Arc<LinkLifecycleService>,
        controller: Arc<LinkRuntimeController>,
    ) -> Self {
        Self { state, link_lifecycle, controller }
    }
}

impl EnrollmentLinkPort for DaemonEnrollmentLinkAdapter {
    fn commit<'a>(
        &'a self,
        request: EnrollmentLinkRequest,
    ) -> BoxFuture<'a, Result<(), EnrollmentLinkError>> {
        Box::pin(classify_link_failure(&self.state, &self.link_lifecycle, request))
    }

    /// This is a pending-enrollment compensation, never a normal role loss:
    /// the link never became an Active/eager full replica, so it must NOT
    /// go through `ReplicaRoleService::unlink`'s full-replica-handoff gate
    /// (that gate exists to protect an already-durable eager replica, which
    /// this never was). Orphan the link and drop the marker atomically,
    /// matching exactly what the reconciliation sweep's own `Deleted`
    /// handling does for a marker left over from a crash
    /// (`pending_enrollment::reconcile`) -- see
    /// `SyncState::orphan_link_and_remove_pending_enrollment`'s doc
    /// comment. On-disk files are left untouched, same as there.
    fn rollback<'a>(
        &'a self,
        local_path: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.state
                .replica_coordinator
                .enrollment_repository().orphan_link_and_remove_pending_enrollment(local_path, operation_id)
                .map_err(|e| e.to_string())?;
            self.controller.stop(local_path).await;
            self.state.clear_pending_enrollment_transient_attempts(operation_id);
            Ok(())
        })
    }
}

fn enrollment_link_to_command(link: EnrollmentLinkRequest) -> LinkCommand {
    LinkCommand {
        local_path: link.absolute_path.to_string_lossy().to_string(),
        group_id: link.group_id.clone(),
        on_demand: link.on_demand,
        max_local_size_bytes: None,
        acknowledge_risks: link.acknowledge_risks,
        pending_enrollment: Some(PendingEnrollmentLinkCommand {
            operation_id: link.operation_id,
            kind: link.kind,
            device_id: link.device_id,
        }),
    }
}

async fn classify_link_failure(
    state: &Arc<DaemonState>,
    link_lifecycle: &Arc<LinkLifecycleService>,
    spec: EnrollmentLinkRequest,
) -> Result<(), EnrollmentLinkError> {
    let operation_id = spec.operation_id.clone();
    let Err(link_error) = link_lifecycle.link(enrollment_link_to_command(spec)).await else {
        return Ok(());
    };
    let detail = link_error.to_string();
    match state.replica_coordinator.enrollment_repository().get_enrollment_operation(&operation_id) {
        // The link/marker/LocalSetupPending commit was never reached (a
        // preflight check failed) or was already rolled back to
        // CancelPending by `link()` itself -- safe to compensate now.
        Ok(Some(operation))
            if matches!(
                operation.state,
                EnrollmentOperationState::Prepared | EnrollmentOperationState::CancelPending
            ) =>
        {
            Err(EnrollmentLinkError::NotCommitted { detail })
        }
        // The row is still `LocalSetupPending` -- the commit landed and
        // either the post-commit setup failure's own rollback never ran, or
        // it ran and failed. The link (and its pending-enrollment marker)
        // may still be fully committed; remote cancellation must never be
        // attempted against a link that might still exist.
        //
        // `ActivationPending` is included in the same fail-closed bucket
        // below even though `link()` returning `Err` should never actually
        // leave a row there (a successful `mark_enrollment_activation_pending`
        // is exactly what makes `link()` return `Ok`) -- if it is ever
        // observed, treating it as "definitely not committed" would be the
        // one classification capable of orphaning a fully live, already
        // activation-eligible link's remote authorization.
        Ok(Some(operation)) if operation.state == EnrollmentOperationState::LocalSetupPending => {
            Err(EnrollmentLinkError::CommitUncertain { detail })
        }
        // Any other state (ActivationPending, RecoveryBlocked), a missing
        // row, or a read failure -- all fail closed on the side of "may
        // still be committed" rather than risk a remote cancel against a
        // link that exists.
        Ok(_) | Err(_) => Err(EnrollmentLinkError::CommitUncertain { detail }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::EnrollmentKind;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        state
    }

    fn test_link_lifecycle(state: &Arc<DaemonState>) -> Arc<LinkLifecycleService> {
        let controller = Arc::new(LinkRuntimeController::new(state.clone()));
        Arc::new(LinkLifecycleService::new(
            Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
            Arc::new(super::super::link_lifecycle::DaemonLinkWatcherAdapter::new(
                state.clone(),
                controller,
            )),
        ))
    }

    fn enrollment_link_spec(operation_id: &str, local_path: &str) -> EnrollmentLinkRequest {
        EnrollmentLinkRequest {
            operation_id: operation_id.to_string(),
            kind: EnrollmentKind::Create,
            device_id: "device-a".to_string(),
            group_id: "group-1".to_string(),
            absolute_path: std::path::PathBuf::from(local_path),
            on_demand: false,
            acknowledge_risks: true,
        }
    }

    /// When the journal row is `Prepared` or `CancelPending` at the time of
    /// a `link()` failure, nothing was left committed (either the failure
    /// happened before the atomic commit, or `link()`'s own rollback already
    /// confirmed it undone) -- `classify_link_failure` must classify this as
    /// `NotCommitted`.
    #[tokio::test]
    async fn classify_link_failure_returns_not_committed_for_a_prepared_row() {
        let state = test_state();
        // A second, unrelated live link on "group-1" forces `link()` to fail
        // deterministically at its very first preflight check, before it
        // ever touches the journal row -- the failure REASON is irrelevant
        // to `classify_link_failure`, only the row's own state at read-back
        // time matters.
        let other = tempfile::tempdir().unwrap();
        state.replica_coordinator.link_repository().add_link(&other.path().to_string_lossy(), "group-1").unwrap();
        state
            .replica_coordinator
            .enrollment_repository().try_insert_enrollment_operation(&yadorilink_replica_domain::session_state::EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: yadorilink_replica_domain::session_state::EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::Prepared,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let result = classify_link_failure(
            &state,
            &test_link_lifecycle(&state),
            enrollment_link_spec("op-1", "/home/alice/Photos"),
        )
        .await;

        assert!(
            matches!(result, Err(EnrollmentLinkError::NotCommitted { .. })),
            "expected NotCommitted, got {result:?}"
        );
    }

    /// When the journal row is `LocalSetupPending` at the time of a
    /// `link()` failure, the link/marker commit landed and either the
    /// post-commit rollback never ran or it ran and failed -- either way
    /// the link may still be fully committed, so `classify_link_failure`
    /// must classify this as `CommitUncertain`, never `NotCommitted`.
    /// Getting this wrong is exactly the bug this function exists to close:
    /// treating a still-committed link as safely cancellable would delete
    /// its remote authorization while the link stays live locally.
    #[tokio::test]
    async fn classify_link_failure_returns_commit_uncertain_for_a_local_setup_pending_row() {
        let state = test_state();
        let other = tempfile::tempdir().unwrap();
        state.replica_coordinator.link_repository().add_link(&other.path().to_string_lossy(), "group-1").unwrap();
        state
            .replica_coordinator
            .enrollment_repository().try_insert_enrollment_operation(&yadorilink_replica_domain::session_state::EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: yadorilink_replica_domain::session_state::EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::LocalSetupPending,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let result = classify_link_failure(
            &state,
            &test_link_lifecycle(&state),
            enrollment_link_spec("op-1", "/home/alice/Photos"),
        )
        .await;

        assert!(
            matches!(result, Err(EnrollmentLinkError::CommitUncertain { .. })),
            "expected CommitUncertain, got {result:?}"
        );
    }

    /// A missing journal row (or a read failure) at classification time must
    /// fail closed toward `CommitUncertain`, never `NotCommitted` -- there is
    /// no way to positively confirm nothing was committed.
    #[tokio::test]
    async fn classify_link_failure_fails_closed_when_the_journal_row_is_missing() {
        let state = test_state();
        let other = tempfile::tempdir().unwrap();
        state.replica_coordinator.link_repository().add_link(&other.path().to_string_lossy(), "group-1").unwrap();
        // No `enrollment_operations` row at all for "op-missing".

        let result = classify_link_failure(
            &state,
            &test_link_lifecycle(&state),
            enrollment_link_spec("op-missing", "/home/alice/Photos"),
        )
        .await;

        assert!(
            matches!(result, Err(EnrollmentLinkError::CommitUncertain { .. })),
            "expected CommitUncertain (fail closed), got {result:?}"
        );
    }
}
