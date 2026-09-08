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
                .enrollment_repository()
                .orphan_link_and_remove_pending_enrollment(local_path, operation_id)
                .map_err(|e| e.to_string())?;
            self.controller.stop(local_path).await;
            self.state.clear_pending_enrollment_transient_attempts(operation_id);
            Ok(())
        })
    }

    fn commit_plain<'a>(
        &'a self,
        group_id: &'a str,
        absolute_path: &'a std::path::Path,
        on_demand: bool,
        acknowledge_risks: bool,
    ) -> BoxFuture<'a, Result<(), EnrollmentLinkError>> {
        Box::pin(async move {
            let local_path = absolute_path.to_string_lossy().to_string();
            let Err(link_error) = self
                .link_lifecycle
                .link(LinkCommand {
                    local_path: local_path.clone(),
                    group_id: group_id.to_string(),
                    on_demand,
                    max_local_size_bytes: None,
                    acknowledge_risks,
                    pending_enrollment: None,
                })
                .await
            else {
                return Ok(());
            };
            let detail = link_error.to_string();
            // No `enrollment_operations` journal row exists for a plain
            // link -- classify by reading CURRENT local link state back
            // directly instead (`LinkLifecycleService::is_linked`), the
            // same authoritative source `link()`'s own duplicate-group
            // check reads. See `commit_plain`'s own doc comment (port
            // trait) for why `link()`'s `Err` alone is not enough here.
            match self.link_lifecycle.is_linked(group_id, &local_path) {
                Ok(true) => Err(EnrollmentLinkError::CommitUncertain {
                    detail: format!(
                        "{detail}; the local link may still be committed even though this call \
                         is reporting failure, so remote cancellation was not attempted"
                    ),
                }),
                Ok(false) => Err(EnrollmentLinkError::NotCommitted { detail }),
                Err(read_err) => {
                    // Can't even confirm which -- fail closed the same way
                    // `classify_link_failure`'s own unreachable/unknown-
                    // state branch does: assume it may still be committed.
                    tracing::error!(
                        error = %read_err,
                        group_id,
                        local_path = %local_path,
                        "commit_plain: link() failed and the local link state re-check ALSO \
                         failed -- cannot confirm whether the link is actually committed"
                    );
                    Err(EnrollmentLinkError::CommitUncertain {
                        detail: format!(
                            "{detail}; could not confirm local link state after the failure \
                             ({read_err}), so remote cancellation was not attempted"
                        ),
                    })
                }
            }
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
    match state.replica_coordinator.enrollment_repository().get_enrollment_operation(&operation_id)
    {
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
    use crate::application::ports::{LinkRepositoryPort, LinkWatcherPort};
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
        state
            .replica_coordinator
            .link_repository()
            .add_link(&other.path().to_string_lossy(), "group-1")
            .unwrap();
        state
            .replica_coordinator
            .enrollment_repository()
            .try_insert_enrollment_operation(
                &yadorilink_replica_domain::session_state::EnrollmentOperation {
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
                },
            )
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
        state
            .replica_coordinator
            .link_repository()
            .add_link(&other.path().to_string_lossy(), "group-1")
            .unwrap();
        state
            .replica_coordinator
            .enrollment_repository()
            .try_insert_enrollment_operation(
                &yadorilink_replica_domain::session_state::EnrollmentOperation {
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
                },
            )
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
        state
            .replica_coordinator
            .link_repository()
            .add_link(&other.path().to_string_lossy(), "group-1")
            .unwrap();
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

    /// `LinkLifecycleService::is_linked` -- the primitive `commit_plain`'s
    /// own classification is built on, since a plain link has no
    /// `enrollment_operations` journal row to read back the way
    /// `classify_link_failure` does above.
    #[tokio::test]
    async fn is_linked_reports_true_only_for_a_genuinely_live_matching_path() {
        let state = test_state();
        let lifecycle = test_link_lifecycle(&state);
        let linked = tempfile::tempdir().unwrap();
        let linked_path = linked.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&linked_path, "group-1").unwrap();

        assert!(
            lifecycle.is_linked("group-1", &linked_path).unwrap(),
            "the exact (group, path) that was just linked must report true"
        );

        let elsewhere = tempfile::tempdir().unwrap();
        assert!(
            !lifecycle.is_linked("group-1", &elsewhere.path().to_string_lossy()).unwrap(),
            "a different path for the SAME group must report false"
        );
        assert!(
            !lifecycle.is_linked("group-2", &linked_path).unwrap(),
            "the same path under a DIFFERENT group must report false"
        );
    }

    /// Forwards every `LinkRepositoryPort` call to a real, working adapter
    /// EXCEPT `remove_link`, which always fails -- the one piece
    /// `classify_link_failure`'s own tests above never needed to fake
    /// (they vary journal-row state instead), but `commit_plain` has no
    /// journal to read, so proving its classification right requires
    /// actually reaching "commit landed, watcher failed, rollback ALSO
    /// failed" for real, not asserting it from a stub.
    struct RemoveLinkAlwaysFails {
        inner: super::super::link_lifecycle::DaemonLinkRepositoryAdapter,
    }

    impl LinkRepositoryPort for RemoveLinkAlwaysFails {
        fn live_link_paths_for_group(
            &self,
            group_id: &str,
        ) -> Result<Vec<String>, crate::sync_error::SyncError> {
            self.inner.live_link_paths_for_group(group_id)
        }
        fn list_link_paths(&self) -> Result<Vec<String>, crate::sync_error::SyncError> {
            self.inner.list_link_paths()
        }
        fn commit_plain_link(
            &self,
            local_path: &str,
            group_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.inner.commit_plain_link(local_path, group_id)
        }
        fn commit_link_with_pending_enrollment(
            &self,
            local_path: &str,
            group_id: &str,
            marker: &PendingEnrollmentLinkCommand,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.inner.commit_link_with_pending_enrollment(local_path, group_id, marker)
        }
        fn remove_link(&self, _local_path: &str) -> Result<(), crate::sync_error::SyncError> {
            Err(std::io::Error::other("simulated remove_link failure").into())
        }
        fn rollback_local_setup_to_cancel_pending(
            &self,
            local_path: &str,
            operation_id: &str,
            detail: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.inner.rollback_local_setup_to_cancel_pending(local_path, operation_id, detail)
        }
        fn mark_enrollment_activation_pending(
            &self,
            operation_id: &str,
        ) -> Result<bool, crate::sync_error::SyncError> {
            self.inner.mark_enrollment_activation_pending(operation_id)
        }
    }

    /// A `LinkWatcherPort` whose `start` always fails -- forces `link()`
    /// past the commit and into its post-commit rollback path.
    struct WatcherStartAlwaysFails;

    impl LinkWatcherPort for WatcherStartAlwaysFails {
        fn is_ready(&self, _local_path: &str) -> bool {
            false
        }
        fn start<'a>(
            &'a self,
            _local_path: &'a str,
            _group_id: &'a str,
            _on_demand: bool,
            _max_local_size_bytes: Option<i64>,
        ) -> BoxFuture<'a, Result<(), crate::error::DaemonError>> {
            Box::pin(async move {
                Err(crate::error::DaemonError::Config(
                    "simulated watcher start failure".to_string(),
                ))
            })
        }
        fn stop<'a>(&'a self, _local_path: &'a str) -> BoxFuture<'a, ()> {
            Box::pin(async move {})
        }
    }

    /// Exercises `commit_plain`'s REAL classification logic end to end,
    /// through the actual `LinkLifecycleService::link()` call chain --
    /// commit succeeds, the watcher fails, the rollback ALSO fails -- the
    /// exact failure shape `commit_plain`'s own doc comment describes.
    /// `link()` itself returns only a plain `Err` with no structure a
    /// caller could classify from; this proves `commit_plain`'s `is_linked`
    /// re-check correctly sees the link row still genuinely present and
    /// classifies it `CommitUncertain`, never `NotCommitted` (which would
    /// let the caller safely cancel the coordination-plane authorization
    /// for a link that is actually still live).
    #[tokio::test]
    async fn commit_plain_classifies_a_genuinely_uncommittable_rollback_failure_as_commit_uncertain(
    ) {
        let state = test_state();
        let repository = RemoveLinkAlwaysFails {
            inner: super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone()),
        };
        let lifecycle = Arc::new(LinkLifecycleService::new(
            Arc::new(repository),
            Arc::new(WatcherStartAlwaysFails),
        ));
        let controller = Arc::new(LinkRuntimeController::new(state.clone()));
        let adapter = DaemonEnrollmentLinkAdapter::new(state.clone(), lifecycle, controller);

        let dir = tempfile::tempdir().unwrap();
        let local_path = dir.path().to_path_buf();
        let local_path_str = local_path.to_string_lossy().to_string();

        let result = adapter.commit_plain("group-1", &local_path, false, true).await;

        assert!(
            matches!(result, Err(EnrollmentLinkError::CommitUncertain { .. })),
            "expected CommitUncertain (the commit landed, only post-commit setup and its own \
             rollback failed), got {result:?}"
        );
        // The proof this test actually exercises the real classification,
        // not a stub: the link row genuinely IS still present.
        assert!(
            state
                .replica_coordinator
                .link_repository()
                .live_link_paths_for_group("group-1")
                .unwrap()
                .iter()
                .any(|p| p == &local_path_str),
            "the link row must genuinely still exist -- this is what makes CommitUncertain correct"
        );
    }
}
