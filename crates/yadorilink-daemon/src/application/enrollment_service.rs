use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;
use yadorilink_replica_domain::session_state::{EnrollmentOperation, EnrollmentOperationState};

use super::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
};
use super::ports::{
    EnrollmentCoordination, EnrollmentLinkPort, EnrollmentLinkRequest, EnrollmentRepository,
};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Owns the create/join pending-enrollment sagas. Every dependency is a
/// port -- no `DaemonState`, no `reqwest`, no IPC proto -- see
/// the composition root for what backs each one
/// in production.
pub(crate) struct EnrollmentService {
    device_id: String,
    repository: Arc<dyn EnrollmentRepository>,
    coordination: Arc<dyn EnrollmentCoordination>,
    links: Arc<dyn EnrollmentLinkPort>,
}

/// High-level create-and-link command.
///
/// Coordination credentials come from the daemon's configured identity and
/// are intentionally absent from this command.
pub(crate) struct CreateAndLinkCommand {
    pub(crate) group_name: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
}

/// High-level join-and-link command.
pub(crate) struct JoinAndLinkCommand {
    pub(crate) group_id: String,
    pub(crate) group_name: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnrollmentOutcome {
    pub(crate) operation_id: String,
    pub(crate) group_id: String,
    pub(crate) local_path: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollmentError {
    #[error("local device identity is unavailable")]
    LocalIdentityUnavailable,
    #[error(
        "could not persist enrollment recovery journal for operation {operation_id}: {detail}"
    )]
    RecoveryJournalUnavailable { operation_id: String, detail: String },
    #[error("enrollment preparation was rejected: {detail}")]
    PreparationRejected { detail: String },
    #[error("enrollment preparation result is ambiguous for operation {operation_id}: {detail}")]
    PreparationAmbiguous { operation_id: String, detail: String },
    #[error("local link commit failed: {detail}")]
    LocalLinkFailed { detail: String },
    #[error("local link outcome is ambiguous for operation {operation_id}: {detail}")]
    LocalLinkAmbiguous { operation_id: String, detail: String },
    #[error("enrollment activation was rejected: {detail}")]
    ActivationRejected { detail: String },
    #[error("enrollment activation result is ambiguous for operation {operation_id}: {detail}")]
    ActivationAmbiguous { operation_id: String, detail: String },
    #[error("enrollment compensation is pending for operation {operation_id}: {detail}")]
    CompensationPending { operation_id: String, detail: String },
    #[error("enrollment operation {operation_id} conflicts with another request: {detail}")]
    OperationConflict { operation_id: String, detail: String },
    #[error("coordination transport failed: {detail}")]
    CoordinationTransport { detail: String },
    #[error("local persistence failed: {0}")]
    Persistence(#[from] crate::sync_error::SyncError),
}

/// The classified result of a `link()` failure -- distinct from a plain
/// `Result<(), String>` so a caller can tell "definitely never committed"
/// (safe to compensate: mark CancelPending, retry remote cancel) apart from
/// "may still be committed" (the link/marker/Transferred row might be fully
/// live locally; remote cancellation must never be attempted, since that
/// would delete the authorization for a link that still exists).
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollmentLinkError {
    #[error("{detail}")]
    NotCommitted { detail: String },
    #[error("{detail}")]
    CommitUncertain { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrollmentKind {
    Create,
    Join,
}

impl From<EnrollmentKind> for yadorilink_replica_domain::session_state::EnrollmentKind {
    fn from(kind: EnrollmentKind) -> Self {
        match kind {
            EnrollmentKind::Create => {
                yadorilink_replica_domain::session_state::EnrollmentKind::Create
            }
            EnrollmentKind::Join => yadorilink_replica_domain::session_state::EnrollmentKind::Join,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationDisposition {
    Finalize,
    RollBack,
    LeaveForReconciliation,
}

fn activation_disposition(outcome: &EnrollmentActivationResult) -> ActivationDisposition {
    match outcome {
        EnrollmentActivationResult::Activated | EnrollmentActivationResult::AlreadyActive => {
            ActivationDisposition::Finalize
        }
        EnrollmentActivationResult::Deleted => ActivationDisposition::RollBack,
        EnrollmentActivationResult::TransientFailure { .. } => {
            ActivationDisposition::LeaveForReconciliation
        }
    }
}

impl EnrollmentService {
    pub(crate) fn new(
        device_id: String,
        repository: Arc<dyn EnrollmentRepository>,
        coordination: Arc<dyn EnrollmentCoordination>,
        links: Arc<dyn EnrollmentLinkPort>,
    ) -> Self {
        Self { device_id, repository, coordination, links }
    }

    pub(crate) async fn create_and_link(
        &self,
        command: CreateAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };

        // 1. Journal ALWAYS opens before the first remote prepare call --
        // if this write itself fails, nothing is ever sent to the
        // coordination plane (fail closed).
        let operation_id = self.open_enrollment_operation(
            yadorilink_replica_domain::session_state::EnrollmentKind::Create,
            None,
            Some(command.group_name.clone()),
            &command.absolute_path,
            storage_mode,
        )?;

        // 2. Prepare, under the SAME operation_id.
        let group_id = match self
            .coordination
            .prepare_create(&operation_id, &command.group_name, &self.device_id)
            .await
        {
            EnrollmentPrepareResult::Prepared { group_id } => group_id,
            EnrollmentPrepareResult::DefinitelyRejected { detail } => {
                self.repository.delete_operation(&operation_id)?;
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                self.mark_recovery_blocked(&operation_id, &detail);
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                // The row stays `PreparePending`; the next reconciliation
                // sweep resends the exact same prepare request under this
                // same operation_id.
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        // 3. Prepare confirmed remotely -- record it locally. A failure
        // here leaves the row `PreparePending`; the next sweep resends the
        // same prepare (idempotent by operation_id) and recovers the same
        // group_id.
        if !self.repository.mark_prepared(&operation_id, &group_id, now_unix())? {
            return Err(EnrollmentError::PreparationAmbiguous {
                operation_id,
                detail: "remote prepare succeeded but local Prepared transition could not be \
                         confirmed"
                    .to_string(),
            });
        }

        let local_path = command.absolute_path.clone();
        let link_request = EnrollmentLinkRequest {
            operation_id: operation_id.clone(),
            kind: EnrollmentKind::Create,
            device_id: self.device_id.clone(),
            group_id: group_id.clone(),
            absolute_path: command.absolute_path,
            on_demand: command.on_demand,
            acknowledge_risks: command.acknowledge_risks,
        };

        // 4. `link()` commits the local link + pending_enrollments marker +
        // this journal row's Transferred transition atomically. Its own
        // best-effort rollback on a post-commit setup failure is itself
        // fallible, so a plain `Err` here does not by itself mean nothing
        // was committed -- the port classifies the failure by reading back
        // the journal row's actual state.
        match self.links.commit(link_request).await {
            Ok(()) => {}
            Err(EnrollmentLinkError::NotCommitted { detail }) => {
                return self.compensate_failed_create_link(&operation_id, &group_id, detail).await;
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link or its activation marker may still be \
                         committed, so remote cancellation was not attempted"
                    ),
                });
            }
        }

        self.finish_activation(
            EnrollmentKind::Create,
            &group_id,
            &operation_id,
            &self.device_id.clone(),
            local_path,
        )
        .await
    }

    pub(crate) async fn join_and_link(
        &self,
        command: JoinAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        tracing::debug!(group_name = %command.group_name, group_id = %command.group_id, "starting join-and-link enrollment");
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };

        let operation_id = self.open_enrollment_operation(
            yadorilink_replica_domain::session_state::EnrollmentKind::Join,
            Some(command.group_id.clone()),
            None,
            &command.absolute_path,
            storage_mode,
        )?;

        match self
            .coordination
            .prepare_join(&operation_id, &command.group_id, &self.device_id, storage_mode)
            .await
        {
            EnrollmentPrepareResult::Prepared { .. } => {}
            EnrollmentPrepareResult::DefinitelyRejected { detail } => {
                self.repository.delete_operation(&operation_id)?;
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                self.mark_recovery_blocked(&operation_id, &detail);
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        if !self.repository.mark_prepared(&operation_id, &command.group_id, now_unix())? {
            return Err(EnrollmentError::PreparationAmbiguous {
                operation_id,
                detail: "remote prepare succeeded but local Prepared transition could not be \
                         confirmed"
                    .to_string(),
            });
        }

        let local_path = command.absolute_path.clone();
        let link_request = EnrollmentLinkRequest {
            operation_id: operation_id.clone(),
            kind: EnrollmentKind::Join,
            device_id: self.device_id.clone(),
            group_id: command.group_id.clone(),
            absolute_path: command.absolute_path,
            on_demand: command.on_demand,
            acknowledge_risks: command.acknowledge_risks,
        };
        match self.links.commit(link_request).await {
            Ok(()) => {}
            Err(EnrollmentLinkError::NotCommitted { detail }) => {
                return self
                    .compensate_failed_join_link(&operation_id, &command.group_id, detail)
                    .await;
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link or its activation marker may still be \
                         committed, so remote cancellation was not attempted"
                    ),
                });
            }
        }

        self.finish_activation(
            EnrollmentKind::Join,
            &command.group_id,
            &operation_id,
            &self.device_id.clone(),
            local_path,
        )
        .await
    }

    /// Opens a fresh `enrollment_operations` journal row, retrying under a
    /// NEW `operation_id` on a (should be astronomically rare) UUID
    /// collision -- mirrors `replica_membership_service.rs`'s
    /// `open_membership_operation`. Fails closed (no coordination call
    /// ever attempted) if the durable write itself keeps failing.
    fn open_enrollment_operation(
        &self,
        kind: yadorilink_replica_domain::session_state::EnrollmentKind,
        group_id: Option<String>,
        group_name: Option<String>,
        local_path: &std::path::Path,
        storage_mode: &str,
    ) -> Result<String, EnrollmentError> {
        const MAX_ID_ATTEMPTS: usize = 4;
        let mut last_operation_id = String::new();
        for _ in 0..MAX_ID_ATTEMPTS {
            let operation_id = Uuid::new_v4().to_string();
            last_operation_id.clone_from(&operation_id);
            let now = now_unix();
            let operation = EnrollmentOperation {
                operation_id: operation_id.clone(),
                kind,
                group_id: group_id.clone(),
                group_name: group_name.clone(),
                device_id: self.device_id.clone(),
                local_path: local_path.to_string_lossy().to_string(),
                storage_mode: storage_mode.to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: now,
                updated_at_unix: now,
            };
            match self.repository.try_insert_operation(&operation) {
                Ok(true) => return Ok(operation_id),
                // A fresh UUID already names a row -- retry under another
                // one; the existing row is untouched.
                Ok(false) => continue,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        operation_id,
                        "refusing the enrollment: could not persist the durable recovery journal, so \
                         coordination prepare must not be attempted"
                    );
                    return Err(EnrollmentError::RecoveryJournalUnavailable {
                        operation_id,
                        detail: error.to_string(),
                    });
                }
            }
        }
        Err(EnrollmentError::RecoveryJournalUnavailable {
            operation_id: last_operation_id,
            detail: "could not allocate a unique enrollment operation id after repeated \
                      collisions"
                .to_string(),
        })
    }

    fn mark_recovery_blocked(&self, operation_id: &str, detail: &str) {
        if let Err(error) = self.repository.mark_state(
            operation_id,
            EnrollmentOperationState::RecoveryBlocked,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(
                %error,
                operation_id,
                "failed to advance an enrollment operation journal row to RecoveryBlocked"
            );
        }
    }

    fn mark_cancel_pending(&self, operation_id: &str, detail: &str) {
        if let Err(error) = self.repository.mark_state(
            operation_id,
            EnrollmentOperationState::CancelPending,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(
                %error,
                operation_id,
                "failed to advance an enrollment operation journal row to CancelPending"
            );
        }
    }

    async fn compensate_failed_create_link(
        &self,
        operation_id: &str,
        group_id: &str,
        link_error: String,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        self.mark_cancel_pending(operation_id, &link_error);
        for _ in 0..3 {
            match self.coordination.cancel_create(group_id, operation_id).await {
                EnrollmentCancellationResult::Confirmed => {
                    self.repository.delete_operation(operation_id)?;
                    return Err(EnrollmentError::LocalLinkFailed { detail: link_error });
                }
                EnrollmentCancellationResult::Conflict { detail } => {
                    self.mark_recovery_blocked(operation_id, &detail);
                    return Err(EnrollmentError::OperationConflict {
                        operation_id: operation_id.to_string(),
                        detail,
                    });
                }
                EnrollmentCancellationResult::Ambiguous { detail } => {
                    self.mark_cancel_pending(operation_id, &detail);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(EnrollmentError::CompensationPending {
            operation_id: operation_id.to_string(),
            detail: format!(
                "local link failed ({link_error}); cancellation remains durably journaled"
            ),
        })
    }

    async fn compensate_failed_join_link(
        &self,
        operation_id: &str,
        group_id: &str,
        link_error: String,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        self.mark_cancel_pending(operation_id, &link_error);
        for _ in 0..3 {
            match self.coordination.cancel_join(group_id, operation_id, &self.device_id).await {
                EnrollmentCancellationResult::Confirmed => {
                    self.repository.delete_operation(operation_id)?;
                    return Err(EnrollmentError::LocalLinkFailed { detail: link_error });
                }
                EnrollmentCancellationResult::Conflict { detail } => {
                    self.mark_recovery_blocked(operation_id, &detail);
                    return Err(EnrollmentError::OperationConflict {
                        operation_id: operation_id.to_string(),
                        detail,
                    });
                }
                EnrollmentCancellationResult::Ambiguous { detail } => {
                    self.mark_cancel_pending(operation_id, &detail);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(EnrollmentError::CompensationPending {
            operation_id: operation_id.to_string(),
            detail: format!(
                "local link failed ({link_error}); cancellation remains durably journaled"
            ),
        })
    }

    async fn finish_activation(
        &self,
        kind: EnrollmentKind,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
        local_path: PathBuf,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        let activation = match kind {
            EnrollmentKind::Create => {
                self.coordination.activate_create(group_id, operation_id).await
            }
            EnrollmentKind::Join => {
                self.coordination.activate_join(group_id, operation_id, device_id).await
            }
        };
        match activation_disposition(&activation) {
            ActivationDisposition::Finalize => {
                self.repository.settle_activated(operation_id)?;
                Ok(EnrollmentOutcome {
                    operation_id: operation_id.to_string(),
                    group_id: group_id.to_string(),
                    local_path,
                })
            }
            ActivationDisposition::RollBack => {
                // `Deleted` is a CONFIRMED terminal answer -- see
                // `EnrollmentLinkPort::rollback`'s own doc comment for the
                // full rollback sequence and why it must not go through
                // `ReplicaRoleService::unlink`'s full-replica-handoff gate.
                let local_path_str = local_path.to_string_lossy().to_string();
                if let Err(e) = self.links.rollback(&local_path_str, operation_id).await {
                    // Leave the link and marker in place; the next
                    // reconciliation sweep retries the same orphan-and-
                    // remove compensation (it will see `Deleted` again and
                    // take this same path).
                    return Err(EnrollmentError::CompensationPending {
                        operation_id: operation_id.to_string(),
                        detail: format!(
                            "activation was rejected but the local rollback failed: {e}"
                        ),
                    });
                }
                Err(EnrollmentError::ActivationRejected {
                    detail: format!("operation {operation_id} no longer exists"),
                })
            }
            ActivationDisposition::LeaveForReconciliation => {
                Err(EnrollmentError::ActivationAmbiguous {
                    operation_id: operation_id.to_string(),
                    detail: "the local link and pending marker were kept for daemon \
                             reconciliation"
                        .to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn enrollment_outcome_keeps_operation_identity_for_recovery() {
        let outcome = EnrollmentOutcome {
            operation_id: "operation-1".to_string(),
            group_id: "group-1".to_string(),
            local_path: PathBuf::from("/tmp/group-1"),
        };

        assert_eq!(outcome.operation_id, "operation-1");
        assert_eq!(outcome.group_id, "group-1");
    }

    #[test]
    fn enrollment_errors_keep_compensation_context_structured() {
        let error = EnrollmentError::CompensationPending {
            operation_id: "operation-1".to_string(),
            detail: "cancel will be retried".to_string(),
        };

        assert!(error.to_string().contains("operation-1"));
    }

    #[test]
    fn activation_success_and_idempotent_retry_finalize() {
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::Activated),
            ActivationDisposition::Finalize
        );
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::AlreadyActive),
            ActivationDisposition::Finalize
        );
    }

    #[test]
    fn confirmed_activation_rejection_rolls_back() {
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::Deleted),
            ActivationDisposition::RollBack
        );
    }

    #[test]
    fn ambiguous_activation_never_rolls_back() {
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::TransientFailure {
                detail: "timeout".to_string()
            }),
            ActivationDisposition::LeaveForReconciliation
        );
    }

    // ===== Fakes =====

    #[derive(Default)]
    struct FakeEnrollmentRepository {
        operations: Mutex<HashMap<String, EnrollmentOperation>>,
    }

    impl EnrollmentRepository for FakeEnrollmentRepository {
        fn try_insert_operation(
            &self,
            operation: &EnrollmentOperation,
        ) -> Result<bool, crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            if operations.contains_key(&operation.operation_id) {
                return Ok(false);
            }
            operations.insert(operation.operation_id.clone(), operation.clone());
            Ok(true)
        }

        fn delete_operation(&self, operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
            self.operations.lock().unwrap().remove(operation_id);
            Ok(())
        }

        fn mark_prepared(
            &self,
            operation_id: &str,
            group_id: &str,
            now_unix: i64,
        ) -> Result<bool, crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
            op.group_id = Some(group_id.to_string());
            op.state = EnrollmentOperationState::Prepared;
            op.updated_at_unix = now_unix;
            Ok(true)
        }

        fn mark_state(
            &self,
            operation_id: &str,
            state: EnrollmentOperationState,
            error: Option<&str>,
            now_unix: i64,
        ) -> Result<bool, crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
            op.state = state;
            op.last_error = error.map(str::to_string);
            op.updated_at_unix = now_unix;
            Ok(true)
        }

        fn list_links(
            &self,
        ) -> Result<
            Vec<yadorilink_replica_domain::session_state::FolderLink>,
            crate::sync_error::SyncError,
        > {
            Ok(Vec::new())
        }

        fn scan_pending(
            &self,
        ) -> Result<
            yadorilink_replica_domain::session_state::PendingEnrollmentScan,
            crate::sync_error::SyncError,
        > {
            Ok(yadorilink_replica_domain::session_state::PendingEnrollmentScan::default())
        }

        fn settle_activated(
            &self,
            _operation_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            Ok(())
        }

        fn operation(
            &self,
            operation_id: &str,
        ) -> Result<Option<EnrollmentOperation>, crate::sync_error::SyncError> {
            Ok(self.operations.lock().unwrap().get(operation_id).cloned())
        }

        fn scan_open_operations(
            &self,
        ) -> Result<
            yadorilink_replica_domain::session_state::EnrollmentOperationScan,
            crate::sync_error::SyncError,
        > {
            Ok(yadorilink_replica_domain::session_state::EnrollmentOperationScan::default())
        }

        fn settle_activated_and_close(
            &self,
            operation_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.operations.lock().unwrap().remove(operation_id);
            Ok(())
        }

        fn move_marker_to_cancel_operation(
            &self,
            _marker: &yadorilink_replica_domain::session_state::PendingEnrollment,
            _now_unix: i64,
        ) -> Result<(), crate::sync_error::SyncError> {
            Ok(())
        }

        fn increment_attempts(
            &self,
            _operation_id: &str,
            _now_unix: i64,
        ) -> Result<i64, crate::sync_error::SyncError> {
            Ok(1)
        }

        fn rollback_local_setup_to_cancel_pending(
            &self,
            _local_path: &str,
            operation_id: &str,
            detail: &str,
            now_unix: i64,
        ) -> Result<(), crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(()) };
            op.state = EnrollmentOperationState::CancelPending;
            op.last_error = Some(detail.to_string());
            op.updated_at_unix = now_unix;
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum EnrollmentCall {
        PrepareCreate,
        PrepareJoin,
        ActivateCreate,
        ActivateJoin,
        CancelCreate,
        CancelJoin,
        LinkCommit,
        LinkRollback,
    }

    #[derive(Default)]
    struct FakeCoordination {
        calls: Mutex<Vec<EnrollmentCall>>,
        prepare: Mutex<std::collections::VecDeque<EnrollmentPrepareResult>>,
        activate: Mutex<std::collections::VecDeque<EnrollmentActivationResult>>,
        cancel: Mutex<std::collections::VecDeque<EnrollmentCancellationResult>>,
        configured: std::sync::atomic::AtomicBool,
    }

    impl FakeCoordination {
        fn configured() -> Self {
            let this = Self::default();
            this.configured.store(true, std::sync::atomic::Ordering::SeqCst);
            this
        }
    }

    impl EnrollmentCoordination for FakeCoordination {
        fn is_configured(&self) -> bool {
            self.configured.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn prepare_create<'a>(
            &'a self,
            _operation_id: &'a str,
            _group_name: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::PrepareCreate);
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
            })
        }

        fn prepare_join<'a>(
            &'a self,
            _operation_id: &'a str,
            _group_id: &'a str,
            _device_id: &'a str,
            _storage_mode: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::PrepareJoin);
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
            })
        }

        fn activate_create<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::ActivateCreate);
                self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
            })
        }

        fn activate_join<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::ActivateJoin);
                self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
            })
        }

        fn cancel_create<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::CancelCreate);
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
            })
        }

        fn cancel_join<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::CancelJoin);
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
            })
        }
    }

    #[derive(Default)]
    struct FakeLinkPort {
        calls: Mutex<Vec<EnrollmentCall>>,
        commit: Mutex<std::collections::VecDeque<Result<(), EnrollmentLinkError>>>,
        rollback: Mutex<std::collections::VecDeque<Result<(), String>>>,
    }

    impl EnrollmentLinkPort for FakeLinkPort {
        fn commit<'a>(
            &'a self,
            _request: EnrollmentLinkRequest,
        ) -> super::super::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::LinkCommit);
                self.commit.lock().unwrap().pop_front().expect("missing fake commit result")
            })
        }

        fn rollback<'a>(
            &'a self,
            _local_path: &'a str,
            _operation_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::LinkRollback);
                self.rollback.lock().unwrap().pop_front().expect("missing fake rollback result")
            })
        }
    }

    fn service(
        repository: Arc<FakeEnrollmentRepository>,
        coordination: Arc<FakeCoordination>,
        links: Arc<FakeLinkPort>,
    ) -> EnrollmentService {
        EnrollmentService::new("device-a".to_string(), repository, coordination, links)
    }

    fn create_command() -> CreateAndLinkCommand {
        CreateAndLinkCommand {
            group_name: "photos".to_string(),
            absolute_path: PathBuf::from("/home/alice/Photos"),
            on_demand: false,
            acknowledge_risks: false,
        }
    }

    /// A `Deleted` activation rolls back via the link port's own rollback
    /// method, never `ReplicaRoleService::unlink`'s full-replica-handoff
    /// gate -- proven here by the sequence: link commit, then activate,
    /// then rollback, nothing else.
    #[tokio::test]
    async fn deleted_activation_rolls_back_via_the_link_port() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(()));
        links.rollback.lock().unwrap().push_back(Ok(()));

        let result = service(repository, coordination.clone(), links.clone())
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })));
        assert_eq!(
            *links.calls.lock().unwrap(),
            vec![EnrollmentCall::LinkCommit, EnrollmentCall::LinkRollback]
        );
    }

    /// If the rollback itself fails, `CompensationPending` is returned so
    /// the next reconciliation sweep retries -- never treated as done.
    #[tokio::test]
    async fn rollback_failure_reports_compensation_pending() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(()));
        links.rollback.lock().unwrap().push_back(Err("disk full".to_string()));

        let result =
            service(repository, coordination, links).create_and_link(create_command()).await;

        assert!(matches!(result, Err(EnrollmentError::CompensationPending { .. })));
    }

    /// `TransientFailure` never rolls back -- the link/marker/rollback port
    /// is never called a second time.
    #[tokio::test]
    async fn transient_activation_failure_never_rolls_back() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination
            .activate
            .lock()
            .unwrap()
            .push_back(EnrollmentActivationResult::TransientFailure { detail: "503".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(()));

        let result = service(repository, coordination, links.clone())
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::ActivationAmbiguous { .. })));
        assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
    }

    /// Config missing is checked BEFORE the journal is even opened -- no
    /// journal row exists afterward, and no coordination call is ever made.
    #[tokio::test]
    async fn missing_coordination_config_never_opens_a_journal_row() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::default()); // not configured
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository.clone(), coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::LocalIdentityUnavailable)));
        assert!(repository.operations.lock().unwrap().is_empty());
        assert!(coordination.calls.lock().unwrap().is_empty());
    }

    /// A local `link()` failure that reaches a durable `CancelPending`
    /// state (the immediate cancel-with-retries also fails) leaves exactly
    /// one journal row behind, in `CancelPending`.
    #[tokio::test]
    async fn link_failure_and_cancel_failure_leaves_a_cancel_pending_row() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        for _ in 0..3 {
            coordination
                .cancel
                .lock()
                .unwrap()
                .push_back(EnrollmentCancellationResult::Ambiguous { detail: "5xx".to_string() });
        }
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
            detail: "simulated local link failure".to_string(),
        }));

        let result = service(repository.clone(), coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::CompensationPending { .. })));
        let operations = repository.operations.lock().unwrap();
        assert_eq!(operations.len(), 1, "expected one cancel-pending journal row");
        let (_, op) = operations.iter().next().unwrap();
        assert_eq!(op.group_id.as_deref(), Some("group-1"));
        assert_eq!(op.state, EnrollmentOperationState::CancelPending);
        assert_eq!(
            coordination
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| **c == EnrollmentCall::CancelCreate)
                .count(),
            3,
            "expected 3 cancel retries"
        );
    }

    /// `NotCommitted` goes through the existing compensation path and the
    /// remote cancel DOES get called -- the counterpart to the
    /// `CommitUncertain` test below, proving the two classifications route
    /// to genuinely different behavior.
    #[tokio::test]
    async fn not_committed_link_failure_calls_remote_cancel_and_reaches_cancel_pending() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
            detail: "preflight rejected, nothing committed".to_string(),
        }));

        let result = service(repository, coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        assert!(
            !matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })),
            "NotCommitted must never surface as LocalLinkAmbiguous: {result:?}"
        );
        assert_eq!(
            coordination
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| **c == EnrollmentCall::CancelCreate)
                .count(),
            1,
            "a NotCommitted failure must attempt remote cancellation"
        );
    }

    /// `CommitUncertain` must NEVER be treated as "definitely not
    /// committed": it must not mark CancelPending, must not call remote
    /// cancel, and must not delete the journal row.
    #[tokio::test]
    async fn commit_uncertain_link_failure_never_calls_remote_cancel() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::CommitUncertain {
            detail: "post-commit setup failed, and rolling back also failed".to_string(),
        }));

        let result = service(repository.clone(), coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        let Err(EnrollmentError::LocalLinkAmbiguous { operation_id, .. }) = result else {
            panic!("expected LocalLinkAmbiguous, got {result:?}");
        };
        let operations = repository.operations.lock().unwrap();
        let row = operations.get(&operation_id).unwrap();
        assert_ne!(
            row.state,
            EnrollmentOperationState::CancelPending,
            "CommitUncertain must never mark CancelPending"
        );
        assert_ne!(
            row.state,
            EnrollmentOperationState::RecoveryBlocked,
            "CommitUncertain must never block/discard the journal row"
        );
        assert!(
            coordination.calls.lock().unwrap().iter().all(|c| *c != EnrollmentCall::CancelCreate),
            "CommitUncertain must never call remote cancel"
        );
    }

    /// A 409 on create prepare means this operation_id already names a
    /// differently-shaped request -- the row must move to
    /// `RecoveryBlocked`, never be treated as an ordinary rejection or
    /// silently retried.
    #[tokio::test]
    async fn create_prepare_conflict_blocks_recovery() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Conflict { detail: "409".to_string() });
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository.clone(), coordination, links)
            .create_and_link(create_command())
            .await;

        let Err(EnrollmentError::OperationConflict { operation_id, .. }) = result else {
            panic!("expected OperationConflict, got {result:?}");
        };
        let operations = repository.operations.lock().unwrap();
        assert_eq!(
            operations.get(&operation_id).unwrap().state,
            EnrollmentOperationState::RecoveryBlocked
        );
    }
}
