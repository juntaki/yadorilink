#![cfg(test)]

use std::collections::HashMap;
use std::sync::Mutex;

use super::*;

#[test]
fn enrollment_outcome_keeps_operation_identity_for_recovery() {
    let outcome = EnrollmentOutcome {
        operation_id: "operation-1".to_string(),
        group_id: "group-1".to_string(),
        local_path: PathBuf::from("/tmp/group-1"),
        awaiting_approval: false,
        already_linked: false,
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

    fn settle_activated(&self, _operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
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
    ) -> Result<bool, crate::sync_error::SyncError> {
        let mut operations = self.operations.lock().unwrap();
        let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
        op.state = EnrollmentOperationState::CancelPending;
        op.last_error = Some(detail.to_string());
        op.updated_at_unix = now_unix;
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EnrollmentCall {
    PrepareCreate,
    PrepareJoin,
    PrepareInviteAccept,
    ActivateCreate,
    ActivateJoin,
    ActivateInviteAccept,
    CancelCreate,
    CancelJoin,
    CancelInviteAccept,
    MintInvite,
    LinkCommit,
    LinkRollback,
    LinkCommitPlain,
}

/// The arguments one `mint_invite` port call carried.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MintInviteArgs {
    group_id: String,
    role: Option<String>,
    ttl_secs: Option<u64>,
    requires_approval: bool,
}

#[derive(Default)]
struct FakeCoordination {
    calls: Mutex<Vec<EnrollmentCall>>,
    prepare: Mutex<std::collections::VecDeque<EnrollmentPrepareResult>>,
    activate: Mutex<std::collections::VecDeque<EnrollmentActivationResult>>,
    cancel: Mutex<std::collections::VecDeque<EnrollmentCancellationResult>>,
    mint: Mutex<std::collections::VecDeque<Result<MintedInvite, String>>>,
    /// One entry per mint call -- the approval flag is the whole point of
    /// the option, so a test must be able to prove it survived the trip
    /// through this port rather than merely that a mint happened.
    mint_args: Mutex<Vec<MintInviteArgs>>,
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

    fn prepare_invite_accept<'a>(
        &'a self,
        _operation_id: &'a str,
        _code: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::PrepareInviteAccept);
            self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
        })
    }

    fn activate_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::ActivateInviteAccept);
            self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
        })
    }

    fn cancel_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::CancelInviteAccept);
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
        })
    }

    fn mint_invite<'a>(
        &'a self,
        group_id: &'a str,
        role: Option<&'a str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> super::super::ports::BoxFuture<'a, Result<MintedInvite, String>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::MintInvite);
            self.mint_args.lock().unwrap().push(MintInviteArgs {
                group_id: group_id.to_string(),
                role: role.map(str::to_string),
                ttl_secs,
                requires_approval,
            });
            self.mint.lock().unwrap().pop_front().expect("missing fake mint result")
        })
    }
}

#[derive(Default)]
struct FakeLinkPort {
    calls: Mutex<Vec<EnrollmentCall>>,
    commit: Mutex<std::collections::VecDeque<Result<LinkOutcome, EnrollmentLinkError>>>,
    rollback: Mutex<std::collections::VecDeque<Result<(), String>>>,
    commit_plain: Mutex<std::collections::VecDeque<Result<(), EnrollmentLinkError>>>,
}

impl EnrollmentLinkPort for FakeLinkPort {
    fn commit<'a>(
        &'a self,
        _request: EnrollmentLinkRequest,
    ) -> super::super::ports::BoxFuture<'a, Result<LinkOutcome, EnrollmentLinkError>> {
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

    fn commit_plain<'a>(
        &'a self,
        _group_id: &'a str,
        _absolute_path: &'a std::path::Path,
        _on_demand: bool,
        _acknowledge_risks: bool,
    ) -> super::super::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::LinkCommitPlain);
            self.commit_plain.lock().unwrap().pop_front().expect("missing fake commit_plain result")
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
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));
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
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));
    links.rollback.lock().unwrap().push_back(Err("disk full".to_string()));

    let result = service(repository, coordination, links).create_and_link(create_command()).await;

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
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));

    let result =
        service(repository, coordination, links.clone()).create_and_link(create_command()).await;

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

    let result =
        service(repository, coordination.clone(), links).create_and_link(create_command()).await;

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

    let result =
        service(repository.clone(), coordination, links).create_and_link(create_command()).await;

    let Err(EnrollmentError::OperationConflict { operation_id, .. }) = result else {
        panic!("expected OperationConflict, got {result:?}");
    };
    let operations = repository.operations.lock().unwrap();
    assert_eq!(
        operations.get(&operation_id).unwrap().state,
        EnrollmentOperationState::RecoveryBlocked
    );
}

fn accept_invite_command() -> AcceptInviteCommand {
    AcceptInviteCommand {
        code: "invite-code-abc".to_string(),
        absolute_path: PathBuf::from("/home/bob/Shared"),
        on_demand: false,
        acknowledge_risks: false,
    }
}

#[test]
fn invite_accept_operation_id_is_deterministic_and_scoped_to_both_inputs() {
    let a = invite_accept_operation_id("code-1", "device-a");
    let b = invite_accept_operation_id("code-1", "device-a");
    assert_eq!(a, b, "same (code, device) must always produce the same operation id");

    let different_device = invite_accept_operation_id("code-1", "device-b");
    assert_ne!(a, different_device, "a different device must produce a different id");

    let different_code = invite_accept_operation_id("code-2", "device-a");
    assert_ne!(a, different_code, "a different code must produce a different id");
}

#[tokio::test]
async fn accept_invite_happy_path_activates_and_returns_outcome() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    let outcome = result.expect("expected a successful enrollment outcome");
    assert_eq!(outcome.group_id, "group-9");
    assert_eq!(outcome.local_path, PathBuf::from("/home/bob/Shared"));
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::ActivateInviteAccept]
    );
    assert!(
        !outcome.awaiting_approval,
        "an ordinary invite acceptance is a completed membership, not a request"
    );
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
}

/// An invite minted requiring the owner's approval parks the membership
/// instead of granting it. That is a success for this device -- nothing
/// failed, nothing is left to retry, and the local link stays -- but it
/// is NOT a membership, and the outcome has to say so or the command
/// that ran it reports a folder as joined when it will not sync until
/// someone else acts.
#[tokio::test]
async fn accept_invite_awaiting_approval_succeeds_but_is_not_reported_as_a_membership() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AwaitingApproval);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let outcome = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await
        .expect("awaiting approval is a success, not an error: nothing failed here");

    assert!(outcome.awaiting_approval);
    assert_eq!(outcome.group_id, "group-9");
    assert_eq!(outcome.local_path, PathBuf::from("/home/bob/Shared"));
    // The local link is NOT rolled back and no cancel is sent: the
    // coordination-plane edge is legitimately parked, waiting on a
    // human, and both sides must survive until they decide.
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::ActivateInviteAccept]
    );
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
}

/// A definitely-rejected prepare (e.g. the invite is invalid/expired/
/// already used) must never attempt a local link commit at all --
/// unlike the same-account create/join paths, there is no durable
/// journal row to open or clean up here either.
#[tokio::test]
async fn accept_invite_rejected_prepare_never_touches_the_link_port() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.prepare.lock().unwrap().push_back(EnrollmentPrepareResult::DefinitelyRejected {
        detail: "invite is invalid or already used".to_string(),
    });
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination, links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })));
    assert!(links.calls.lock().unwrap().is_empty());
}

/// A local link failure compensates by cancelling the invite-accept
/// Pending edge -- best-effort, but always attempted (mirrors
/// `compensate_failed_join_link`'s reasoning, simplified since there is
/// no local partial-state classification to make: see
/// `accept_invite_and_link`'s own doc comment).
#[tokio::test]
async fn accept_invite_not_committed_link_failure_triggers_a_cancel() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    links
        .commit_plain
        .lock()
        .unwrap()
        .push_back(Err(EnrollmentLinkError::NotCommitted { detail: "disk full".to_string() }));

    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::LocalLinkFailed { .. })));
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::CancelInviteAccept]
    );
}

/// A `CommitUncertain` classification (the local link may still be
/// live even though `commit_plain` is reporting failure) must NEVER
/// trigger the compensating cancel -- doing so would delete the
/// coordination-plane authorization for a group this device may
/// actually be actively linked to. Mirrors `commit`'s identical
/// same-account guarantee (see `classify_link_failure`'s own doc
/// comment and its 3 dedicated tests in enrollment_link.rs).
#[tokio::test]
async fn accept_invite_commit_uncertain_never_triggers_a_cancel() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Err(EnrollmentLinkError::CommitUncertain {
        detail: "watcher start failed and the rollback itself also failed".to_string(),
    }));

    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })));
    // Only PrepareInviteAccept ran -- no CancelInviteAccept, and no
    // ActivateInviteAccept either (this call returns before reaching
    // activate).
    assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::PrepareInviteAccept]);
}

/// A confirmed-gone activation (the Pending row's TTL swept it before
/// activate ran) reports an error but does NOT roll back the local
/// link -- there is no marker for `commit_plain` to have written, so
/// there is nothing for a rollback to remove; the link is left in
/// place for the user to `unlink` or retry with a fresh invite (see
/// `accept_invite_and_link`'s own doc comment).
#[tokio::test]
async fn accept_invite_deleted_activation_leaves_the_link_in_place() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let result = service(repository, coordination, links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })));
    // Only the plain commit ran -- no rollback call exists on this path
    // at all (unlike `commit`'s `EnrollmentLinkPort::rollback`).
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
}

#[tokio::test]
async fn accept_invite_missing_coordination_config_never_attempts_a_link() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::default()); // not configured
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination, links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::LocalIdentityUnavailable)));
    assert!(links.calls.lock().unwrap().is_empty());
}

fn minted(role: &str, requires_approval: bool) -> MintedInvite {
    MintedInvite {
        code: "abc123".to_string(),
        invite_id: "invite-1".to_string(),
        group_id: "group-9".to_string(),
        role: role.to_string(),
        expires_at_unix: 1_800_000_000,
        requires_approval,
    }
}

#[tokio::test]
async fn mint_invite_happy_path_returns_the_coordination_plane_result() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.mint.lock().unwrap().push_back(Ok(minted("viewer", false)));
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination.clone(), links)
        .mint_invite("group-9", Some("viewer"), None, false)
        .await;

    let invite = result.expect("expected a minted invite");
    assert_eq!(invite.code, "abc123");
    assert_eq!(invite.group_id, "group-9");
    assert!(!invite.requires_approval);
    assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::MintInvite]);
    assert_eq!(
        *coordination.mint_args.lock().unwrap(),
        vec![MintInviteArgs {
            group_id: "group-9".to_string(),
            role: Some("viewer".to_string()),
            ttl_secs: None,
            requires_approval: false,
        }],
    );
}

/// The approval flag must reach the coordination plane unchanged and
/// independently of the role -- an owner asking for an approval-gated
/// Editor invite must not silently get an ungated one.
#[tokio::test]
async fn mint_invite_forwards_the_approval_requirement_independently_of_the_role() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.mint.lock().unwrap().push_back(Ok(minted("editor", true)));
    let links = Arc::new(FakeLinkPort::default());

    let invite = service(repository, coordination.clone(), links)
        .mint_invite("group-9", Some("editor"), None, true)
        .await
        .expect("expected a minted invite");

    assert!(invite.requires_approval);
    assert_eq!(
        *coordination.mint_args.lock().unwrap(),
        vec![MintInviteArgs {
            group_id: "group-9".to_string(),
            role: Some("editor".to_string()),
            ttl_secs: None,
            requires_approval: true,
        }],
    );
}

/// What the caller reports is what the coordination plane recorded, not
/// what was requested: a plane that ignored the flag must not be
/// described as having honored it.
#[tokio::test]
async fn mint_invite_reports_the_coordination_planes_own_approval_answer() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.mint.lock().unwrap().push_back(Ok(minted("editor", false)));
    let links = Arc::new(FakeLinkPort::default());

    let invite = service(repository, coordination.clone(), links)
        .mint_invite("group-9", Some("editor"), None, true)
        .await
        .expect("expected a minted invite");

    assert!(!invite.requires_approval);
}

#[tokio::test]
async fn mint_invite_missing_coordination_config_fails_closed() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::default()); // not configured
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination.clone(), links)
        .mint_invite("group-9", None, None, true)
        .await;

    assert!(result.is_err());
    assert!(coordination.calls.lock().unwrap().is_empty());
}

// ===== A re-join of a folder already linked and running =====

fn join_command() -> JoinAndLinkCommand {
    JoinAndLinkCommand {
        group_id: "group-1".to_string(),
        group_name: "photos".to_string(),
        absolute_path: PathBuf::from("/home/alice/Photos"),
        on_demand: false,
        acknowledge_risks: true,
    }
}

/// Runs `join_and_link` with the link port reporting the folder already
/// linked and running, and activation answering `activation`.
async fn rejoin_with_activation(
    activation: EnrollmentActivationResult,
) -> (Result<EnrollmentOutcome, EnrollmentError>, Arc<FakeEnrollmentRepository>, Arc<FakeLinkPort>)
{
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(activation);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::AlreadyLinked));

    let result = service(repository.clone(), coordination, links.clone())
        .join_and_link(join_command())
        .await;
    (result, repository, links)
}

/// The coordination plane has no membership to activate: the command fails,
/// its own journal row is closed, and the earlier link is left alone -- no
/// rollback, which would orphan a link this command never created.
#[tokio::test]
async fn a_rejoin_whose_membership_is_gone_closes_its_row_and_never_rolls_back_the_link() {
    let (result, repository, links) =
        rejoin_with_activation(EnrollmentActivationResult::Deleted).await;

    assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })), "{result:?}");
    assert!(repository.operations.lock().unwrap().is_empty(), "the journal row is closed");
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}

/// Activation could not be confirmed: the command reports it, the row moves
/// to `CancelPending` (cancelling only a Pending membership this prepare
/// created, never an Active one), and the earlier link is left alone.
#[tokio::test]
async fn a_rejoin_with_a_transient_activation_failure_moves_to_cancel_pending_and_keeps_the_link() {
    let (result, repository, links) =
        rejoin_with_activation(EnrollmentActivationResult::TransientFailure {
            detail: "offline".to_string(),
        })
        .await;

    assert!(matches!(result, Err(EnrollmentError::ActivationAmbiguous { .. })), "{result:?}");
    let operations = repository.operations.lock().unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations.values().next().unwrap().state, EnrollmentOperationState::CancelPending);
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}

/// The ordinary case: the membership is already Active, so the command is a
/// no-op reported as one.
#[tokio::test]
async fn a_rejoin_of_an_active_membership_is_reported_as_already_linked() {
    let (result, repository, links) =
        rejoin_with_activation(EnrollmentActivationResult::AlreadyActive).await;

    let outcome = result.expect("a no-op re-join succeeds");
    assert!(outcome.already_linked);
    assert!(!outcome.awaiting_approval);
    assert!(repository.operations.lock().unwrap().is_empty());
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}
