#![cfg(test)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use yadorilink_replica_domain::session_state::FolderLink;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    RoleLossAction, RoleLossOperation, RoleLossOperationState,
};

use super::*;
use crate::application::model::RoleLossCompensationOutcome;
use crate::application::ports::BoxFuture;
use crate::handoff_proof::StrongHandoffProof;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Latch(String),
    RemoveLink(String),
    SetPolicy(String),
    OpenOperation(String),
    MarkWorkerCommitted(String),
    DiscardOperation(String),
    SettleSuccess(String),
    Advance(String, RoleLossOperationState),
    DeleteOperation(String),
    StartWatch(String),
    StopWatch(String),
}

#[derive(Default)]
struct FakeRepository {
    calls: Mutex<Vec<Call>>,
    links: Mutex<Vec<FolderLink>>,
    recheck_policy_result: Mutex<VecDeque<Result<bool, crate::sync_error::SyncError>>>,
    recheck_remove_result: Mutex<VecDeque<Result<bool, crate::sync_error::SyncError>>>,
}

impl FakeRepository {
    fn with_link(self, link: FolderLink) -> Self {
        self.links.lock().unwrap().push(link);
        self
    }
}

impl ReplicaRoleRepository for FakeRepository {
    fn list_links(&self) -> Result<Vec<FolderLink>, crate::sync_error::SyncError> {
        Ok(self.links.lock().unwrap().clone())
    }

    fn live_link_local_path_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, crate::sync_error::SyncError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.group_id == group_id)
            .map(|l| l.local_path.clone()))
    }

    fn recheck_digest_then_set_materialization_policy(
        &self,
        _group_id: &str,
        local_path: &str,
        _policy: MaterializationPolicy,
        _expected_digest: [u8; 32],
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::SetPolicy(local_path.to_string()));
        self.recheck_policy_result.lock().unwrap().pop_front().unwrap_or(Ok(true))
    }

    fn recheck_digest_then_remove_link(
        &self,
        _group_id: &str,
        local_path: &str,
        _expected_digest: [u8; 32],
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::RemoveLink(local_path.to_string()));
        self.recheck_remove_result.lock().unwrap().pop_front().unwrap_or(Ok(true))
    }

    fn remove_link(&self, local_path: &str) -> Result<(), crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::RemoveLink(local_path.to_string()));
        Ok(())
    }

    fn set_materialization_policy(
        &self,
        local_path: &str,
        _policy: MaterializationPolicy,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::SetPolicy(local_path.to_string()));
        Ok(())
    }

    fn latch_group_durability_unknown(
        &self,
        group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::Latch(group_id.to_string()));
        Ok(())
    }

    fn arm_duplicate_recovery_paths(
        &self,
        _group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        Ok(())
    }

    fn set_suppress_tombstones(
        &self,
        _local_path: &str,
        _suppress: bool,
    ) -> Result<(), crate::sync_error::SyncError> {
        Ok(())
    }
}

/// In-memory role-loss journal: `open_operation` inserts a real `Prepared`
/// row, so the service's own compensation and reconciliation workflows run
/// against rows exactly as they would against the durable journal.
#[derive(Default)]
struct FakeRoleLoss {
    calls: Mutex<Vec<Call>>,
    open_result: Mutex<VecDeque<Result<String, String>>>,
    rows: Mutex<BTreeMap<String, RoleLossOperation>>,
}

fn journal_row(
    operation_id: &str,
    target_device_id: &str,
    lease_id: &str,
    state: RoleLossOperationState,
) -> RoleLossOperation {
    RoleLossOperation {
        operation_id: operation_id.to_string(),
        group_id: "group-1".to_string(),
        source_device_id: "device-a".to_string(),
        target_device_id: target_device_id.to_string(),
        lease_id: lease_id.to_string(),
        worker_membership_generation: None,
        action: RoleLossAction::Demote,
        state,
        local_path: Some("/home/alice/Photos".to_string()),
        attempts: 0,
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

impl FakeRoleLoss {
    fn with_row(self, row: RoleLossOperation) -> Self {
        self.rows.lock().unwrap().insert(row.operation_id.clone(), row);
        self
    }

    fn row(&self, operation_id: &str) -> Option<RoleLossOperation> {
        self.rows.lock().unwrap().get(operation_id).cloned()
    }
}

impl RoleLossJournal for FakeRoleLoss {
    fn open_operation(
        &self,
        _group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        _action: RoleLossAction,
        _local_path: &str,
    ) -> Result<String, String> {
        let result = self.open_result.lock().unwrap().pop_front().unwrap_or(Ok("op-1".to_string()));
        if let Ok(id) = &result {
            self.calls.lock().unwrap().push(Call::OpenOperation(id.clone()));
            self.rows.lock().unwrap().insert(
                id.clone(),
                journal_row(id, target_device_id, lease_id, RoleLossOperationState::Prepared),
            );
        }
        result
    }

    fn mark_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        self.calls.lock().unwrap().push(Call::MarkWorkerCommitted(operation_id.to_string()));
        if let Some(row) = self.rows.lock().unwrap().get_mut(operation_id) {
            row.state = RoleLossOperationState::WorkerCommitted;
            row.worker_membership_generation = Some(membership_generation);
        }
    }

    fn discard_operation(&self, operation_id: &str) {
        self.calls.lock().unwrap().push(Call::DiscardOperation(operation_id.to_string()));
        self.rows.lock().unwrap().remove(operation_id);
    }

    fn settle_success(&self, operation_id: &str) {
        self.calls.lock().unwrap().push(Call::SettleSuccess(operation_id.to_string()));
        self.rows.lock().unwrap().remove(operation_id);
    }

    fn get_operation(&self, operation_id: &str) -> Result<Option<RoleLossOperation>, String> {
        Ok(self.row(operation_id))
    }

    fn list_operations_in_states(
        &self,
        states: &[RoleLossOperationState],
    ) -> Result<Vec<RoleLossOperation>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .values()
            .filter(|row| states.contains(&row.state))
            .cloned()
            .collect())
    }

    fn advance_operation(
        &self,
        operation_id: &str,
        state: RoleLossOperationState,
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push(Call::Advance(operation_id.to_string(), state));
        if let Some(row) = self.rows.lock().unwrap().get_mut(operation_id) {
            row.state = state;
        }
        Ok(())
    }

    fn increment_attempts(&self, operation_id: &str) -> Result<i64, String> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.get_mut(operation_id).ok_or_else(|| "no such row".to_string())?;
        row.attempts += 1;
        Ok(row.attempts)
    }

    fn delete_operation(&self, operation_id: &str) -> Result<(), String> {
        self.calls.lock().unwrap().push(Call::DeleteOperation(operation_id.to_string()));
        self.rows.lock().unwrap().remove(operation_id);
        Ok(())
    }
}

#[derive(Default)]
struct FakeReadiness {
    full_replica: AtomicBool,
    digest_and_peer: Mutex<DigestAndPeerResults>,
    lease: Mutex<VecDeque<Option<String>>>,
}

type DigestAndPeerResults = VecDeque<Option<([u8; 32], Option<String>)>>;

impl HandoffReadinessPort for FakeReadiness {
    fn is_local_full_replica(&self, _group_id: &str) -> bool {
        self.full_replica.load(Ordering::SeqCst)
    }

    fn full_replica_handoff_proof<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> BoxFuture<'a, Option<StrongHandoffProof>> {
        Box::pin(async move {
            self.digest_and_peer
                .lock()
                .unwrap()
                .pop_front()
                .flatten()
                .map(|(digest, peer)| StrongHandoffProof::new(digest, peer, 0))
        })
    }

    fn obtain_handoff_lease_from_peer<'a>(
        &'a self,
        _group_id: &'a str,
        _target_peer_device_id: &'a str,
        _my_digest: [u8; 32],
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move { self.lease.lock().unwrap().pop_front().flatten() })
    }
}

#[derive(Default)]
struct FakeCoordination {
    configured: AtomicBool,
    commit_result: Mutex<VecDeque<RoleLossCommitOutcome>>,
    set_storage_mode_calls: Mutex<u32>,
    set_storage_mode_result: Mutex<VecDeque<Result<(), String>>>,
    compensate_calls: Mutex<Vec<String>>,
    compensate_result: Mutex<VecDeque<Result<RoleLossCompensationOutcome, String>>>,
}

impl FakeCoordination {
    fn configured() -> Self {
        let this = Self::default();
        this.configured.store(true, Ordering::SeqCst);
        this
    }
}

impl RoleLossCoordination for FakeCoordination {
    fn is_configured(&self) -> bool {
        self.configured.load(Ordering::SeqCst)
    }

    fn commit_handoff_role_loss<'a>(
        &'a self,
        _group_id: &'a str,
        _source_device_id: &'a str,
        _target_device_id: &'a str,
        _lease_id: Option<&'a str>,
        _action: &'a str,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, RoleLossCommitOutcome> {
        Box::pin(async move {
            self.commit_result.lock().unwrap().pop_front().expect("missing fake commit result")
        })
    }

    fn set_storage_mode<'a>(
        &'a self,
        _group_id: &'a str,
        _device_id: &'a str,
        _mode: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            *self.set_storage_mode_calls.lock().unwrap() += 1;
            self.set_storage_mode_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
        })
    }

    fn compensate_handoff_role_loss<'a>(
        &'a self,
        _group_id: &'a str,
        _source_device_id: &'a str,
        _target_device_id: &'a str,
        lease_id: &'a str,
        _expected_membership_generation: Option<i64>,
    ) -> BoxFuture<'a, Result<RoleLossCompensationOutcome, String>> {
        Box::pin(async move {
            self.compensate_calls.lock().unwrap().push(lease_id.to_string());
            self.compensate_result
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(RoleLossCompensationOutcome::Restored))
        })
    }
}

#[derive(Default)]
struct FakeRuntime {
    calls: Mutex<Vec<Call>>,
    start_result: Mutex<VecDeque<Result<(), String>>>,
}

impl LinkRuntimePort for FakeRuntime {
    fn start_link_watch(&self, local_path: String, _group_id: String) -> Result<(), String> {
        self.calls.lock().unwrap().push(Call::StartWatch(local_path));
        self.start_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
    }

    fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(Call::StopWatch(local_path.to_string()));
        })
    }
}

fn link(group_id: &str, policy: MaterializationPolicy) -> FolderLink {
    FolderLink {
        local_path: "/home/alice/Photos".to_string(),
        group_id: group_id.to_string(),
        paused: false,
        materialization_policy: policy,
        max_local_size_bytes: None,
        orphaned: false,
    }
}

/// Fixed-answer [`PlaceholderPipelineCapabilityPort`] fake -- defaults to
/// connected since none of this module's own unit tests exercise the
/// disconnected-gate rejection itself (that's covered by the daemon
/// integration tests in `tests/role_loss_saga.rs`/
/// `tests/storage_mode_orchestration.rs`).
struct FakePlaceholderPipeline {
    connected: bool,
}

impl Default for FakePlaceholderPipeline {
    fn default() -> Self {
        Self { connected: true }
    }
}

impl PlaceholderPipelineCapabilityPort for FakePlaceholderPipeline {
    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[allow(clippy::too_many_arguments)]
fn service(
    repository: Arc<FakeRepository>,
    role_loss: Arc<FakeRoleLoss>,
    readiness: Arc<FakeReadiness>,
    coordination: Arc<FakeCoordination>,
    runtime: Arc<FakeRuntime>,
) -> ReplicaRoleService {
    ReplicaRoleService::new(
        "device-a".to_string(),
        repository,
        role_loss,
        readiness,
        coordination,
        runtime,
        Arc::new(FakePlaceholderPipeline::default()),
    )
}

// ===== set_storage_mode =====

#[tokio::test]
async fn promotion_writes_coordination_before_the_local_flip() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository.clone(), role_loss, readiness, coordination.clone(), runtime)
        .set_storage_mode("group-1", false)
        .await;

    assert!(result.is_ok());
    assert_eq!(*coordination.set_storage_mode_calls.lock().unwrap(), 1);
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&Call::SetPolicy("/home/alice/Photos".to_string())));
}

#[tokio::test]
async fn promotion_without_coordination_config_fails_closed() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::default());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository.clone(), role_loss, readiness, coordination, runtime)
        .set_storage_mode("group-1", false)
        .await;

    assert!(result.is_err());
    assert!(repository.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn demotion_of_a_vacuously_ready_empty_group_flips_locally_with_no_journal() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness.digest_and_peer.lock().unwrap().push_back(Some(([1u8; 32], None)));
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(result.is_ok());
    assert!(role_loss.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn demotion_with_confirmed_peer_opens_journal_commits_then_settles() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
        HandoffCommitResult {
            target_device_id: "device-b".to_string(),
            membership_generation: 3,
            lease_id: Some("lease-1".to_string()),
        },
    ));
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(result.is_ok());
    let calls = role_loss.calls.lock().unwrap();
    assert!(calls.contains(&Call::OpenOperation("op-1".to_string())));
    assert!(calls.contains(&Call::MarkWorkerCommitted("op-1".to_string())));
    assert!(calls.contains(&Call::SettleSuccess("op-1".to_string())));
}

#[tokio::test]
async fn demotion_lease_unavailable_refuses_with_the_lease_failure_message() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(None);
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss, readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert_eq!(result.unwrap_err(), demotion_handoff_lease_failure_message());
}

#[tokio::test]
async fn demotion_ambiguous_commit_compensates_and_refuses() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .commit_result
        .lock()
        .unwrap()
        .push_back(RoleLossCommitOutcome::Ambiguous("timeout".to_string()));
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(result.is_err());
    assert!(role_loss
        .calls
        .lock()
        .unwrap()
        .contains(&Call::Advance("op-1".to_string(), RoleLossOperationState::Compensating)));
}

// ===== ensure_unlink_keeps_a_full_replica =====

#[tokio::test]
async fn last_full_replica_cannot_unlink() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss, readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn forced_unlink_bypasses_the_gate_and_latches_durability_unknown() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let commit = service(repository.clone(), role_loss, readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", true)
        .await
        .unwrap();

    assert_eq!(commit, UnlinkCommit::RemoveNormally);
    assert!(repository.calls.lock().unwrap().contains(&Call::Latch("group-1".to_string())));
}

#[tokio::test]
async fn on_demand_link_always_allowed_no_gate_touched() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let commit = service(repository, role_loss, readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false)
        .await
        .unwrap();

    assert_eq!(commit, UnlinkCommit::RemoveNormally);
}

#[tokio::test]
async fn ready_eager_unlink_removes_atomically_via_the_readiness_and_coordination_ports() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
        HandoffCommitResult {
            target_device_id: "device-b".to_string(),
            membership_generation: 1,
            lease_id: Some("lease-1".to_string()),
        },
    ));
    let runtime = Arc::new(FakeRuntime::default());

    let commit = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false)
        .await
        .unwrap();

    assert!(matches!(commit, UnlinkCommit::AlreadyRemoved(Some(_))));
    assert!(role_loss.calls.lock().unwrap().contains(&Call::SettleSuccess("op-1".to_string())));
}

// ===== unlink =====

#[tokio::test]
async fn unlink_stops_the_watcher_and_removes_the_link_normally() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let outcome = service(repository.clone(), role_loss, readiness, coordination, runtime.clone())
        .unlink("/home/alice/Photos", false)
        .await
        .unwrap();

    assert!(outcome.handoff.is_none());
    assert!(runtime
        .calls
        .lock()
        .unwrap()
        .contains(&Call::StopWatch("/home/alice/Photos".to_string())));
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&Call::RemoveLink("/home/alice/Photos".to_string())));
}

// ===== role-loss recovery =====

#[tokio::test]
async fn compensation_without_coordination_config_keeps_the_row_for_a_later_sweep() {
    let role_loss = Arc::new(FakeRoleLoss::default().with_row(journal_row(
        "op-1",
        "device-b",
        "lease-1",
        RoleLossOperationState::WorkerCommitted,
    )));
    let coordination = Arc::new(FakeCoordination::default());

    let result = service(
        Arc::new(FakeRepository::default()),
        role_loss.clone(),
        Arc::new(FakeReadiness::default()),
        coordination.clone(),
        Arc::new(FakeRuntime::default()),
    )
    .compensate_role_loss_operation("op-1")
    .await;

    assert!(result.is_err());
    assert!(coordination.compensate_calls.lock().unwrap().is_empty());
    let row = role_loss.row("op-1").expect("an uncompensated row must never be dropped");
    assert_eq!(row.state, RoleLossOperationState::Compensating);
    assert_eq!(row.attempts, 1);
}

#[tokio::test]
async fn reconciliation_deletes_settled_rows_and_compensates_in_flight_ones() {
    let role_loss = Arc::new(
        FakeRoleLoss::default()
            .with_row(journal_row(
                "op-settled",
                "device-b",
                "lease-settled",
                RoleLossOperationState::LocalCommitted,
            ))
            .with_row(journal_row(
                "op-prepared",
                "device-b",
                "lease-prepared",
                RoleLossOperationState::Prepared,
            ))
            .with_row(journal_row(
                "op-unreachable",
                "device-b",
                "lease-unreachable",
                RoleLossOperationState::Compensating,
            )),
    );
    let coordination = Arc::new(FakeCoordination::configured());
    // Rows are visited in operation-id order: op-prepared, then
    // op-unreachable (op-settled needs no coordination call).
    coordination.compensate_result.lock().unwrap().extend([
        Ok(RoleLossCompensationOutcome::Restored),
        Err("coordination plane unavailable".to_string()),
    ]);

    service(
        Arc::new(FakeRepository::default()),
        role_loss.clone(),
        Arc::new(FakeReadiness::default()),
        coordination.clone(),
        Arc::new(FakeRuntime::default()),
    )
    .reconcile_role_loss()
    .await;

    assert_eq!(
        *coordination.compensate_calls.lock().unwrap(),
        vec!["lease-prepared".to_string(), "lease-unreachable".to_string()]
    );
    assert!(role_loss.row("op-settled").is_none());
    assert!(role_loss.row("op-prepared").is_none());
    let retained = role_loss.row("op-unreachable").expect("a failed revert must keep its row");
    assert_eq!(retained.state, RoleLossOperationState::Compensating);
    assert_eq!(retained.attempts, 1);
}
