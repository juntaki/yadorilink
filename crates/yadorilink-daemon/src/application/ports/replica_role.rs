//! Replica-role's own ports -- what `ReplicaRoleService` needs from durable
//! storage, an established peer session, the coordination plane, and the
//! local link-watcher runtime, expressed as `dyn`-safe traits. Split into
//! five narrow ports rather than one wide one, mirroring Membership's own
//! split: each has an independent reason to vary (a fake lease port for
//! readiness-gate tests never needs a fake link-watcher runtime too).

use yadorilink_replica_domain::session_state::{FolderLink, RoleLossAction};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use crate::sync_error::SyncError;

use super::common::BoxFuture;
use crate::application::model::RoleLossCommitOutcome;

/// The durable link-table reads/writes `ReplicaRoleService` needs.
/// Deliberately narrow: only the specific atomic transitions the
/// storage-mode/unlink sagas actually perform.
pub(crate) trait ReplicaRoleRepository: Send + Sync {
    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError>;

    fn live_link_local_path_for_group(&self, group_id: &str) -> Result<Option<String>, SyncError>;

    /// Atomically re-enumerates the group's durability-root digest and, only
    /// if it still equals `expected_digest`, flips `local_path`'s
    /// materialization policy. `Ok(false)` means the digest had moved --
    /// the caller must treat this the same as an unconfirmed peer.
    fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError>;

    /// Same atomicity as `recheck_digest_then_set_materialization_policy`,
    /// for a link removal instead of a policy flip.
    fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError>;

    fn remove_link(&self, local_path: &str) -> Result<(), SyncError>;

    fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError>;

    /// Marks a group's local durability status as unknown -- the backstop a
    /// `--force` override latches so the UI cannot keep reporting the group
    /// healthy after an override that may have discarded its only complete
    /// copy.
    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError>;

    /// Legacy duplicate-root recovery: arms additive-scan protection for
    /// every OTHER live link in `group_id` before a departing link's removal
    /// commits, so a crash after the removal can never leave a survivor
    /// whose first scan tombstones files that only existed under the
    /// departed root.
    fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<(), SyncError>;

    fn set_suppress_tombstones(&self, local_path: &str, suppress: bool) -> Result<(), SyncError>;
}

/// The durable role-loss journal `ReplicaRoleService` uses to make a
/// coordination-plane handoff commit crash-safe -- see
/// `DaemonState::open_role_loss_operation`'s own doc comment for the
/// Prepared-before-commit ordering this exists to guarantee.
pub(crate) trait RoleLossJournal: Send + Sync {
    fn open_operation(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        action: RoleLossAction,
        local_path: &str,
    ) -> Result<String, String>;

    fn mark_worker_committed(&self, operation_id: &str, membership_generation: i64);

    fn discard_operation(&self, operation_id: &str);

    fn settle_success(&self, operation_id: &str);

    /// Reverts a role loss that committed coordination-side but whose
    /// matching local change failed, back to `eager` -- never
    /// force-completing the role loss once the local side is known to have
    /// failed.
    fn compensate<'a>(&'a self, operation_id: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// Confirms another full replica is ready to take over a group, and obtains
/// the live, peer-attested lease a role-loss commit requires once a real
/// target is confirmed.
pub(crate) trait HandoffReadinessPort: Send + Sync {
    fn is_local_full_replica(&self, group_id: &str) -> bool;

    /// The confirmed root-set digest (and, when a real peer confirmed it,
    /// that peer's device id -- `None` for the vacuously-ready empty-group
    /// case) this device's durability set was checked against.
    fn full_replica_handoff_ready_digest_and_peer<'a>(
        &'a self,
        group_id: &'a str,
    ) -> BoxFuture<'a, Option<([u8; 32], Option<String>)>>;

    /// `None` means no live lease could be obtained (peer unreachable,
    /// refused, or its attested root digest didn't match this device's
    /// own) -- a lease is mandatory for a non-empty root set, so its
    /// absence refuses the whole role-loss commit.
    fn obtain_handoff_lease_from_peer<'a>(
        &'a self,
        group_id: &'a str,
        target_peer_device_id: &'a str,
        my_digest: [u8; 32],
    ) -> BoxFuture<'a, Option<String>>;
}

/// The coordination-plane HTTP calls a role-loss/storage-mode change needs.
pub(crate) trait RoleLossCoordination: Send + Sync {
    /// Whether this device currently has a coordination-plane address/
    /// access token recorded.
    fn is_configured(&self) -> bool;

    #[allow(clippy::too_many_arguments)]
    fn commit_handoff_role_loss<'a>(
        &'a self,
        group_id: &'a str,
        source_device_id: &'a str,
        target_device_id: &'a str,
        lease_id: Option<&'a str>,
        action: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, RoleLossCommitOutcome>;

    fn set_storage_mode<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        mode: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;
}

/// The local link-watcher runtime a duplicate-root recovery restart and an
/// unlink both touch.
pub(crate) trait LinkRuntimePort: Send + Sync {
    fn start_link_watch(&self, local_path: String, group_id: String) -> Result<(), String>;

    fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()>;
}

/// Whether this build's on-demand (placeholder) materialization pipeline is
/// actually connected end-to-end -- see `yadorilink_sync_core::
/// placeholder_backend::on_demand_pipeline_is_connected`'s own doc comment
/// for exactly what that requires and why it is unconditionally `false` in
/// every real build today (no backend implemented anywhere yet). A port
/// rather than calling that free function directly so a test can inject a
/// fixed answer deterministically -- the free function's own `OverrideForTest`
/// is a thread-local, which a multi-threaded Tokio integration test (this
/// port's actual callers) cannot reliably rely on: the async task that
/// calls `set_storage_mode` is not guaranteed to run on the same OS thread
/// the test itself set the override from (Phase 7D-0's own investigation
/// into `role_loss_saga`/`storage_mode_orchestration`'s workspace failures).
pub(crate) trait PlaceholderPipelineCapabilityPort: Send + Sync {
    fn is_connected(&self) -> bool;
}
