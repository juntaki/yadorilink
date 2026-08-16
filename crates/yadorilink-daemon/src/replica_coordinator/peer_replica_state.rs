//! `impl PeerReplicaStatePort for ReplicaCoordinator` -- Phase 7D-10.5,
//! finally unblocked by 7D-10.4's `MaterializationIntentGuard`
//! generalization (this trait's `open_materialization_intent_guard` is the
//! one method that needed it). Every other method here is byte-identical in
//! logic to `yadorilink-sync-core`'s own `impl PeerReplicaStatePort for
//! SyncState` (`crates/yadorilink-sync-core/src/ports/peer_replica_state_impl.rs`)
//! -- same delegate shape, same accessor calls, just against
//! `ReplicaCoordinator`'s own accessors (all already present since
//! 7D-10.2/10.3) instead of `SyncState`'s.
//!
//! `SyncState`'s own impl is left completely unchanged (see
//! `replica_coordinator.rs`'s own module doc for why `SyncState` stays alive
//! and unmodified through this whole transitional period) -- this is a
//! second, independent implementor of the same trait, not a replacement.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_peer_session::ports::PeerReplicaStatePort;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::admission::{AdmitResult, ChangeOrdering};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{
    CurrentVersionRecord, HeldState, LinkGate, MaterializationPolicy, MaterializationState,
    StartupFailed,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::ReplicaCoordinator;

#[async_trait::async_trait]
impl PeerReplicaStatePort for ReplicaCoordinator {
    async fn wait_group_ready(&self, group_id: &str) -> Result<(), StartupFailed> {
        ReplicaCoordinator::wait_group_ready(self, group_id).await
    }

    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    fn link_gate_for_group(&self, group_id: &str) -> Result<LinkGate, PeerSessionError> {
        self.link_repository()
            .link_gate_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn materialization_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<MaterializationPolicy>, PeerSessionError> {
        self.link_repository()
            .materialization_policy_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn windows_symlink_opt_in_for_group(&self, group_id: &str) -> Result<bool, PeerSessionError> {
        self.link_repository()
            .windows_symlink_opt_in_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .get_file(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .get_files_by_paths(group_id, paths)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn has_real_current_row(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .has_real_current_row(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, PeerSessionError> {
        self.file_index_repository()
            .get_record_kind(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, PeerSessionError> {
        self.file_index_repository()
            .get_symlink_target(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .get_symlink_out_of_root(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .get_exec_bit(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError> {
        self.file_index_repository()
            .get_origin_device_id(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError> {
        self.file_index_repository()
            .get_authoring_change_hash(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
        hash: &ChangeHash,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_authoring_change_hash(group_id, path, hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, PeerSessionError> {
        self.materialization_state_repository()
            .get_materialization_state(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .set_materialization_state(group_id, path, state, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn transition_materialization_state_if_same_authoring(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        expected_authoring_hash: Option<&ChangeHash>,
        next: MaterializationState,
    ) -> Result<bool, PeerSessionError> {
        self.materialization_state_repository()
            .transition_materialization_state_if_same_authoring(
                group_id,
                path,
                expected,
                expected_authoring_hash,
                next,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn record_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
        fingerprint: Option<yadorilink_sync_sqlite::MaterializedFingerprint>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .record_materialized_fingerprint(group_id, path, fingerprint, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn record_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .record_placeholder_generation(group_id, path, identity, provider_kind, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<yadorilink_local_storage::PlaceholderDiskIdentity, PeerSessionError> {
        self.materialization_state_repository()
            .record_placeholder_generation_if_absent(
                group_id,
                path,
                candidate,
                provider_kind,
                permit,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .clear_placeholder_generation(group_id, path, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .is_pinned(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_pinned(&self, group_id: &str, path: &str, pinned: bool) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_pinned(group_id, path, pinned)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .touch_last_accessed(group_id, path, unix_ts)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn clear_held(&self, group_id: &str, path: &str) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .clear_held(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .set_held(group_id, path, reason, since_unix_nanos)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.materialization_job_repository()
            .has_materialization_intent(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, PeerSessionError> {
        self.materialization_state_repository()
            .list_materialization_repair_candidates(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn materialization_enqueue_pending(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &[u8],
        trigger_lamport: u64,
        now: i64,
    ) -> Result<(), PeerSessionError> {
        self.materialization_job_repository()
            .materialization_enqueue_pending(group_id, path, version_hash, trigger_lamport, now)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn notify_materialization_wake(&self) {
        self.materialization_wake().notify_materialization_wake()
    }

    fn notify_retirement_wake(&self, group_id: &str) {
        self.retirement_wake().mark_dirty(group_id)
    }

    fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        self.dirty_path_repository()
            .is_path_dirty(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::VersionRecord>, PeerSessionError>
    {
        self.sqlite()
            .dag_list_versions(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .upsert_file_with_origin(group_id, record, origin_device_id, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn upsert_file_with_origin_and_author(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: &ChangeHash,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .upsert_file_with_origin_and_author(
                group_id,
                record,
                origin_device_id,
                authoring_change_hash,
                permit,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn group_has_block_provenance(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError> {
        self.sqlite()
            .dag_group_has_block_provenance(group_id, block_hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), PeerSessionError> {
        self.change_history_repository()
            .record_group_block_provenance(group_id, block_hashes)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn record_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
        reason: &str,
        refused_at_unix_nanos: i64,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .record_block_fetch_refusal(
                group_id,
                path,
                version_hash,
                peer_device_id,
                reason,
                refused_at_unix_nanos,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .clear_block_fetch_refusal(group_id, path, version_hash, peer_device_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, PeerSessionError> {
        self.sqlite()
            .dag_group_heads(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_group_history_paths(&self, group_id: &str) -> Result<HashSet<String>, PeerSessionError> {
        self.change_history_repository()
            .dag_group_history_paths(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_list_unapplied_changes(&self, group_id: &str) -> Result<Vec<Change>, PeerSessionError> {
        self.change_history_repository()
            .dag_list_unapplied_changes(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, PeerSessionError> {
        self.change_history_repository()
            .dag_has_change(hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_has_change_or_pruned(
        &self,
        group_id: &str,
        hash: &ChangeHash,
    ) -> Result<bool, PeerSessionError> {
        self.change_history_repository()
            .dag_has_change_or_pruned(group_id, hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn current_authoring_relation(
        &self,
        group_id: &str,
        path: &str,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, PeerSessionError> {
        self.change_history_repository()
            .current_authoring_relation(group_id, path, incoming)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_missing_ancestor_frontier(
        &self,
        roots: Vec<ChangeHash>,
    ) -> Result<Vec<ChangeHash>, PeerSessionError> {
        self.sqlite()
            .dag_missing_ancestor_frontier(roots)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, PeerSessionError> {
        self.sqlite().dag_get_change(hash).map_err(SyncError::from).map_err(PeerSessionError::from)
    }

    fn dag_get_encoded(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, PeerSessionError> {
        self.sqlite().dag_get_encoded(hash).map_err(SyncError::from).map_err(PeerSessionError::from)
    }

    fn dag_has_file_version(
        &self,
        group_id: &str,
        hash: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, PeerSessionError> {
        self.sqlite()
            .dag_has_file_version(group_id, hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<Option<FileVersion>, PeerSessionError> {
        self.sqlite()
            .dag_get_file_version(group_id, hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, PeerSessionError> {
        self.sqlite().dag_parents_of(hash).map_err(SyncError::from).map_err(PeerSessionError::from)
    }

    fn dag_is_ancestor(
        &self,
        ancestor: &ChangeHash,
        descendant: &ChangeHash,
    ) -> Result<bool, PeerSessionError> {
        self.change_history_repository()
            .dag_is_ancestor(ancestor, descendant)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
        applied: bool,
    ) -> Result<AdmitResult, PeerSessionError> {
        self.change_history_repository()
            .dag_admit_change_with_versions(change, versions, applied)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), PeerSessionError> {
        self.change_history_repository()
            .dag_mark_applied(hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_get_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError> {
        self.change_history_repository()
            .dag_get_device_frontier(group_id, device_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<
        Box<dyn yadorilink_peer_session::ports::OpenMaterializationIntent + Send + 'a>,
        PeerSessionError,
    > {
        let guard = crate::materialization_intent::MaterializationIntentGuard::open(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )
        .map_err(SyncError::from)
        .map_err(PeerSessionError::from)?;
        Ok(Box::new(guard))
    }

    fn verify_root(&self, root: &Path, group_id: &str) -> Result<(), PeerSessionError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(root, group_id, self)
            .map(|_| ())
            .map_err(PeerSessionError::from)
    }

    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .list_files(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_compare_authoring(
        &self,
        group_id: &str,
        local: &ChangeHash,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, PeerSessionError> {
        self.change_history_repository()
            .dag_compare_authoring(group_id, local, incoming)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError> {
        self.change_history_repository()
            .dag_group_file_version_references_block(group_id, block_hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn group_retained_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .group_retained_version_references_block(group_id, block_hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, PeerSessionError> {
        self.sqlite()
            .dag_get_current_version_record(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, PeerSessionError> {
        self.materialization_state_repository()
            .get_held_state(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn record_acknowledged_frontier(
        &self,
        group: &yadorilink_replica_domain::ids::FolderGroupId,
        device: &yadorilink_replica_domain::ids::DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), PeerSessionError> {
        yadorilink_replica_engine::compaction::record_acknowledged_frontier(
            self, group, device, frontier,
        )
        .map_err(PeerSessionError::from)
    }

    fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .ensure_bootstrap_row_for_metadata(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_record_kind(group_id, path, kind, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_symlink_target(group_id, path, target)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_symlink_out_of_root(group_id, path, out_of_root)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_exec_bit(group_id, path, exec_bit, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves the direct impl above lets a real `Arc<ReplicaCoordinator>`
    /// unsize-coerce to `Arc<dyn PeerReplicaStatePort>`, and that calls
    /// through the coerced handle still dispatch correctly -- mirrors
    /// `yadorilink-sync-core`'s own `arc_sync_state_coerces_to_port_trait`.
    #[test]
    fn arc_replica_coordinator_coerces_to_port_trait() {
        let coordinator: Arc<ReplicaCoordinator> =
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let port: Arc<dyn PeerReplicaStatePort> = coordinator;

        let _lock = port.path_lock("group-a", "path/a.txt");
        assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
    }
}
