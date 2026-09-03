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

/// Process-wide cache for [`dag_zero_work_settlement_if_already_current`]'s
/// disk revalidation. A real granularity probe (`fs_capabilities::
/// probe_birth_time_granularity`) performs its own file creation/deletion
/// to measure clock resolution -- genuine physical work, which is exactly
/// what the zero-work pre-check exists to avoid paying on every call.
/// Probing once per sync root and reusing the result for the rest of the
/// daemon's process lifetime keeps the *steady-state* cost at zero, at the
/// price of one one-time bootstrap probe the first time any path under a
/// given root is checked. `TimestampGranularity::Coarse` unconditionally
/// (no probe at all) was tried first and rejected: on a filesystem that
/// does not expose `generation_or_usn` (unprivileged `FS_IOC_GETVERSION`
/// is commonly unavailable, and never available on overlayfs -- see
/// `FileIdentity::compare`'s own doc), `Coarse` treats even a perfectly
/// matching birth time as `Ambiguous`, never `SameObject` -- meaning the
/// zero-work close could never fire at all on such a filesystem, not
/// merely miss an optimization on it.
///
/// Keyed by the sync root's `VolumeIdentity`, not its path: this crate's
/// own `fs_capabilities` module (see `CapabilityCacheKey`'s own doc, and
/// its module doc's "a volume change... always misses the cache") already
/// establishes that a path is not a stable proxy for a filesystem --
/// removable drives can be reformatted at the same mountpoint, and
/// network/container mounts can be replaced entirely, both without the
/// path ever changing. `PeerSyncSession` itself already re-verifies root
/// identity immediately before a write for exactly this reason (see
/// `verify_root`'s own call sites), so this is an established, defended-
/// against failure mode in this codebase, not a hypothetical one. A
/// path-keyed cache would silently keep serving a stale volume's
/// granularity after a remount at the same path, which could let a
/// `Coarse`-appropriate replacement filesystem be wrongly treated as
/// `Fine` and turn a false `SameObject` into an incorrect zero-work close.
/// Keying by `VolumeIdentity` instead makes a remount (a different
/// identity at the same path) a fresh cache miss automatically, exactly
/// like `CapabilityCacheKey` already does for every other probed
/// capability. Falls back to an uncached probe (never a stale answer) if
/// the volume identity itself cannot even be observed.
static BIRTH_TIME_GRANULARITY_CACHE: std::sync::OnceLock<
    std::sync::Mutex<
        HashMap<
            yadorilink_root_authority::fs_identity::VolumeIdentity,
            yadorilink_root_authority::fs_identity::TimestampGranularity,
        >,
    >,
> = std::sync::OnceLock::new();

fn cached_birth_time_granularity(
    sync_root: &Path,
) -> yadorilink_root_authority::fs_identity::TimestampGranularity {
    let Ok(volume_identity) = yadorilink_root_authority::fs_capabilities::observe_volume_identity(sync_root)
    else {
        return yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(sync_root);
    };
    cached_granularity_for_volume(volume_identity, || {
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(sync_root)
    })
}

/// The pure caching decision `cached_birth_time_granularity` delegates to,
/// factored out so a test can exercise "same volume identity reuses the
/// cached probe; a different one re-probes" directly with synthetic
/// identities, without needing to actually remount a real volume.
fn cached_granularity_for_volume(
    volume_identity: yadorilink_root_authority::fs_identity::VolumeIdentity,
    probe: impl FnOnce() -> yadorilink_root_authority::fs_identity::TimestampGranularity,
) -> yadorilink_root_authority::fs_identity::TimestampGranularity {
    let cache = BIRTH_TIME_GRANULARITY_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard.entry(volume_identity).or_insert_with(probe)
}

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

    fn get_unix_mode(&self, group_id: &str, path: &str) -> Result<Option<u32>, PeerSessionError> {
        self.file_index_repository()
            .get_unix_mode(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, PeerSessionError> {
        self.file_index_repository()
            .get_xattrs(group_id, path)
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
        self.materialization_intent_repository()
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

    fn notify_materialization_wake(&self) {
        self.materialization_wake().notify_materialization_wake()
    }

    fn notify_retirement_wake(&self, group_id: &str) {
        self.retirement_wake().mark_dirty(group_id)
    }

    fn notify_hazard_recheck_wake(&self, group_id: &str) {
        self.hazard_recheck_wake().mark_dirty(group_id)
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

    fn group_has_block_provenance_batch(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<std::collections::HashSet<Vec<u8>>, PeerSessionError> {
        self.sqlite()
            .dag_group_has_block_provenance_batch(group_id, block_hashes)
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

    fn dag_admit_change_batch_with_versions(
        &self,
        items: &[(&Change, &[FileVersion], bool)],
    ) -> Vec<Result<AdmitResult, PeerSessionError>> {
        let pending: Vec<yadorilink_sync_sqlite::PendingAdmission<'_>> = items
            .iter()
            .map(|(change, versions, applied)| yadorilink_sync_sqlite::PendingAdmission {
                change,
                versions,
                applied: *applied,
            })
            .collect();
        self.change_history_repository()
            .dag_admit_change_batch_with_versions(&pending)
            .into_iter()
            .map(|r| r.map_err(SyncError::from).map_err(PeerSessionError::from))
            .collect()
    }

    fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), PeerSessionError> {
        self.change_history_repository()
            .dag_mark_applied(hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        mutation_kind: &str,
    ) -> Result<i64, PeerSessionError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::materialized_generation::bump_mutation_fence(
                    tx,
                    group_id,
                    path,
                    mutation_kind,
                    now,
                )
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_snapshot_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, PeerSessionError> {
        self.database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::materialized_generation::snapshot_mutation_fence(
                    tx, group_id, path,
                )
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn dag_publish_materialized_generation_if_fence_current(
        &self,
        group_id: &str,
        path: &str,
        causal_basis: &[ChangeHash],
        state: yadorilink_peer_session::ports::ExactActualState,
        expected_mutation_generation: i64,
    ) -> Result<bool, PeerSessionError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let (sync_kind, version, filesystem_identity) = match state {
            yadorilink_peer_session::ports::ExactActualState::Object { kind, version, identity } => {
                let sync_kind = match kind {
                    RecordKind::File => {
                        yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
                    }
                    RecordKind::Directory => {
                        yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Directory
                    }
                    RecordKind::Symlink => {
                        yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Symlink
                    }
                };
                (sync_kind, Some(version), identity)
            }
            yadorilink_peer_session::ports::ExactActualState::Absent => {
                (yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent, None, None)
            }
        };
        let published = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::materialized_generation::publish_materialized_generation_if_fence_current(
                    tx,
                    group_id,
                    path,
                    causal_basis,
                    sync_kind,
                    version.as_ref(),
                    filesystem_identity.as_ref(),
                    expected_mutation_generation,
                    now,
                )
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        Ok(published.is_some())
    }

    fn dag_has_usable_materialized_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        Ok(self
            .sqlite()
            .dag_lookup_materialized_generation(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
            .is_some())
    }

    fn dag_zero_work_settlement_if_already_current(
        &self,
        group_id: &str,
        path: &str,
        resolution: &yadorilink_replica_engine::conflict::PathResolution,
        winner_version_hash: Option<&yadorilink_replica_domain::ids::VersionHash>,
    ) -> Result<Option<(yadorilink_peer_session::ports::ExactActualState, i64)>, PeerSessionError>
    {
        let desired_hash = self
            .sqlite()
            .dag_desired_resolved_path_state_hash(group_id, path, resolution, winner_version_hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        let Some(basis) = self
            .sqlite()
            .dag_lookup_materialized_generation(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
        else {
            return Ok(None);
        };
        if basis.resolved_path_state_hash != desired_hash {
            return Ok(None);
        }
        let sync_root = match self
            .link_repository()
            .link_gate_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
        {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                std::path::PathBuf::from(local_path)
            }
            LinkGate::NoLiveLink => return Ok(None),
        };
        let out_path = sync_root.join(path);
        let granularity = cached_birth_time_granularity(&sync_root);
        let revalidation = yadorilink_sync_sqlite::materialized_generation::revalidate_identity_against_disk(
            &basis, &out_path, granularity,
        );
        if revalidation
            != yadorilink_sync_sqlite::materialized_generation::IdentityRevalidation::Confirmed
        {
            return Ok(None);
        }
        let exact_state = match basis.object_kind {
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent => {
                yadorilink_peer_session::ports::ExactActualState::Absent
            }
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile => {
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: basis.version.ok_or_else(|| {
                        PeerSessionError::from(SyncError::from(yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                            "a non-Absent materialized generation must carry a version".into(),
                        )))
                    })?,
                    identity: basis.filesystem_identity,
                }
            }
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Directory => {
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::Directory,
                    version: basis.version.ok_or_else(|| {
                        PeerSessionError::from(SyncError::from(yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                            "a non-Absent materialized generation must carry a version".into(),
                        )))
                    })?,
                    identity: basis.filesystem_identity,
                }
            }
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Symlink => {
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::Symlink,
                    version: basis.version.ok_or_else(|| {
                        PeerSessionError::from(SyncError::from(yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                            "a non-Absent materialized generation must carry a version".into(),
                        )))
                    })?,
                    identity: basis.filesystem_identity,
                }
            }
        };
        let mutation_generation = self.dag_snapshot_mutation_fence(group_id, path)?;
        Ok(Some((exact_state, mutation_generation)))
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

    fn open_projected_upserts_batch(
        &self,
        group_id: &str,
        upserts: &[yadorilink_peer_session::ports::PreparedProjectedUpsert],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        if upserts.is_empty() {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                for u in upserts {
                    yadorilink_sync_sqlite::MaterializationIntentRepository::begin_materialization_intent_in_tx(
                        tx,
                        group_id,
                        &u.rel_path,
                        &u.target_version_hash,
                        now,
                    )?;
                    yadorilink_sync_sqlite::file_index::upsert_file_in_tx(
                        tx,
                        group_id,
                        &u.record,
                        &u.origin_device_id,
                        u.authoring_change_hash.as_ref(),
                    )?;
                    // The schema's own column default no longer supplies
                    // this (v25 changed it to `Placeholder` -- see
                    // `SCHEMA_VERSION`'s doc comment): this batch's whole
                    // crash-recovery design depends on the row reading
                    // `Hydrated` with the intent above still open, so a
                    // crash before the disk publish below is disambiguated
                    // from a genuine offline deletion by the intent, exactly
                    // as an unbatched `materialize()`'s equivalent write
                    // already is. Must say so explicitly now.
                    if !u.record.deleted {
                        yadorilink_sync_sqlite::MaterializationStateRepository::set_materialization_state_in_tx(
                            tx,
                            group_id,
                            &u.rel_path,
                            yadorilink_replica_domain::session_state::MaterializationState::Hydrated,
                        )?;
                    }
                    // C4-7: applied here, in the SAME transaction as the
                    // row/intent above, instead of `revalidate_ordinary_
                    // upsert` calling `apply_incoming_wire_metadata`
                    // per-candidate (its own separate `writer_gate` hit,
                    // defeating this batch's "2 transactions total"
                    // design). Must run strictly after `upsert_file_in_tx`
                    // -- see `apply_local_meta_columns_in_tx`'s own doc
                    // comment -- which this loop already guarantees.
                    yadorilink_sync_sqlite::file_index::apply_local_meta_columns_in_tx(
                        tx,
                        group_id,
                        &u.rel_path,
                        &u.metadata,
                    )?;
                    yadorilink_sync_sqlite::MaterializationStateRepository::clear_held_in_tx(
                        tx, group_id, &u.rel_path,
                    )?;
                }
                permit.verify()?;
                Ok(())
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn finalize_projected_mutations_batch(
        &self,
        group_id: &str,
        finished_upserts: &[yadorilink_peer_session::ports::FinishedProjectedUpsert],
        deletes: &[yadorilink_peer_session::ports::PreparedProjectedDelete],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        if finished_upserts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        self.database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                for u in finished_upserts {
                    yadorilink_sync_sqlite::MaterializationStateRepository::record_materialized_fingerprint_in_tx(
                        tx,
                        group_id,
                        &u.rel_path,
                        u.fingerprint,
                    )?;
                    yadorilink_sync_sqlite::MaterializationIntentRepository::clear_materialization_intent_in_tx(
                        tx,
                        group_id,
                        &u.rel_path,
                    )?;
                }
                for d in deletes {
                    yadorilink_sync_sqlite::MaterializationStateRepository::clear_held_in_tx(
                        tx, group_id, &d.rel_path,
                    )?;
                    yadorilink_sync_sqlite::file_index::upsert_file_in_tx(
                        tx,
                        group_id,
                        &d.record,
                        &d.origin_device_id,
                        d.authoring_change_hash.as_ref(),
                    )?;
                }
                permit.verify()?;
                Ok(())
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
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

    fn diagnostic_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError> {
        self.sqlite()
            .dag_lookup_projection_obligation(group_id, path)
            .map(|obligation| obligation.map(|o| format!("{o:?}")))
            .map_err(SyncError::from)
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

    fn set_unix_mode(
        &self,
        group_id: &str,
        path: &str,
        unix_mode: Option<u32>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_unix_mode(group_id, path, unix_mode, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn set_xattrs(
        &self,
        group_id: &str,
        path: &str,
        xattrs: &[(String, Vec<u8>)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .set_xattrs(group_id, path, xattrs, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn apply_incoming_metadata_atomic(
        &self,
        group_id: &str,
        path: &str,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .apply_incoming_metadata_atomic(group_id, path, meta, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    fn apply_projected_row_atomic(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .apply_projected_row_atomic(
                group_id,
                record,
                origin_device_id,
                authoring_change_hash,
                meta,
                permit,
            )
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

    /// The granularity cache must be keyed by volume identity, not by
    /// path: a real path can outlive the volume mounted at it (a removable
    /// drive reformatted at the same mountpoint, a network/container mount
    /// replaced entirely), and this codebase already treats that as a real
    /// threat, not a hypothetical one (`PeerSyncSession` re-verifies root
    /// identity immediately before every write for exactly this reason).
    /// Uses two distinct synthetic `VolumeIdentity` values rather than an
    /// actual remount (impractical in a unit test) to prove the caching
    /// decision itself: the SAME identity must reuse an already-cached
    /// probe (never re-probing), and a DIFFERENT identity must always
    /// re-probe, regardless of how many times the first one was already
    /// cached. Confirmed genuinely RED by temporarily keying the cache on
    /// a constant instead of the given identity: the second, different-
    /// identity call then wrongly reused the first identity's cached
    /// value instead of re-probing.
    #[test]
    fn granularity_cache_reprobes_on_a_different_volume_identity_but_not_the_same_one() {
        use yadorilink_root_authority::fs_identity::{TimestampGranularity, VolumeIdentity};

        let volume_a = VolumeIdentity::Unix { device_id: 0xAAAA };
        let volume_b = VolumeIdentity::Unix { device_id: 0xBBBB };

        let probes_for_a = std::sync::atomic::AtomicU32::new(0);
        let first = cached_granularity_for_volume(volume_a, || {
            probes_for_a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            TimestampGranularity::Fine
        });
        let second = cached_granularity_for_volume(volume_a, || {
            probes_for_a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            TimestampGranularity::Coarse
        });
        assert_eq!(first, TimestampGranularity::Fine);
        assert_eq!(second, TimestampGranularity::Fine, "the same volume identity must reuse the cached probe");
        assert_eq!(probes_for_a.load(std::sync::atomic::Ordering::SeqCst), 1, "must probe only once for the same identity");

        let probes_for_b = std::sync::atomic::AtomicU32::new(0);
        let third = cached_granularity_for_volume(volume_b, || {
            probes_for_b.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            TimestampGranularity::Coarse
        });
        assert_eq!(
            third,
            TimestampGranularity::Coarse,
            "a different volume identity must be probed fresh, never inherit another volume's \
             cached answer -- exactly the case of a remount at the same path"
        );
        assert_eq!(probes_for_b.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
