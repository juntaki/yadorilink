//! `impl yadorilink_filesystem_sync::materialization_execution::
//! MaterializationExecutionPort for ReplicaCoordinator` -- Phase 7D-10.5,
//! unblocked by 7D-10.4's `MaterializationIntentGuard` generalization.
//! Byte-identical in logic to `yadorilink-sync-core`'s own `impl
//! MaterializationExecutionPort for SyncState`
//! (`crates/yadorilink-sync-core/src/ports/materialization_execution_impl.rs`),
//! against `ReplicaCoordinator`'s own accessors. The three snapshot methods
//! and `reclaim_cached_blocks` delegate the same way the `SyncState` impl
//! does: through this same crate's own `MaterializationStatePort` impl
//! (`materialization_state.rs`, this pass) for the snapshots, and through
//! `yadorilink_sync_sqlite::block_deletion::BlockDeletionCoordinator`
//! (`MaterializationStatePort` and `block_deletion` both relocated there
//! from `yadorilink-sync-core`, see `docs/design/phase7d10-exit-report.md`'s
//! "item 1" addendum) for block reclamation.

use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_filesystem_sync::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_filesystem_sync::materialization_execution::{
    EvictionEligibilitySnapshot as ExecEvictionEligibilitySnapshot,
    EvictionRevalidationSnapshot as ExecEvictionRevalidationSnapshot,
    MaterializationExecutionError, MaterializationExecutionPort, OpenMaterializationIntent,
    RepairRowSnapshot as ExecRepairRowSnapshot,
};
use yadorilink_filesystem_sync::materialization_types::{
    EvictableFile, RestoreCommitOutcome, RestoreOperation,
};
use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;
use yadorilink_sync_sqlite::materialization_state_port::MaterializationStatePort;

use super::ReplicaCoordinator;

impl MaterializationExecutionPort for ReplicaCoordinator {
    fn get_exec_bit(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self.file_index_repository().get_exec_bit(group_id, path).map_err(SyncError::from)?)
    }

    fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, MaterializationExecutionError> {
        Ok(self.file_index_repository().get_file(group_id, path).map_err(SyncError::from)?)
    }

    fn list_evictable_files(
        &self,
        group_id: &str,
    ) -> Result<Vec<EvictableFile>, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .list_evictable_files(group_id)
            .map_err(SyncError::from)?)
    }

    fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .hydrated_usage_bytes(group_id)
            .map_err(SyncError::from)?)
    }

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .file_index_repository()
            .touch_last_accessed(group_id, path, unix_ts)
            .map_err(SyncError::from)?)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<String, MaterializationState>,
        MaterializationExecutionError,
    > {
        Ok(self
            .materialization_state_repository()
            .list_materialization_states(group_id)
            .map_err(SyncError::from)?)
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .materialization_job_repository()
            .has_materialization_intent(group_id, path)
            .map_err(SyncError::from)?)
    }

    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_job_repository()
            .clear_materialization_intent(group_id, path, permit)
            .map_err(SyncError::from)?)
    }

    fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_job_repository()
            .begin_materialization_intent(group_id, path, target_version_hash, permit)
            .map_err(SyncError::from)?)
    }

    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, MaterializationExecutionError> {
        Ok(ReplicaCoordinator::mark_deleted_emitting_change(
            self,
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            emitter,
            permit,
        )?)
    }

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .dirty_path_repository()
            .record_dirty_path(group_id, path, change_kind, observed_at_unix_nanos, permit)
            .map_err(SyncError::from)?)
    }

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .set_materialization_state(group_id, path, state, permit)
            .map_err(SyncError::from)?)
    }

    fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .transition_materialization_state(group_id, path, expected, next, permit)
            .map_err(SyncError::from)?)
    }

    fn record_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .record_placeholder_generation(group_id, path, identity, provider_kind, permit)
            .map_err(SyncError::from)?)
    }

    fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<yadorilink_local_storage::PlaceholderDiskIdentity, MaterializationExecutionError>
    {
        Ok(self
            .materialization_state_repository()
            .record_placeholder_generation_if_absent(
                group_id,
                path,
                candidate,
                provider_kind,
                permit,
            )
            .map_err(SyncError::from)?)
    }

    fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .clear_placeholder_generation(group_id, path, permit)
            .map_err(SyncError::from)?)
    }

    fn list_placeholder_paths_missing_generation(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .list_placeholder_paths_missing_generation(group_id)
            .map_err(SyncError::from)?)
    }

    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .list_restore_operations(group_id)
            .map_err(SyncError::from)?)
    }

    fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .commit_restore_operation(operation_id)
            .map_err(SyncError::from)?)
    }

    fn discard_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .discard_restore_operation(operation_id)
            .map_err(SyncError::from)?)
    }

    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError> {
        Ok(VerifiedRoot::verify(root, group_id, self)?)
    }

    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError> {
        Ok(VerifiedRoot::open(root, group_id, self)?)
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError> {
        let guard = crate::materialization_intent::MaterializationIntentGuard::open(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )
        .map_err(SyncError::from)?;
        Ok(Box::new(guard))
    }

    fn eviction_eligibility_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecEvictionEligibilitySnapshot, MaterializationExecutionError> {
        let snapshot =
            <ReplicaCoordinator as MaterializationStatePort>::eviction_eligibility_snapshot(
                self, group_id, path,
            )
            .map_err(SyncError::from)?;
        Ok(ExecEvictionEligibilitySnapshot {
            pinned: snapshot.pinned,
            current_version: snapshot.current_version,
            record_kind: snapshot.record_kind,
        })
    }

    fn eviction_revalidation_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecEvictionRevalidationSnapshot, MaterializationExecutionError> {
        let snapshot =
            <ReplicaCoordinator as MaterializationStatePort>::eviction_revalidation_snapshot(
                self, group_id, path,
            )
            .map_err(SyncError::from)?;
        Ok(ExecEvictionRevalidationSnapshot {
            current_version: snapshot.current_version,
            pinned: snapshot.pinned,
            materialization_state: snapshot.materialization_state,
            path_dirty: snapshot.path_dirty,
        })
    }

    fn repair_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecRepairRowSnapshot, MaterializationExecutionError> {
        let snapshot = <ReplicaCoordinator as MaterializationStatePort>::repair_row_snapshot(
            self, group_id, path,
        )
        .map_err(SyncError::from)?;
        Ok(ExecRepairRowSnapshot {
            materialization_state: snapshot.materialization_state,
            record_kind: snapshot.record_kind,
            file: snapshot.file,
        })
    }

    fn reclaim_verified_cached_blocks(
        &self,
        deletion_guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, MaterializationExecutionError> {
        Ok(yadorilink_sync_sqlite::block_deletion::BlockDeletionCoordinator::new(store)
            .reclaim_cached_blocks(deletion_guard, custody, self)
            .map_err(SyncError::from)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use yadorilink_filesystem_sync::block_liveness::BlockLivenessGate;
    use yadorilink_filesystem_sync::materialization_eviction::{
        evict_file, MaterializationContext,
    };
    use yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations;
    use yadorilink_local_storage::{BlockStore as _, FsBlockStore};
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    use yadorilink_replica_domain::ids::VersionHash;
    use yadorilink_replica_domain::session_state::MaterializationState;
    use yadorilink_replica_engine::custody::{CustodyStamp, FullReplicaCustody};
    use yadorilink_root_authority::root_commit::RootCommitPermit;
    use yadorilink_root_authority::root_identity::VerifiedRoot;

    /// A custody oracle that never confirms anything. Note (an independent
    /// review's finding): with today's `REMOTE_CUSTODY_LEASES_SUPPORTED =
    /// false` global kill switch, `verify_reclaim_custody` returns `None`
    /// unconditionally BEFORE ever consulting any oracle -- so a test using
    /// this stub cannot, by itself, distinguish "the oracle said no" from
    /// "custody leases are globally unsupported today." Kept for the
    /// day `REMOTE_CUSTODY_LEASES_SUPPORTED` flips (at which point this
    /// stub starts actually being consulted), and to make the test using
    /// it self-documenting about which case is real right now.
    struct NeverConfirms;

    impl FullReplicaCustody for NeverConfirms {
        fn confirm_exact_version(
            &self,
            _: &str,
            _: &str,
            _: &VersionHash,
            _: &[yadorilink_replica_domain::file::VersionBlock],
        ) -> Option<CustodyStamp> {
            None
        }

        fn confirmation_still_valid(&self, _: &str, _: &CustodyStamp) -> bool {
            false
        }
    }

    /// A custody oracle that panics if it is ever consulted -- proves
    /// `evict_file` rejects a pinned file WITHOUT reading any version or
    /// custody state at all, not merely that it happens to reject one an
    /// oracle would also have refused. An independent review's finding: a
    /// plain rejection assertion with a permissive oracle (`AlwaysConfirmed`)
    /// cannot distinguish "checked pinned first" from "checked custody
    /// first, which also would have failed."
    struct PanicsIfConsulted;

    impl FullReplicaCustody for PanicsIfConsulted {
        fn confirm_exact_version(
            &self,
            _: &str,
            _: &str,
            _: &VersionHash,
            _: &[yadorilink_replica_domain::file::VersionBlock],
        ) -> Option<CustodyStamp> {
            panic!("a pinned file's eviction must be rejected before custody is ever consulted");
        }

        fn confirmation_still_valid(&self, _: &str, _: &CustodyStamp) -> bool {
            panic!("a pinned file's eviction must be rejected before custody is ever consulted");
        }
    }

    /// M1-4: a pinned file must never be evicted -- `EvictionEligibilitySnapshot::pinned`
    /// is the very first check `evict_file` performs, before it reads any
    /// version or custody state. `PanicsIfConsulted` locks down that
    /// ordering directly rather than merely observing rejection.
    #[test]
    fn evict_rejects_a_pinned_file() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let content = b"pinned content must never be evicted";
        let record = store_and_record(&store, "a.bin", content);
        let permit = RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file("group-a", &record, &permit).unwrap();
        state.file_index_repository().set_pinned("group-a", "a.bin", true).unwrap();
        std::fs::write(root.path().join("a.bin"), content).unwrap();

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            "group-a",
            "a.bin",
            false,
            &PanicsIfConsulted,
        );

        assert!(
            matches!(result, Err(MaterializationExecutionError::EvictionRejected(_))),
            "a pinned file must be rejected outright, got {result:?}"
        );
        assert_eq!(
            std::fs::read(root.path().join("a.bin")).unwrap(),
            content,
            "the pinned file's own bytes must be untouched"
        );
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state("group-a", "a.bin")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "the row must be left exactly as it was"
        );
    }

    /// M1-4: on an on-demand (non-full-replica) device, an evicted file's
    /// content-addressed blocks are NEVER purged from the local block
    /// store while `REMOTE_CUSTODY_LEASES_SUPPORTED` stays `false` --
    /// `verify_reclaim_custody` returns `None` unconditionally at that
    /// gate, before ever consulting an oracle (an independent review's
    /// finding: `NeverConfirms` is not actually exercised here today --
    /// see its own doc comment). This test pins the CURRENT, observable
    /// production invariant (nothing is ever purged without a durable
    /// custody lease, and none exist yet) rather than claiming to prove
    /// oracle-specific handling this build cannot actually reach.
    #[test]
    fn evict_on_an_on_demand_device_frees_the_file_but_never_purges_its_blocks_today() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let content = b"content nobody else has confirmed custody of";
        let record = store_and_record(&store, "a.bin", content);
        let hash = hex::encode(&record.blocks[0].hash);
        let permit = RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file("group-a", &record, &permit).unwrap();
        std::fs::write(root.path().join("a.bin"), content).unwrap();

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            "group-a",
            "a.bin",
            false, // on-demand device, not a full replica
            &NeverConfirms,
        )
        .unwrap();

        assert!(outcome.dehydrated, "the working-tree copy is still freed");
        assert!(outcome.blocks_retained, "unconfirmed custody must never authorize a block purge");
        assert!(store.exists(&hash).unwrap(), "the block must survive on disk, unconfirmed");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state("group-a", "a.bin")
                .unwrap(),
            Some(MaterializationState::Placeholder)
        );
        // The working-tree file itself must actually have become a
        // placeholder -- not merely have its index row updated. An
        // independent review's finding: the prior version of this test
        // never inspected `a.bin` after eviction at all.
        assert_ne!(
            std::fs::read(root.path().join("a.bin")).unwrap(),
            content,
            "the real content must no longer be materialized on disk"
        );
        assert_eq!(
            std::fs::metadata(root.path().join("a.bin")).unwrap().len(),
            content.len() as u64,
            "the placeholder must still report the file's real size"
        );
    }

    /// M1-4: content that already diverged from the indexed version
    /// BEFORE `evict_file` is even called (an unsynced local edit landed
    /// sometime after the last index write, or any other source of
    /// pre-existing on-disk drift) must abort the eviction at its first
    /// `disk_bytes_match_indexed_blocks` check, before any placeholder is
    /// written -- never silently discard those bytes. An independent
    /// review's finding: this specifically exercises the FIRST divergence
    /// check (`materialization_eviction.rs`'s pre-lock read); it does NOT
    /// exercise the SECOND recheck performed after the path lock is
    /// acquired (the one that specifically closes a race occurring DURING
    /// this call itself) -- that revalidation has no direct test today.
    #[test]
    fn evict_aborts_when_disk_content_diverges_from_the_indexed_version() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let indexed_content = b"the version the index still believes is current";
        let record = store_and_record(&store, "a.bin", indexed_content);
        let hash = hex::encode(&record.blocks[0].hash);
        let permit = RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file("group-a", &record, &permit).unwrap();
        // A local edit landed on disk that the index does not know about
        // yet, before this call even begins.
        std::fs::write(root.path().join("a.bin"), b"a locally edited, unindexed replacement")
            .unwrap();

        let outcome = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            "group-a",
            "a.bin",
            false,
            &AlwaysConfirmed,
        )
        .unwrap();

        assert!(!outcome.dehydrated, "eviction must abort, not silently discard the local edit");
        assert!(outcome.blocks_retained);
        assert!(
            store.exists(&hash).unwrap(),
            "the aborted eviction must not touch the block store either"
        );
        assert_eq!(
            std::fs::read(root.path().join("a.bin")).unwrap(),
            b"a locally edited, unindexed replacement",
            "the unindexed local edit's bytes must survive untouched"
        );
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state("group-a", "a.bin")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "the row must be left exactly as it was, not stuck mid-transition"
        );
    }

    /// M1-5: reproduces the exact crash window an independent review found
    /// in M1-2's own design -- `write_placeholder` durably writes the
    /// sparse placeholder file, then its identity is recorded in a
    /// SEPARATE commit; a crash between the two leaves a `Placeholder`
    /// row with no recorded identity, even though the placeholder file on
    /// disk is genuinely untouched. Without a startup repair pass, the
    /// very next watcher tick on that path would fall through to the
    /// full chunk-and-compare path (no generation to compare against) and
    /// index the placeholder's own sparse/all-zero bytes as if they were
    /// real content -- `backfill_placeholder_generations` exists
    /// specifically to close this before any watcher gets a chance to
    /// observe the row. Unix-only: exercises the real captured-identity
    /// path, matching M1-2's own `#[cfg(unix)]` placeholder tests.
    #[test]
    #[cfg(unix)]
    fn backfill_placeholder_generations_recovers_the_write_placeholder_crash_window() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let permit = RootCommitPermit::for_tests();
        let size = 4096u64;
        state
            .file_index_repository()
            .upsert_file(
                "group-a",
                &FileRecord {
                    path: "a.bin".into(),
                    size,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash: vec![0xAB; 32], offset: 0, size: size as u32 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-a",
                "a.bin",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
        // Simulates exactly what `write_placeholder` leaves behind: a real
        // sparse file at the indexed size, durably on disk -- but,
        // crucially, NO `record_placeholder_generation` call ever ran
        // (the simulated crash).
        let identity =
            yadorilink_local_storage::write_placeholder(&root.path().join("a.bin"), size, 0)
                .unwrap()
                .expect("this test runs on unix, where an identity is always captured");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_placeholder_generation("group-a", "a.bin")
                .unwrap(),
            None,
            "precondition: the crash window leaves no identity recorded"
        );

        let backfilled =
            yadorilink_filesystem_sync::materialization_repair::backfill_placeholder_generations(
                &state,
                root.path(),
                "group-a",
                &permit,
            )
            .unwrap();

        assert_eq!(backfilled, 1);
        let recorded = state
            .materialization_state_repository()
            .get_placeholder_generation("group-a", "a.bin")
            .unwrap()
            .expect("the identity must now be recorded");
        assert_eq!(
            recorded.identity, identity,
            "the backfilled identity must match the real on-disk object, not a synthetic value"
        );
        assert_eq!(recorded.provider_kind, yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND);
    }

    /// A path whose on-disk content no longer matches the indexed size
    /// (a genuine local edit landed during the crash-to-restart window,
    /// however unlikely) must NOT be backfilled -- fabricating an
    /// identity for it would wrongly certify a file this process never
    /// actually wrote as "still untouched." Leaving it with no identity
    /// keeps it on the existing fail-closed full chunk-and-compare path,
    /// which is the correct outcome for genuinely divergent content.
    #[test]
    fn backfill_placeholder_generations_skips_a_path_whose_disk_size_no_longer_matches() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let permit = RootCommitPermit::for_tests();
        state
            .file_index_repository()
            .upsert_file(
                "group-a",
                &FileRecord {
                    path: "a.bin".into(),
                    size: 4096,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash: vec![0xAB; 32], offset: 0, size: 4096 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-a",
                "a.bin",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
        // Content of a DIFFERENT size than the index believes -- not the
        // placeholder this process would have written.
        std::fs::write(root.path().join("a.bin"), b"a genuine local edit, not a placeholder")
            .unwrap();

        let backfilled =
            yadorilink_filesystem_sync::materialization_repair::backfill_placeholder_generations(
                &state,
                root.path(),
                "group-a",
                &permit,
            )
            .unwrap();

        assert_eq!(backfilled, 0);
        assert_eq!(
            state
                .materialization_state_repository()
                .get_placeholder_generation("group-a", "a.bin")
                .unwrap(),
            None,
            "a diverged path must be left with no identity, staying on the fail-closed path"
        );
    }

    /// Proves the impl above lets a real `Arc<ReplicaCoordinator>`
    /// unsize-coerce to `Arc<dyn MaterializationExecutionPort>`, and that
    /// calls through the coerced handle still dispatch correctly -- same
    /// shape as `materialization_state::tests::
    /// arc_replica_coordinator_coerces_to_port_trait` for the wider port
    /// this one narrows.
    #[test]
    fn arc_replica_coordinator_coerces_to_execution_port_trait() {
        let coordinator: Arc<ReplicaCoordinator> =
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let port: Arc<dyn MaterializationExecutionPort> = coordinator;

        let _lock = port.path_lock("group-a", "path/a.txt");
        assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
    }

    fn adopt_root(state: &ReplicaCoordinator, group_id: &str, root: &Path) {
        state.link_repository().add_link(&root.to_string_lossy(), group_id).unwrap();
        VerifiedRoot::open(root, group_id, state).unwrap();
    }

    fn store_and_record(store: &FsBlockStore, path: &str, content: &[u8]) -> FileRecord {
        let hash = hex::decode(store.put(content).unwrap()).unwrap();
        FileRecord {
            path: path.to_owned(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        }
    }

    struct AlwaysConfirmed;

    impl FullReplicaCustody for AlwaysConfirmed {
        fn confirm_exact_version(
            &self,
            _: &str,
            _: &str,
            _: &VersionHash,
            _: &[yadorilink_replica_domain::file::VersionBlock],
        ) -> Option<CustodyStamp> {
            Some(CustodyStamp::new("test-peer".to_owned(), 0))
        }

        fn confirmation_still_valid(&self, _: &str, _: &CustodyStamp) -> bool {
            true
        }
    }

    fn assert_cross_group_reference_retains_shared_block(
        other_state: MaterializationState,
        pinned: bool,
    ) {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let content = b"same content shared across folder groups";
        let record_a = store_and_record(&store, "group-a.bin", content);
        let mut record_b = record_a.clone();
        record_b.path = "group-b.bin".to_owned();
        let hash = hex::encode(&record_a.blocks[0].hash);
        let permit = RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file("group-a", &record_a, &permit).unwrap();
        state.file_index_repository().upsert_file("group-b", &record_b, &permit).unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state("group-b", "group-b.bin", other_state, &permit)
            .unwrap();
        state.file_index_repository().set_pinned("group-b", "group-b.bin", pinned).unwrap();
        std::fs::write(root.path().join("group-a.bin"), content).unwrap();

        evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            "group-a",
            "group-a.bin",
            false,
            &AlwaysConfirmed,
        )
        .unwrap();

        assert!(store.exists(&hash).unwrap(), "another group still references the shared block");
    }

    #[test]
    fn eviction_must_not_delete_block_used_by_hydrated_file_in_another_group() {
        assert_cross_group_reference_retains_shared_block(MaterializationState::Hydrated, false);
    }

    #[test]
    fn eviction_must_not_delete_block_retained_for_uncustodied_placeholder_in_another_group() {
        assert_cross_group_reference_retains_shared_block(MaterializationState::Placeholder, false);
    }

    #[test]
    fn eviction_must_not_delete_block_used_by_pinned_file_in_another_group() {
        assert_cross_group_reference_retains_shared_block(MaterializationState::Hydrated, true);
    }

    #[test]
    fn concurrent_evictions_across_groups_must_preserve_shared_block() {
        use std::sync::Barrier;

        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root_a.path());
        adopt_root(&state, "group-b", root_b.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let content = b"concurrently evicted cross-group content";
        let record_a = store_and_record(&store, "a.bin", content);
        let mut record_b = record_a.clone();
        record_b.path = "b.bin".to_owned();
        let hash = hex::encode(&record_a.blocks[0].hash);
        let permit = RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file("group-a", &record_a, &permit).unwrap();
        state.file_index_repository().upsert_file("group-b", &record_b, &permit).unwrap();
        std::fs::write(root_a.path().join("a.bin"), content).unwrap();
        std::fs::write(root_b.path().join("b.bin"), content).unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let gate = Arc::new(BlockLivenessGate::default());
        let handles: Vec<_> = [
            ("group-a", "a.bin", root_a.path().to_owned()),
            ("group-b", "b.bin", root_b.path().to_owned()),
        ]
        .into_iter()
        .map(|(group_id, path, root)| {
            let state = state.clone();
            let store = store.clone();
            let barrier = barrier.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let permit = RootCommitPermit::for_tests();
                evict_file(
                    MaterializationContext {
                        state: state.as_ref(),
                        liveness_gate: gate.as_ref(),
                        store: store.as_ref(),
                        root: &root,
                        permit: &permit,
                    },
                    group_id,
                    path,
                    false,
                    &AlwaysConfirmed,
                )
                .unwrap();
            })
        })
        .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(
            store.exists(&hash).unwrap(),
            "concurrent cross-group eviction deleted shared block"
        );
    }

    fn record_with_blocks(path: &str, content: &[u8], hash: Vec<u8>) -> FileRecord {
        FileRecord {
            path: path.to_owned(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        }
    }

    #[test]
    fn repair_reconstructs_locally_after_a_simulated_crash_before_rename() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let content = b"hello from before the crash";
        let hash = hex::decode(store.put(content).unwrap()).unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        let permit = RootCommitPermit::for_tests();
        state
            .file_index_repository()
            .upsert_file("group-1", &record_with_blocks("doc.txt", content, hash), &permit)
            .unwrap();
        state
            .materialization_job_repository()
            .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
            .unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1", &permit)
                .unwrap();
        assert_eq!(report.reconstructed, vec!["doc.txt"]);
        assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
    }

    #[test]
    fn repair_demotes_to_placeholder_when_blocks_are_also_missing_locally() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(store_dir.path()).unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        let permit = RootCommitPermit::for_tests();
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &record_with_blocks("missing.bin", b"not present", vec![0xcd; 32]),
                &permit,
            )
            .unwrap();
        state
            .materialization_job_repository()
            .begin_materialization_intent("group-1", "missing.bin", &[0; 32], &permit)
            .unwrap();

        let report =
            repair_interrupted_materializations(&state, &store, root.path(), "group-1", &permit)
                .unwrap();
        assert_eq!(report.demoted_to_placeholder, vec!["missing.bin"]);
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state("group-1", "missing.bin")
                .unwrap(),
            Some(MaterializationState::Placeholder)
        );
    }

    /// Sets up a file row already transitioned to `Placeholder` -- matching
    /// every real caller, which always pairs `record_placeholder_generation`
    /// with that same transition (never calls it on a `Hydrated` row).
    fn setup_placeholder_file(
        group_id: &str,
        path: &str,
    ) -> (ReplicaCoordinator, RootCommitPermit<'static>) {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();
        state
            .file_index_repository()
            .upsert_file(group_id, &record_with_blocks(path, b"x", vec![0xab; 32]), &permit)
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(group_id, path, MaterializationState::Placeholder, &permit)
            .unwrap();
        (state, permit)
    }

    fn recorded(
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
    ) -> yadorilink_sync_sqlite::RecordedPlaceholderGeneration {
        yadorilink_sync_sqlite::RecordedPlaceholderGeneration {
            identity,
            provider_kind: "internal-inode".to_owned(),
        }
    }

    /// M1-2: a recorded placeholder identity survives an in-process
    /// "restart" (a fresh read through the repository, not merely an
    /// in-memory cache) -- the exact property `write_placeholder_backend`'s
    /// `PlaceholderGeneration` doc comment names as the second missing
    /// piece of a connected on-demand pipeline. `provider_kind` round-trips
    /// too, not merely the `(dev, ino)` pair.
    #[test]
    fn recorded_placeholder_generation_is_readable_after_being_recorded() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
        let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 7, ino: 42 };

        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "doc.txt",
                identity,
                "internal-inode",
                &permit,
            )
            .unwrap();

        assert_eq!(
            state
                .materialization_state_repository()
                .get_placeholder_generation("group-1", "doc.txt")
                .unwrap(),
            Some(recorded(identity))
        );
    }

    /// M2-2 review finding: `record_placeholder_generation_if_absent` must
    /// do its check-then-write atomically in one `database.write` closure
    /// -- pins the exact race an independent review found in this method's
    /// two-call predecessor (`get_placeholder_generation` then a separate
    /// `record_placeholder_generation`): a second "concurrent" mint for
    /// the same path with a DIFFERENT candidate identity must lose, not
    /// silently overwrite the first winner.
    #[test]
    fn record_placeholder_generation_if_absent_keeps_the_first_winner() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
        let first = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 1 };
        let second = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 2 };

        let winner_a = state
            .materialization_state_repository()
            .record_placeholder_generation_if_absent(
                "group-1",
                "doc.txt",
                first,
                "windows-cfapi-generation",
                &permit,
            )
            .unwrap();
        let winner_b = state
            .materialization_state_repository()
            .record_placeholder_generation_if_absent(
                "group-1",
                "doc.txt",
                second,
                "windows-cfapi-generation",
                &permit,
            )
            .unwrap();

        assert_eq!(winner_a, first);
        assert_eq!(winner_b, first, "the second caller must see the first caller's winning value");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_placeholder_generation("group-1", "doc.txt")
                .unwrap()
                .unwrap()
                .identity,
            first,
            "the persisted row must still hold the first-minted identity, never the second"
        );
    }

    /// A row already carrying a DIFFERENT provider's identity (e.g. the
    /// Unix `(dev, ino)` scheme) is treated as "nothing recorded for THIS
    /// provider yet" and overwritten -- matches
    /// `record_placeholder_generation`'s own unconditional behavior for
    /// that case, which this method must not silently change.
    #[test]
    fn record_placeholder_generation_if_absent_overwrites_a_different_providers_identity() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
        let unix_identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 7, ino: 42 };
        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "doc.txt",
                unix_identity,
                "internal-inode",
                &permit,
            )
            .unwrap();

        let windows_identity =
            yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 99 };
        let winner = state
            .materialization_state_repository()
            .record_placeholder_generation_if_absent(
                "group-1",
                "doc.txt",
                windows_identity,
                "windows-cfapi-generation",
                &permit,
            )
            .unwrap();

        assert_eq!(winner, windows_identity);
    }

    /// A path with no recorded identity -- never placeholdered, or cleared
    /// -- must read back `None`, not a synthetic zero identity: callers
    /// treat `None` as fail-closed "unknown", which a real `dev:0, ino:0`
    /// row would defeat.
    #[test]
    fn unrecorded_placeholder_generation_reads_back_as_none() {
        let (state, _permit) = setup_placeholder_file("group-1", "doc.txt");

        assert_eq!(
            state
                .materialization_state_repository()
                .get_placeholder_generation("group-1", "doc.txt")
                .unwrap(),
            None
        );
    }

    /// An independent review's finding: a row that has since left
    /// `Placeholder` (hydrated, say) must never expose its old identity
    /// through this getter, even though nothing explicitly cleared it --
    /// gated on the row's own current `materialization_state`, not merely
    /// on the recorded columns being non-NULL.
    #[test]
    fn placeholder_generation_is_hidden_once_the_row_leaves_placeholder_state() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
        let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
        let repo = state.materialization_state_repository();
        repo.record_placeholder_generation(
            "group-1",
            "doc.txt",
            identity,
            "internal-inode",
            &permit,
        )
        .unwrap();

        repo.set_materialization_state(
            "group-1",
            "doc.txt",
            MaterializationState::Hydrated,
            &permit,
        )
        .unwrap();

        assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
    }

    /// A newer placeholder write's identity must fully replace an older
    /// one -- `record_placeholder_generation` called twice for the same
    /// path leaves only the SECOND identity readable, never a stale first
    /// one a caller could wrongly trust. This is the exact "stale
    /// generation must not be trusted" invariant M1-2's roadmap step names.
    #[test]
    fn recording_a_new_generation_replaces_the_old_one() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
        let stale = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
        let fresh = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 2 };
        let repo = state.materialization_state_repository();
        repo.record_placeholder_generation("group-1", "doc.txt", stale, "internal-inode", &permit)
            .unwrap();

        repo.record_placeholder_generation("group-1", "doc.txt", fresh, "internal-inode", &permit)
            .unwrap();

        assert_eq!(
            repo.get_placeholder_generation("group-1", "doc.txt").unwrap(),
            Some(recorded(fresh))
        );
    }

    /// `clear_placeholder_generation` must actually erase the recorded
    /// identity, not merely become unreachable -- a stale identity left in
    /// place after a hydrate (say) could later be wrongly matched against a
    /// brand-new placeholder that happens to reuse the same inode number.
    #[test]
    fn clearing_a_placeholder_generation_removes_it() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
        let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
        let repo = state.materialization_state_repository();
        repo.record_placeholder_generation(
            "group-1",
            "doc.txt",
            identity,
            "internal-inode",
            &permit,
        )
        .unwrap();

        repo.clear_placeholder_generation("group-1", "doc.txt", &permit).unwrap();

        assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
    }

    /// Clearing a path that was never recorded is a no-op, not an error --
    /// mirrors `clear_held`'s own precedent so callers never need to check
    /// "was this ever a placeholder" first.
    #[test]
    fn clearing_an_unrecorded_placeholder_generation_is_not_an_error() {
        let (state, permit) = setup_placeholder_file("group-1", "doc.txt");

        state
            .materialization_state_repository()
            .clear_placeholder_generation("group-1", "doc.txt", &permit)
            .unwrap();
    }

    /// `list_placeholder_generations` is the bulk-load path
    /// `LocalChangeProcessor::scan_existing_files` will use -- it must
    /// include every recorded identity for the group and exclude paths
    /// with none, in one call.
    #[test]
    fn list_placeholder_generations_includes_only_recorded_paths() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &record_with_blocks("has-one.bin", b"x", vec![0xab; 32]),
                &permit,
            )
            .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &record_with_blocks("has-none.bin", b"y", vec![0xcd; 32]),
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "has-one.bin",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "has-none.bin",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
        let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 9, ino: 99 };
        state
            .materialization_state_repository()
            .record_placeholder_generation(
                "group-1",
                "has-one.bin",
                identity,
                "internal-inode",
                &permit,
            )
            .unwrap();

        let all = state
            .materialization_state_repository()
            .list_placeholder_generations("group-1")
            .unwrap();

        assert_eq!(all.get("has-one.bin"), Some(&recorded(identity)));
        assert!(!all.contains_key("has-none.bin"));
    }
}
