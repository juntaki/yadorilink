//! Single production boundary for physical content-addressed block deletion.

use std::collections::HashSet;
use std::time::SystemTime;

use yadorilink_local_storage::{BlockStore, ContentHash, GcReport};

use crate::block_liveness::BlockPhysicalDeletionGuard;
use crate::custody::VerifiedCustody;
use crate::index::SyncState;
use crate::types::MaterializationState;
use crate::SyncError;

pub enum BlockDeletionReason {
    GloballyUnreferenced,
    CorruptBlock,
}

pub struct BlockDeletionCoordinator<'a> {
    store: &'a dyn BlockStore,
}

impl<'a> BlockDeletionCoordinator<'a> {
    pub fn new(store: &'a dyn BlockStore) -> Self {
        Self { store }
    }

    pub fn sweep(
        &self,
        _guard: &BlockPhysicalDeletionGuard<'_>,
        reason: BlockDeletionReason,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, SyncError> {
        if !matches!(reason, BlockDeletionReason::GloballyUnreferenced) {
            return Err(SyncError::InvalidInput(
                "block-store sweep requires GloballyUnreferenced deletion reason".into(),
            ));
        }
        Ok(self.store.sweep(live, grace_cutoff, dry_run)?)
    }

    pub(crate) fn reclaim_cached_blocks(
        &self,
        _guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        state: &SyncState,
    ) -> Result<GcReport, SyncError> {
        let Some(current) = state.get_current_version_record(custody.group_id(), custody.path())?
        else {
            return Ok(GcReport::default());
        };
        if current.deleted {
            return Ok(GcReport::default());
        }
        let current = current.to_file_version();
        if current.version_hash != *custody.version_hash() || current.blocks != custody.blocks() {
            return Ok(GcReport::default());
        }
        // Custody confirmation may have waited on the network. Revalidate
        // local retention requirements under the exclusive deletion guard so
        // a concurrent pin or re-hydration cannot be followed by reclaiming
        // the blocks its final state requires.
        if state.is_pinned(custody.group_id(), custody.path())?
            || state.get_materialization_state(custody.group_id(), custody.path())?
                != Some(MaterializationState::Placeholder)
        {
            return Ok(GcReport::default());
        }
        if !custody.confirmation_still_valid() {
            return Ok(GcReport::default());
        }

        let needed =
            state.blocks_referenced_outside_current_file(custody.group_id(), custody.path())?;
        let reclaimable: Vec<String> = current
            .blocks
            .iter()
            .map(|block| hex::encode(&block.hash.0))
            .filter(|hash| !needed.contains(hash))
            .collect();
        Ok(self.store.reclaim_cached_blocks(&reclaimable)?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use yadorilink_local_storage::FsBlockStore;

    use super::*;
    use crate::block_liveness::BlockLivenessGate;
    use crate::change::{VersionBlock, VersionHash};
    use crate::custody::{CustodyStamp, CustodyVerifier, FullReplicaCustody};

    fn verified_custody<'a>(
        oracle: &'a dyn crate::custody::FullReplicaCustody,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> VerifiedCustody<'a> {
        CustodyVerifier::new(oracle)
            .verify_exact_version_for_test("group-a", "file.txt", version_hash, blocks)
            .unwrap()
    }

    #[test]
    fn cache_reclaim_deletes_hash_covered_by_custody_proof() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let hash = store.put(b"content").unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let record = crate::types::FileRecord {
            path: "file.txt".into(),
            size: 7,
            mtime_unix_nanos: 0,
            version: crate::version_vector::VersionVector::new(),
            blocks: vec![crate::types::BlockInfo {
                hash: hex::decode(&hash).unwrap(),
                offset: 0,
                size: 7,
            }],
            deleted: false,
        };
        state.upsert_file("group-a", &record).unwrap();
        state
            .set_materialization_state("group-a", "file.txt", MaterializationState::Placeholder)
            .unwrap();
        let current = state.get_current_version_record("group-a", "file.txt").unwrap().unwrap();
        let version = current.to_file_version();
        let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
        let custody = verified_custody(&accepting, &version.version_hash, &version.blocks);

        let gate = BlockLivenessGate::default();
        let deletion = gate.begin_physical_deletion();
        let report = BlockDeletionCoordinator::new(&store)
            .reclaim_cached_blocks(&deletion, custody, &state)
            .unwrap();

        assert_eq!(report.blocks_deleted, 1);
        assert!(!store.exists(&hash).unwrap());
    }

    #[test]
    fn mismatched_victim_block_token_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let current_hash = store.put(b"current").unwrap();
        let victim_hash = store.put(b"unreferenced victim").unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let record = crate::types::FileRecord {
            path: "file.txt".into(),
            size: 7,
            mtime_unix_nanos: 0,
            version: crate::version_vector::VersionVector::new(),
            blocks: vec![crate::types::BlockInfo {
                hash: hex::decode(&current_hash).unwrap(),
                offset: 0,
                size: 7,
            }],
            deleted: false,
        };
        state.upsert_file("group-a", &record).unwrap();
        state
            .set_materialization_state("group-a", "file.txt", MaterializationState::Placeholder)
            .unwrap();
        let current = state.get_current_version_record("group-a", "file.txt").unwrap().unwrap();
        let version_hash = current.to_file_version().version_hash;
        let victim_blocks = vec![VersionBlock {
            hash: crate::change::BlockHash(hex::decode(&victim_hash).unwrap()),
            size: 19,
        }];
        let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
        let custody = verified_custody(&accepting, &version_hash, &victim_blocks);

        let gate = BlockLivenessGate::default();
        let deletion = gate.begin_physical_deletion();
        let report = BlockDeletionCoordinator::new(&store)
            .reclaim_cached_blocks(&deletion, custody, &state)
            .unwrap();

        assert_eq!(report.blocks_deleted, 0);
        assert!(store.exists(&victim_hash).unwrap());
        assert!(store.exists(&current_hash).unwrap());
    }

    #[test]
    fn stale_version_token_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let old_hash = store.put(b"old").unwrap();
        let new_hash = store.put(b"new").unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let mut version = crate::version_vector::VersionVector::new();
        version.increment("device-a");
        let old_record = crate::types::FileRecord {
            path: "file.txt".into(),
            size: 3,
            mtime_unix_nanos: 0,
            version: version.clone(),
            blocks: vec![crate::types::BlockInfo {
                hash: hex::decode(&old_hash).unwrap(),
                offset: 0,
                size: 3,
            }],
            deleted: false,
        };
        state.upsert_file("group-a", &old_record).unwrap();
        let old_version = state
            .get_current_version_record("group-a", "file.txt")
            .unwrap()
            .unwrap()
            .to_file_version();
        let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
        let custody = verified_custody(&accepting, &old_version.version_hash, &old_version.blocks);

        version.increment("device-a");
        state
            .upsert_file(
                "group-a",
                &crate::types::FileRecord {
                    version,
                    blocks: vec![crate::types::BlockInfo {
                        hash: hex::decode(&new_hash).unwrap(),
                        offset: 0,
                        size: 3,
                    }],
                    ..old_record
                },
            )
            .unwrap();
        state
            .set_materialization_state("group-a", "file.txt", MaterializationState::Placeholder)
            .unwrap();

        let gate = BlockLivenessGate::default();
        let deletion = gate.begin_physical_deletion();
        let report = BlockDeletionCoordinator::new(&store)
            .reclaim_cached_blocks(&deletion, custody, &state)
            .unwrap();

        assert_eq!(report.blocks_deleted, 0);
        assert!(store.exists(&old_hash).unwrap());
        assert!(store.exists(&new_hash).unwrap());
    }

    #[test]
    fn tombstoned_current_version_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let hash = store.put(b"content").unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let record = crate::types::FileRecord {
            path: "file.txt".into(),
            size: 7,
            mtime_unix_nanos: 0,
            version: crate::version_vector::VersionVector::new(),
            blocks: vec![crate::types::BlockInfo {
                hash: hex::decode(&hash).unwrap(),
                offset: 0,
                size: 7,
            }],
            deleted: false,
        };
        state.upsert_file("group-a", &record).unwrap();
        let current = state.get_current_version_record("group-a", "file.txt").unwrap().unwrap();
        let version = current.to_file_version();
        let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
        let custody = verified_custody(&accepting, &version.version_hash, &version.blocks);
        state
            .upsert_file("group-a", &crate::types::FileRecord { deleted: true, ..record })
            .unwrap();
        state
            .set_materialization_state("group-a", "file.txt", MaterializationState::Placeholder)
            .unwrap();

        let gate = BlockLivenessGate::default();
        let deletion = gate.begin_physical_deletion();
        let report = BlockDeletionCoordinator::new(&store)
            .reclaim_cached_blocks(&deletion, custody, &state)
            .unwrap();

        assert_eq!(report.blocks_deleted, 0);
        assert!(store.exists(&hash).unwrap());
    }

    struct ExpiringCustody {
        valid: AtomicBool,
    }

    impl FullReplicaCustody for ExpiringCustody {
        fn confirm_exact_version(
            &self,
            _group_id: &str,
            _path: &str,
            _version_hash: &VersionHash,
            _blocks: &[VersionBlock],
        ) -> Option<CustodyStamp> {
            Some(CustodyStamp::new("peer-a".into(), 7))
        }

        fn confirmation_still_valid(&self, _group_id: &str, _stamp: &CustodyStamp) -> bool {
            self.valid.load(Ordering::Acquire)
        }
    }

    #[test]
    fn expired_membership_confirmation_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlockStore::new(dir.path()).unwrap();
        let hash = store.put(b"content").unwrap();
        let state = SyncState::open_in_memory().unwrap();
        let record = crate::types::FileRecord {
            path: "file.txt".into(),
            size: 7,
            mtime_unix_nanos: 0,
            version: crate::version_vector::VersionVector::new(),
            blocks: vec![crate::types::BlockInfo {
                hash: hex::decode(&hash).unwrap(),
                offset: 0,
                size: 7,
            }],
            deleted: false,
        };
        state.upsert_file("group-a", &record).unwrap();
        state
            .set_materialization_state("group-a", "file.txt", MaterializationState::Placeholder)
            .unwrap();
        let current = state.get_current_version_record("group-a", "file.txt").unwrap().unwrap();
        let version = current.to_file_version();
        let oracle = ExpiringCustody { valid: AtomicBool::new(true) };
        let custody = CustodyVerifier::new(&oracle)
            .verify_exact_version_for_test(
                "group-a",
                "file.txt",
                &version.version_hash,
                &version.blocks,
            )
            .unwrap();
        oracle.valid.store(false, Ordering::Release);

        let gate = BlockLivenessGate::default();
        let deletion = gate.begin_physical_deletion();
        let report = BlockDeletionCoordinator::new(&store)
            .reclaim_cached_blocks(&deletion, custody, &state)
            .unwrap();

        assert_eq!(report.blocks_deleted, 0);
        assert!(store.exists(&hash).unwrap());
    }
}
