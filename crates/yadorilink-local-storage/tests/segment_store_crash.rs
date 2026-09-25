//! The crash matrix.
//!
//! The store's central claim is an ordering claim:
//!
//! > **The index never names a block whose bytes are not already durable.**
//!
//! An ordering claim cannot be tested by exercising the happy path -- a
//! store that recovered correctly and a store that never crashed are
//! indistinguishable afterwards. It can only be tested by cutting the
//! commit sequence at each of its boundaries and reopening.
//!
//! Every case here asserts the same three things after the restart:
//!
//! 1. **nothing the store claims is unreadable** -- every mapping in the
//!    index resolves to a record that reads back and hashes to its key;
//! 2. **nothing already committed was lost** -- blocks whose receipts the
//!    caller had in hand before the crash are still there;
//! 3. **the store still works** -- a write after recovery succeeds, so
//!    recovery leaves a usable store rather than a readable corpse.
//!
//! The victim blocks (the group the crash interrupted) are allowed to be
//! absent or present depending on where the cut fell, and each case says
//! which it must be. What is never allowed is *present but broken*.

use yadorilink_local_storage::segment_store::testing;
use yadorilink_local_storage::{
    hash_block_bytes, BlockStore, CommitPoint, FaultPlan, GroupCommitLimits, LocallyHashedBlock,
    SegmentBlockStore, StorageError,
};

/// Small on purpose: a 4 KiB segment target makes roll-over reachable with
/// a handful of 600-byte blocks, so the roll-over boundary is exercised by
/// the same harness as every other one.
fn limits() -> GroupCommitLimits {
    GroupCommitLimits { segment_target_bytes: 4096, ..GroupCommitLimits::default() }
}

fn block(tag: &str, len: usize) -> LocallyHashedBlock {
    let mut payload = vec![b'.'; len];
    let bytes = tag.as_bytes();
    let take = bytes.len().min(len);
    payload[..take].copy_from_slice(&bytes[..take]);
    LocallyHashedBlock::from_bytes(payload)
}

/// Claim 1, in full: every mapping the index holds resolves to bytes that
/// read back and hash to their own key.
fn assert_index_names_only_readable_blocks(store: &SegmentBlockStore) {
    let verification = store.verify_store(true).unwrap();
    assert!(
        verification.unbacked_mappings.is_empty(),
        "the index names {} block(s) with no record behind them: {:?}",
        verification.unbacked_mappings.len(),
        verification.unbacked_mappings
    );
    assert!(
        verification.corrupt_records.is_empty(),
        "the index names {} block(s) whose bytes do not hash to their key: {:?}",
        verification.corrupt_records.len(),
        verification.corrupt_records
    );
    assert!(
        verification.segments_with_incomplete_tail.is_empty(),
        "a segment's durable range runs past its last complete record: {:?}",
        verification.segments_with_incomplete_tail
    );

    // Independently of the scrub, go through the ordinary read path: a
    // store that verifies but cannot serve is still a store that lies.
    for hash in store.list_by_prefix("").unwrap() {
        let bytes =
            store.get(&hash).unwrap_or_else(|e| panic!("indexed block {hash} is unreadable: {e}"));
        assert_eq!(hash_block_bytes(&bytes), hash, "indexed block {hash} hashes to something else");
    }
}

/// Whether the interrupted group's blocks must be present after recovery.
///
/// Only one boundary is past the point of no return: the index
/// transaction has committed, so the blocks are durable whether or not the
/// caller ever learned it. Everywhere earlier, the group must have left
/// nothing behind.
fn victim_must_be_present(point: CommitPoint) -> bool {
    matches!(point, CommitPoint::AfterIndexCommitBeforeReceipt)
}

/// Whether reaching `point` requires the group to create a segment.
fn needs_a_fresh_segment(point: CommitPoint) -> bool {
    matches!(point, CommitPoint::AfterSegmentCreateBeforeDirSync | CommitPoint::AfterSegmentDirSync)
}

fn crash_scenario(point: CommitPoint) {
    let dir = tempfile::tempdir().unwrap();
    let baseline: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("baseline-{i}"), 600)).collect();
    // Enough blocks, at this size, that laying them out crosses the 4 KiB
    // segment target -- which is what makes the roll-over boundary
    // reachable.
    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("victim-{i}"), 600)).collect();

    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
        store.put_durable_batch(&baseline).unwrap();
        for committed in &baseline {
            assert!(store.exists(committed.hash()).unwrap());
        }
        if needs_a_fresh_segment(point) {
            // Close the segment the baseline went into, so the faulted
            // group has to create one and the create-related boundaries
            // are actually reached.
            store.seal_active_segment().unwrap();
        }

        store.arm_commit_fault_for_tests(FaultPlan::crash_at(point));
        let outcome = store.put_durable_batch(&victim);
        assert!(outcome.is_err(), "the armed crash at {point:?} did not fail the commit");
        assert!(
            store.is_halted_for_tests(),
            "a crash must halt the store at {point:?}; a dead process does not keep serving"
        );
        assert!(
            store.put(b"a write after the process is gone").is_err(),
            "a halted store must refuse further writes"
        );
        // Dropped without any graceful shutdown -- nothing here flushes,
        // truncates, or tidies up, which is the point.
        drop(store);
    }

    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();

    // Claim 2: everything the caller was told was durable, still is.
    for committed in &baseline {
        assert_eq!(
            store.get(committed.hash()).unwrap(),
            committed.bytes(),
            "a block committed before the {point:?} crash was lost"
        );
    }

    // The interrupted group is all-or-nothing, and which it is depends on
    // whether its transaction committed.
    let expected = victim_must_be_present(point);
    for interrupted in &victim {
        let present = store.exists(interrupted.hash()).unwrap();
        assert_eq!(
            present,
            expected,
            "after a crash at {point:?} the interrupted group must be {} -- an index \
             transaction is atomic, so a partially-visible group means the group was not \
             committed as one",
            if expected { "entirely present" } else { "entirely absent" }
        );
        if present {
            assert_eq!(store.get(interrupted.hash()).unwrap(), interrupted.bytes());
        }
    }

    // Claim 1.
    assert_index_names_only_readable_blocks(&store);

    // Claim 3.
    let after = store.put(b"written after recovery").unwrap();
    assert_eq!(store.get(&after).unwrap(), b"written after recovery");
    for committed in &baseline {
        assert_eq!(store.get(committed.hash()).unwrap(), committed.bytes());
    }
}

#[test]
fn no_commit_boundary_leaves_the_index_naming_a_block_that_is_not_durable() {
    for point in CommitPoint::ALL {
        crash_scenario(point);
    }
}

#[test]
fn crashing_mid_record_leaves_a_tail_recovery_truncates() {
    // The specific shape `MidRecordAppend` produces: the file is longer
    // than any committed transaction accounts for, and the extra bytes are
    // half a record. Recovery must cut them back rather than try to
    // interpret them, and must say it did.
    let dir = tempfile::tempdir().unwrap();
    let baseline = block("baseline", 400);
    let victim: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("half-written-{i}"), 400)).collect();

    let (segment_id, durable_end) = {
        let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
        store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
        let segment_id = store.segment_ids().unwrap()[0];
        let (_, durable_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();

        store.arm_commit_fault_for_tests(
            FaultPlan::crash_at(CommitPoint::MidRecordAppend).with_partial_append_bytes(700),
        );
        assert!(store.put_durable_batch(&victim).is_err());
        drop(store);
        (segment_id, durable_end)
    };

    let on_disk =
        std::fs::metadata(dir.path().join("segments").join(format!("{segment_id:016}.seg")))
            .unwrap()
            .len();
    assert!(
        on_disk > durable_end,
        "the half-written record should still be on disk before recovery runs"
    );

    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    assert_eq!(
        store.recovery_report().truncated_segments,
        vec![segment_id],
        "recovery must report the truncation rather than doing it silently"
    );
    assert_eq!(store.recovery_report().truncated_bytes, on_disk - durable_end);
    let (_, recovered_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();
    assert_eq!(recovered_end, durable_end);
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    for interrupted in &victim {
        assert!(!store.exists(interrupted.hash()).unwrap());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_segment_created_by_an_uncommitted_group_is_removed_on_the_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let baseline = block("baseline", 300);
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
        store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
        store.seal_active_segment().unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::AfterFsyncBeforeIndex));
        assert!(store.put(b"in a segment whose transaction never lands").is_err());
        drop(store);
    }

    let on_disk_before = testing::segment_ids_on_disk(dir.path()).unwrap();
    assert_eq!(on_disk_before.len(), 2, "the orphaned segment file should still be there");

    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    assert_eq!(
        store.recovery_report().removed_orphan_segments.len(),
        1,
        "a segment no committed transaction mentions has nothing referencing it and must go"
    );
    assert_eq!(testing::segment_ids_on_disk(dir.path()).unwrap().len(), 1);
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn durable_bytes_whose_transaction_never_committed_are_never_served() {
    // The subtle one. `AfterFsyncBeforeIndex` is the window where the
    // bytes really are on the platter and the index has never heard of
    // them. A store that rebuilt its index by scanning segments would
    // resurrect this group; this one must not.
    let dir = tempfile::tempdir().unwrap();
    let victim: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("fsynced-but-uncommitted-{i}"), 300)).collect();
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
        store.put(b"something committed first").unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::AfterFsyncBeforeIndex));
        assert!(store.put_durable_batch(&victim).is_err());
        drop(store);
    }

    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    for interrupted in &victim {
        assert!(
            !store.exists(interrupted.hash()).unwrap(),
            "bytes that reached the platter but whose transaction never committed must not \
             be served: durability is what the index says, not what the disk happens to hold"
        );
        assert!(matches!(store.get(interrupted.hash()), Err(StorageError::NotFound(_))));
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_crash_inside_the_index_transaction_rolls_the_whole_group_back() {
    let dir = tempfile::tempdir().unwrap();
    let victim: Vec<LocallyHashedBlock> =
        (0..16).map(|i| block(&format!("rolled-back-{i}"), 200)).collect();
    {
        let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(CommitPoint::DuringIndexTransaction));
        assert!(store.put_durable_batch(&victim).is_err());
        drop(store);
    }

    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    assert!(
        testing::indexed_hashes(dir.path()).unwrap().is_empty(),
        "an aborted transaction must leave no row at all, not the rows it had staged"
    );
    for interrupted in &victim {
        assert!(!store.exists(interrupted.hash()).unwrap());
    }
    assert_index_names_only_readable_blocks(&store);
}

// ---------------------------------------------------------------------
// Survivable failures: the process lives, so the store has to stay both
// correct and usable -- which is a stronger requirement than crashing.
// ---------------------------------------------------------------------

fn io_failure_scenario(point: CommitPoint) {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    let baseline = block("baseline", 300);
    store.put_durable_batch(std::slice::from_ref(&baseline)).unwrap();
    if needs_a_fresh_segment(point) {
        store.seal_active_segment().unwrap();
    }

    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("failed-{point:?}-{i}"), 600)).collect();
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(point));
    let outcome = store.put_durable_batch(&victim);
    assert!(outcome.is_err(), "an injected I/O failure at {point:?} must fail the commit");
    assert!(
        !store.is_halted_for_tests(),
        "a survivable I/O failure must not halt the store at {point:?}"
    );
    store.clear_commit_fault_for_tests();

    // Fail-closed: nothing the failed commit touched is claimed, except
    // where the transaction genuinely committed before the failure.
    let expected = victim_must_be_present(point);
    for interrupted in &victim {
        assert_eq!(
            store.exists(interrupted.hash()).unwrap(),
            expected,
            "a failed commit at {point:?} left an inconsistent claim"
        );
    }
    assert_eq!(store.get(baseline.hash()).unwrap(), baseline.bytes());
    assert_index_names_only_readable_blocks(&store);

    // Usable afterwards, with no restart: the retry of the very batch that
    // failed must succeed and be readable.
    store.put_durable_batch(&victim).unwrap();
    for retried in &victim {
        assert_eq!(store.get(retried.hash()).unwrap(), retried.bytes());
    }
    assert_index_names_only_readable_blocks(&store);

    // And it all still holds across a restart.
    drop(store);
    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    for retried in &victim {
        assert_eq!(store.get(retried.hash()).unwrap(), retried.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn every_boundary_fails_closed_and_leaves_the_store_usable() {
    for point in CommitPoint::ALL {
        io_failure_scenario(point);
    }
}

#[test]
fn a_survivable_failure_after_the_append_leaves_no_orphan_tail() {
    // A crash may leave bytes past `durable_end` -- truncating them is
    // recovery's job precisely because a dead process cannot. A process
    // that survives has no such excuse: the group's bytes must be gone by
    // the time the failure is reported, without waiting for a restart.
    //
    // This is what an earlier version got wrong. The writer's open segment
    // was taken out of the writer state to lay the group out and, on the
    // error paths, never handed back -- so the rollback found nothing to
    // truncate, the next group quietly started a different segment, and
    // the abandoned one kept an orphan tail and an "active" row until the
    // next open.
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    store.put(b"a committed block the segment starts with").unwrap();
    let segment_id = store.segment_ids().unwrap()[0];
    let (_, durable_end, _) = testing::segment_row(dir.path(), segment_id).unwrap().unwrap();
    let on_disk = |id: u64| {
        std::fs::metadata(dir.path().join("segments").join(format!("{id:016}.seg"))).unwrap().len()
    };
    assert_eq!(on_disk(segment_id), durable_end);

    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("rolled-back-{i}"), 500)).collect();
    store.arm_commit_fault_for_tests(FaultPlan::io_failure_at(CommitPoint::AfterFsyncBeforeIndex));
    assert!(store.put_durable_batch(&victim).is_err());
    store.clear_commit_fault_for_tests();

    assert_eq!(
        on_disk(segment_id),
        durable_end,
        "the failed group's bytes must be gone already, not left for the next open"
    );
    assert_eq!(
        store.segment_ids().unwrap(),
        vec![segment_id],
        "a failed group must not strand its segment and start a new one"
    );
    assert_index_names_only_readable_blocks(&store);

    // And the very batch that failed commits cleanly on a retry. It rolls
    // over on the way (eight 552-byte records do not fit the 4 KiB target
    // this test uses), which is the point of using a group that spans two
    // segments: the rollback above had to undo both.
    store.put_durable_batch(&victim).unwrap();
    let after_retry = store.segment_ids().unwrap();
    assert!(after_retry.starts_with(&[segment_id]), "got {after_retry:?}");
    assert!(after_retry.len() > 1, "the retried group should have rolled over: {after_retry:?}");
    for block in &victim {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_headroom_rejection_writes_nothing_at_all() {
    // The ENOSPC shape the store checks for itself, rather than one
    // injected underneath it: the preflight runs before any byte is laid
    // out, so a rejected batch must not move the physical size by one
    // byte.
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    let existing = store.put(b"written while there was room").unwrap();
    let before = store.detailed_usage().unwrap();

    store.set_headroom_override_bytes(Some(u64::MAX / 2));
    store.set_headroom_enforced(true);

    let rejected: Vec<LocallyHashedBlock> =
        (0..4).map(|i| block(&format!("no-room-{i}"), 400)).collect();
    assert!(matches!(store.put_durable_batch(&rejected), Err(StorageError::DiskPressure { .. })));

    assert_eq!(
        store.detailed_usage().unwrap(),
        before,
        "a headroom rejection happens before any layout or append; nothing may change"
    );
    for block in &rejected {
        assert!(!store.exists(block.hash()).unwrap());
    }
    assert_eq!(store.get(&existing).unwrap(), b"written while there was room");

    // Releasing the pressure makes the same batch succeed.
    store.set_headroom_enforced(false);
    store.put_durable_batch(&rejected).unwrap();
    for block in &rejected {
        assert_eq!(store.get(block.hash()).unwrap(), block.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

// ---------------------------------------------------------------------
// Compaction. The same ordering, applied to bytes that already exist: at
// every cut, at least one valid copy is reachable from the index.
// ---------------------------------------------------------------------

/// Builds a store with one sealed, mostly-dead segment ready to compact,
/// and returns the blocks that must survive it.
fn store_with_a_compactable_segment(
    dir: &std::path::Path,
) -> (SegmentBlockStore, Vec<LocallyHashedBlock>) {
    let store = SegmentBlockStore::with_limits(dir, limits()).unwrap();
    let blocks: Vec<LocallyHashedBlock> =
        (0..32).map(|i| block(&format!("compaction-source-{i}"), 200)).collect();
    store.put_durable_batch(&blocks).unwrap();
    store.seal_active_segment().unwrap();
    let mut survivors = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        if i % 4 == 0 {
            survivors.push(b.clone());
        } else {
            store.delete(b.hash()).unwrap();
        }
    }
    (store, survivors)
}

fn compaction_crash_scenario(point: CommitPoint) {
    let dir = tempfile::tempdir().unwrap();
    let survivors = {
        let (store, survivors) = store_with_a_compactable_segment(dir.path());
        store.arm_commit_fault_for_tests(FaultPlan::crash_at(point));
        let outcome = store.compact_with_thresholds(0.5, 1);
        assert!(outcome.is_err(), "the armed crash at {point:?} did not fail the compaction");
        drop(store);
        survivors
    };

    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    for survivor in &survivors {
        assert_eq!(
            store.get(survivor.hash()).unwrap(),
            survivor.bytes(),
            "a crash at {point:?} during compaction lost a live block -- at every cut, at \
             least one valid copy must stay reachable from the index"
        );
    }
    assert_index_names_only_readable_blocks(&store);

    // The compaction can simply be run again.
    store.compact_with_thresholds(0.5, 1).unwrap();
    for survivor in &survivors {
        assert_eq!(store.get(survivor.hash()).unwrap(), survivor.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}

#[test]
fn a_crash_at_any_point_in_a_compaction_keeps_every_live_block_reachable() {
    for point in [
        CommitPoint::AfterAppendBeforeFsync,
        CommitPoint::AfterFsyncBeforeIndex,
        CommitPoint::DuringIndexTransaction,
    ] {
        compaction_crash_scenario(point);
    }
}

#[test]
fn a_crash_between_the_mapping_swap_and_the_old_files_deletion_is_finished_by_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let survivors = {
        let (store, survivors) = store_with_a_compactable_segment(dir.path());
        // Swap the mappings, then stop -- exactly the window where both
        // copies exist on disk and the index points at the new one.
        let report = store.compact_without_reclaim_for_tests(0.5, 1).unwrap();
        assert!(report.segments_compacted > 0);
        assert!(
            store.detailed_usage().unwrap().retired_segments > 0,
            "the source segment should be retired but not yet deleted"
        );
        for survivor in &survivors {
            assert_eq!(store.get(survivor.hash()).unwrap(), survivor.bytes());
        }
        drop(store);
        survivors
    };

    let segments_before = testing::segment_ids_on_disk(dir.path()).unwrap().len();
    let store = SegmentBlockStore::with_limits(dir.path(), limits()).unwrap();
    assert!(
        !store.recovery_report().reclaimed_segments.is_empty(),
        "recovery must delete a segment the index already retired"
    );
    assert!(testing::segment_ids_on_disk(dir.path()).unwrap().len() < segments_before);
    assert_eq!(store.detailed_usage().unwrap().retired_segments, 0);
    for survivor in &survivors {
        assert_eq!(store.get(survivor.hash()).unwrap(), survivor.bytes());
    }
    assert_index_names_only_readable_blocks(&store);
}
