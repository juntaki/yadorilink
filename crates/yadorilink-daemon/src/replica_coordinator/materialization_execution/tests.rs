#![cfg(test)]

use super::*;
use std::path::Path;
use yadorilink_filesystem_sync::block_liveness::BlockLivenessGate;
use yadorilink_filesystem_sync::materialization_eviction::{evict_file, MaterializationContext};
use yadorilink_filesystem_sync::materialization_repair::{
    repair_interrupted_materializations, RepairMode,
};
use yadorilink_local_storage::{BlockStore as _, SegmentBlockStore};
use yadorilink_peer_session::ports::PreparedProjectedUpsert;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, MaterializationState};
use yadorilink_replica_engine::custody::{CustodyStamp, FullReplicaCustody};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

/// A custody oracle that never confirms anything. Note: with today's `REMOTE_CUSTODY_LEASES_SUPPORTED =
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
/// oracle would also have refused. A plain rejection assertion with a permissive oracle (`AlwaysConfirmed`)
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

/// A pinned file must never be evicted -- `EvictionEligibilitySnapshot::pinned`
/// is the very first check `evict_file` performs, before it reads any
/// version or custody state. `PanicsIfConsulted` locks down that
/// ordering directly rather than merely observing rejection.
#[test]
fn evict_rejects_a_pinned_file() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"pinned content must never be evicted";
    let record = store_and_record(&store, "a.bin", content);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
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

/// On an on-demand (non-full-replica) device, an evicted file's
/// content-addressed blocks are NEVER purged from the local block
/// store while `REMOTE_CUSTODY_LEASES_SUPPORTED` stays `false` --
/// `verify_reclaim_custody` returns `None` unconditionally at that
/// gate, before ever consulting an oracle (`NeverConfirms` is not actually
/// exercised here today -- see its own doc comment). This test pins the CURRENT, observable
/// production invariant (nothing is ever purged without a durable
/// custody lease, and none exist yet) rather than claiming to prove
/// oracle-specific handling this build cannot actually reach.
///
/// `#[cfg(not(windows))]`: this is the only test in this module that
/// drives a `Hydrated` row all the way through `evict_file` to a
/// successful placeholder write, so it is the only one that actually
/// reaches `materialization_eviction::evict_to_placeholder`'s Windows
/// arm (every other eviction test here either rejects earlier --
/// pinned, diverged-on-disk -- or, like the cross-group tests below,
/// leaves its row at the schema-v25 `Placeholder` default, which bails
/// out of `evict_file` before `evict_to_placeholder` is ever called).
/// On Windows that arm does not locally write a placeholder at all --
/// by design (see `evict_to_placeholder`'s own doc comment) it asks
/// the real `cfapi-host.exe` process to confirm native dehydration over
/// a named pipe (`placeholder_dehydrate_windows::
/// dehydrate_via_cfapi_host_blocking`), and there is no test-support
/// seam to fake that confirmation the way `create_or_defer_
/// placeholder`'s `set_test_force_deferred_placeholder_for_path` fakes
/// the Windows-deferred *creation* path elsewhere in this module. A
/// plain `cargo test` binary never starts that host process, so on a
/// real Windows runner this call fails fast with a pipe-connect error
/// (`EvictionOutcomeAmbiguous`) regardless of whether the row has a
/// recorded placeholder identity -- recording one (as a real Windows
/// CfAPI-hydrated row always would) only changes which error `evict_
/// file` returns, not whether this test can succeed without that
/// external process. This is a test-infrastructure gap, not a
/// production bug: the fail-closed behavior itself is exactly what a
/// real Windows host is supposed to do. Scoping the test out mirrors
/// this same module's `repair_recreates_a_symlink_after_a_simulated_
/// crash_before_the_write`, `#[cfg(unix)]`-scoped for the same reason
/// (a real write this platform cannot exercise without OS-specific
/// support this test harness does not provide).
#[cfg(not(windows))]
#[test]
fn evict_on_an_on_demand_device_frees_the_file_but_never_purges_its_blocks_today() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"content nobody else has confirmed custody of";
    let record = store_and_record(&store, "a.bin", content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
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
    // placeholder -- not merely have its index row updated.
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

/// Content that already diverged from the indexed version
/// BEFORE `evict_file` is even called (an unsynced local edit landed
/// sometime after the last index write, or any other source of
/// pre-existing on-disk drift) must abort the eviction at its first
/// `disk_bytes_match_indexed_blocks` check, before any placeholder is
/// written -- never silently discard those bytes. This specifically exercises the FIRST divergence
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
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let indexed_content = b"the version the index still believes is current";
    let record = store_and_record(&store, "a.bin", indexed_content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
    // A local edit landed on disk that the index does not know about
    // yet, before this call even begins.
    std::fs::write(root.path().join("a.bin"), b"a locally edited, unindexed replacement").unwrap();

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

/// Reproduces the placeholder-identity crash window --
/// `write_placeholder` durably writes the
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
/// path, matching the other `#[cfg(unix)]` placeholder tests.
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
        .set_materialization_state("group-a", "a.bin", MaterializationState::Placeholder, &permit)
        .unwrap();
    // Simulates exactly what `write_placeholder` leaves behind: a real
    // sparse file at the indexed size, durably on disk -- but,
    // crucially, NO `record_placeholder_generation` call ever ran
    // (the simulated crash).
    let identity = yadorilink_local_storage::write_placeholder(&root.path().join("a.bin"), size, 0)
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
        .set_materialization_state("group-a", "a.bin", MaterializationState::Placeholder, &permit)
        .unwrap();
    // Content of a DIFFERENT size than the index believes -- not the
    // placeholder this process would have written.
    std::fs::write(root.path().join("a.bin"), b"a genuine local edit, not a placeholder").unwrap();

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

/// Test-only convenience: `upsert_file` alone no longer leaves a fresh
/// row `Hydrated` (schema v25 defaults `materialization_state` to
/// `Placeholder` instead -- see `SCHEMA_VERSION`'s own doc comment).
/// Every test in this module that upserts a record to simulate an
/// already-fully-materialized row (the overwhelming majority here --
/// this module is about repair/eviction over already-hydrated content)
/// must say so explicitly now, the same way production local-emission
/// callers do, rather than relying on a column default a genuinely
/// unhydrated row must NOT get.
fn upsert_hydrated_file(
    state: &ReplicaCoordinator,
    group_id: &str,
    record: &FileRecord,
    permit: &RootCommitPermit,
) {
    state.file_index_repository().upsert_file(group_id, record, permit).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(group_id, &record.path, MaterializationState::Hydrated, permit)
        .unwrap();
}

fn store_and_record(store: &SegmentBlockStore, path: &str, content: &[u8]) -> FileRecord {
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
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
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
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
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
    assert!(store.exists(&hash).unwrap(), "concurrent cross-group eviction deleted shared block");
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

/// The live repair sweep runs over EVERY materialization-state row in the
/// group on its own periodic cadence, and its "already fine" arm used to
/// issue an unconditional `clear_materialization_intent` for each such row
/// -- one fsync-backed write transaction, each taking the process-wide
/// writer gate, for a DELETE matching no row, since the intent journal is
/// empty in steady state. The sweep now reads the outstanding set once per
/// pass and writes only for a path actually in it.
///
/// The cost reduction itself is not asserted here: the only instrument
/// that can see "did this take the writer gate at all" is `writer_gate_stats`'s
/// process-global counter, and a global counter cannot be read soundly
/// from a parallel test runner -- another test writing to its own database
/// inflates it (confirmed: this assertion passed alone and failed in the
/// full suite). It is evidenced by measurement instead, at the scale where
/// it matters: a 20,050-row pass went from 35,491ms to 4,195ms with
/// `intent_clears=0`. What IS asserted deterministically is the primitive
/// the fix rests on -- that the set really is the outstanding set -- plus
/// the correctness half in the test below.
#[test]
fn the_outstanding_intent_set_is_exactly_the_paths_that_have_one() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();
    let intents = state.materialization_intent_repository();

    assert!(
        intents.list_materialization_intent_paths("group-1").unwrap().is_empty(),
        "a group that has never materialized anything has no outstanding intents"
    );

    intents.begin_materialization_intent("group-1", "a.txt", &[0; 32], &permit).unwrap();
    intents.begin_materialization_intent("group-1", "b.txt", &[1; 32], &permit).unwrap();
    // A different group's intent must never leak into this group's set.
    intents.begin_materialization_intent("group-2", "c.txt", &[2; 32], &permit).unwrap();

    let outstanding = intents.list_materialization_intent_paths("group-1").unwrap();
    assert_eq!(
        outstanding,
        ["a.txt".to_string(), "b.txt".to_string()].into_iter().collect(),
        "exactly this group's open intents, and nothing else"
    );

    intents.clear_materialization_intent("group-1", "a.txt", &permit).unwrap();
    assert_eq!(
        intents.list_materialization_intent_paths("group-1").unwrap(),
        ["b.txt".to_string()].into_iter().collect(),
        "a cleared intent leaves the set"
    );
}

/// Teeth for the assertion above: the sweep must still clear an intent that
/// genuinely exists. A crash between a completed rename and its own intent
/// clear leaves exactly this state, and leaving it would later make an
/// ordinary offline deletion of the same path read as a crash mid-write.
#[test]
fn a_sweep_still_clears_a_real_dangling_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();

    let content = b"already written before the crash".to_vec();
    let hash = hex::decode(store.put(&content).unwrap()).unwrap();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("doc.txt", &content, hash),
        &permit,
    );
    // The rename completed; only the intent's own clear did not.
    std::fs::write(root.path().join("doc.txt"), &content).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();
    assert!(state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "doc.txt")
        .unwrap());

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert!(
        !state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "a real dangling intent over a completed write must still be dropped"
    );
}

#[test]
fn repair_reconstructs_locally_after_a_simulated_crash_before_rename() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"hello from before the crash";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    assert_eq!(report.reconstructed, vec!["doc.txt"]);
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
}

/// A repair reconstruct keeps its intent until the proof commit clears it.
/// The intent is the only durable record that the write is in flight, so a
/// failure (or a crash) after the bytes and metadata land but before the
/// proof is committed must leave it open for the next pass to decide.
#[test]
fn a_repair_reconstruct_whose_proof_commit_fails_keeps_its_intent_open() {
    const GROUP: &str = "group-reconstruct-proof-commit-fails";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt, but never proven";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, GROUP, &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "doc.txt", &[0; 32], &permit)
        .unwrap();
    crate::replica_coordinator::materialization_owner::set_test_fail_repair_reconstruct_proof_commit(
        GROUP, "doc.txt", true,
    );

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
    assert!(report.reconstructed.is_empty(), "nothing was proven, so nothing is reconstructed");
    assert!(
        !MaterializationExecutionPort::has_usable_materialized_generation(&state, GROUP, "doc.txt")
            .unwrap(),
        "the failed commit published no proof"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "doc.txt")
            .unwrap(),
        "the intent must survive until the proof commit that clears it"
    );
}

/// The kept intent has to be one some lane still decides. A proof commit
/// that fails without a crash left the row `Placeholder`, which is never a
/// repair candidate, so the intent stayed open with full bytes on disk and
/// no pass ever visited it again -- and every scan kept deferring an
/// offline delete of that path. The failed settle now leaves the row in
/// the in-flight state, so the next pass (live, here) finds `Hydrating`
/// with an open intent over matching bytes and proves it.
#[test]
fn a_repair_reconstruct_whose_proof_commit_failed_is_proven_by_the_next_pass() {
    const GROUP: &str = "group-reconstruct-proof-commit-fails-then-heals";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt, proven one pass later";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, GROUP, &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "doc.txt", &[0; 32], &permit)
        .unwrap();
    crate::replica_coordinator::materialization_owner::set_test_fail_repair_reconstruct_proof_commit(
        GROUP, "doc.txt", true,
    );
    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    crate::replica_coordinator::materialization_owner::set_test_fail_repair_reconstruct_proof_commit(
        GROUP, "doc.txt", false,
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrating),
        "an unproven reconstruct that keeps its intent must stay a repair candidate"
    );

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
    assert!(
        MaterializationExecutionPort::has_usable_materialized_generation(&state, GROUP, "doc.txt")
            .unwrap(),
        "the next pass proves the bytes the failed settle left behind"
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert!(
        !state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "doc.txt")
            .unwrap(),
        "the proving commit clears the intent the failed settle kept"
    );
}

/// The success counterpart: the proof commit is what clears the intent, in
/// the same transaction that publishes the proof and stamps `Hydrated`.
#[test]
fn a_repair_reconstruct_clears_its_intent_with_the_proof_it_commits() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt and proven";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["doc.txt"]);
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert!(!state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "doc.txt")
        .unwrap());
}

/// The exact crash cut-point repair must cover: a symlink row is committed durably, then the daemon
/// crashes before the physical symlink is ever written -- previously,
/// repair's own `RecordKind::File`-only filter meant this row was
/// simply never examined, leaving the symlink permanently missing
/// across restarts (and, before `materialize_symlink_at`'s matching
/// fix, no durable intent even existed to disambiguate this from an
/// offline deletion in the first place). Confirmed genuinely RED by
/// temporarily reverting the loop's symlink branch back to the bare
/// `RecordKind::File`-only filter: the row was skipped and the
/// symlink was never created.
#[cfg(unix)]
#[test]
fn repair_recreates_a_symlink_after_a_simulated_crash_before_the_write() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "link.txt", Some(b"target.txt"))
        .unwrap();
    // Simulate the crash: a durable intent was opened (exactly what
    // `materialize_symlink_at` now does before its own row commit),
    // but the physical symlink write never happened.
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "link.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["link.txt"]);
    let out_path = root.path().join("link.txt");
    assert!(
        std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
        "must be a real symlink on disk after repair"
    );
    assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
    assert!(
        MaterializationExecutionPort::materialization_intent_kind(&state, "group-1", "link.txt")
            .unwrap()
            .is_none(),
        "the intent must be cleared once repair completes the write"
    );
}

/// An explicit directory whose materialization was interrupted
/// between its row commit and its `mkdir` (the intent is still open, the
/// directory is not on disk) is recreated by repair, with its mode, and
/// proven.
#[cfg(unix)]
#[test]
fn repair_recreates_missing_explicit_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "nested/docs".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "nested/docs", RecordKind::Directory, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode("group-1", "nested/docs", Some(0o750), &permit)
        .unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "nested/docs", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["nested/docs"]);
    let metadata = std::fs::symlink_metadata(root.path().join("nested/docs")).unwrap();
    assert!(metadata.is_dir(), "repair must recreate a real directory");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o750);
    assert!(
        MaterializationExecutionPort::materialization_intent_kind(&state, "group-1", "nested/docs")
            .unwrap()
            .is_none(),
        "the intent must be cleared once repair completes the directory"
    );
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state,
        "group-1",
        "nested/docs"
    )
    .unwrap());
    // The parent repair had to create is structural, like any other.
    assert!(matches!(
        state.sqlite().dag_structural_directory_origin("group-1", "nested").unwrap(),
        yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin::Recorded(_)
    ));
}

/// A healthy explicit directory costs repair nothing, and a directory
/// whose materialization completed on disk but whose proof did not land
/// is proven, not recreated.
#[test]
fn repair_proves_an_explicit_directory_already_on_disk() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "docs".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "docs", RecordKind::Directory, &permit)
        .unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "docs", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reproven, vec!["docs"]);
    assert!(report.reconstructed.is_empty());
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "docs"
    )
    .unwrap());
}

/// The offline-deletion counterpart of the crash-recovery test above:
/// a symlink row says `Hydrated` with a recorded target, but there is
/// no on-disk symlink and no open intent -- the write had already
/// completed (intent cleared) and the symlink was deleted while the
/// daemon was stopped. Repair must classify this as an offline
/// deletion, never resurrect it.
#[test]
fn repair_does_not_resurrect_an_offline_deleted_symlink() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    // `repair_one_interrupted_symlink`'s Windows arm gates its ENTIRE
    // body -- including this test's own offline-delete classification
    // -- on the link's `windows_symlink_opt_in` policy flag, which a
    // fresh `add_link` (inside `adopt_root` above) defaults to `false`
    // (see `windows_symlink_opt_in_for_group`'s own `unwrap_or(0)`).
    // Without opting in here, `policy_permits_write` is `false` on
    // Windows and the function returns `Ok(())` before ever reaching
    // the on-disk/intent checks this test means to exercise, so
    // `report.offline_deleted` stays empty regardless of what is (or
    // is not) on disk. Mirrors the same opt-in every other symlink-
    // materialization test that must actually reach that logic on
    // Windows already performs (see e.g. `yadorilink-daemon::
    // hydration`'s own `set_windows_symlink_opt_in(..., true)` calls).
    #[cfg(windows)]
    state
        .link_repository()
        .set_windows_symlink_opt_in(&root.path().to_string_lossy(), true)
        .unwrap();
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "gone-link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "gone-link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "gone-link.txt", Some(b"target.txt"))
        .unwrap();
    // No intent opened, and nothing on disk -- the write completed
    // and was later deleted offline; never simulate a crash here.

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.offline_deleted, vec!["gone-link.txt"]);
    assert_eq!(report.reconstructed, Vec::<String>::new());
    assert!(!root.path().join("gone-link.txt").exists());
}

/// A crash inside a single-path tombstone delete, after its
/// `remove_file` and before its settle: the row is still live and
/// `Hydrated`, the file is gone, and the delete's own intent is open. That
/// intent is a delete, not an interrupted write, so the missing file is the
/// state it was heading to. Repair must not rebuild the file from blocks;
/// it leaves the path and the intent to the outstanding delete. Run for
/// both modes, since the missing-file arms differ between them.
fn crash_a_tombstone_delete_after_its_removal(
    state: &ReplicaCoordinator,
    group_id: &str,
    root: &Path,
    record: &FileRecord,
    permit: &RootCommitPermit,
) {
    let out_path = root.join(&record.path);
    let (delete_intent_guard, _mutation_generation) =
        state.open_tombstone_delete(group_id, &record.path, permit).unwrap();
    std::fs::remove_file(&out_path).unwrap();
    // The crash: the settle never runs, so the intent is dropped uncleared.
    drop(delete_intent_guard);
}

#[test]
fn repair_does_not_reconstruct_a_file_its_interrupted_tombstone_delete_removed() {
    for (group_id, mode) in
        [("group-tomb-startup", RepairMode::Startup), ("group-tomb-live", RepairMode::Live)]
    {
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, group_id, root.path());
        let permit = RootCommitPermit::for_tests();
        let content = b"deleted by a peer's tombstone";
        let record = store_and_record(&store, "doc.txt", content);
        upsert_hydrated_file(&state, group_id, &record, &permit);
        std::fs::write(root.path().join("doc.txt"), content).unwrap();
        crash_a_tombstone_delete_after_its_removal(&state, group_id, root.path(), &record, &permit);

        let report = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            group_id,
            mode,
            &permit,
        )
        .unwrap();

        assert!(
            !root.path().join("doc.txt").exists(),
            "{mode:?}: repair recreated a file its tombstone delete had already removed"
        );
        assert_eq!(report.reconstructed, Vec::<String>::new(), "{mode:?}");
        assert_eq!(report.offline_deleted, Vec::<String>::new(), "{mode:?}");
        assert!(
            state
                .materialization_intent_repository()
                .has_materialization_intent(group_id, "doc.txt")
                .unwrap(),
            "{mode:?}: the delete's intent is the outstanding delete's to settle"
        );
    }
}

/// The owner tells a delete's intent from a write's by the target it
/// opened it with, and that must hold for an empty file too: the ordinary
/// target of an empty file is the hash of an empty block list, which the
/// delete's target must never equal.
#[test]
fn the_owner_classifies_a_tombstone_intent_as_a_delete_and_an_empty_files_write_as_a_write() {
    const GROUP: &str = "group-intent-kind";
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    assert_eq!(state.materialization_intent_kind(GROUP, "gone.txt").unwrap(), None);

    let (delete_intent_guard, _) = state.open_tombstone_delete(GROUP, "gone.txt", &permit).unwrap();
    drop(delete_intent_guard);
    assert_eq!(
        state.materialization_intent_kind(GROUP, "gone.txt").unwrap(),
        Some(MaterializationIntentKind::Delete)
    );

    state
        .materialization_intent_repository()
        .begin_materialization_intent(
            GROUP,
            "empty.txt",
            &yadorilink_local_storage::intent_target_hash(&[]),
            &permit,
        )
        .unwrap();
    assert_eq!(
        state.materialization_intent_kind(GROUP, "empty.txt").unwrap(),
        Some(MaterializationIntentKind::Materialize)
    );
}

/// The symlink lane's counterpart of the tombstone crash: the removed
/// link must not be rebuilt either.
#[cfg(unix)]
#[test]
fn repair_does_not_recreate_a_symlink_its_interrupted_tombstone_delete_removed() {
    const GROUP: &str = "group-tomb-link";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    state
        .file_index_repository()
        .set_record_kind(GROUP, "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target(GROUP, "link.txt", Some(b"target.txt"))
        .unwrap();
    std::os::unix::fs::symlink("target.txt", root.path().join("link.txt")).unwrap();
    crash_a_tombstone_delete_after_its_removal(&state, GROUP, root.path(), &record, &permit);

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(
        std::fs::symlink_metadata(root.path().join("link.txt")).is_err(),
        "repair recreated a symlink its tombstone delete had already removed"
    );
    assert_eq!(report.reconstructed, Vec::<String>::new());
}

/// The generic defense-in-depth fix: a `Hydrated` row that is missing
/// on disk, has no open intent, but still has an OUTSTANDING projection
/// obligation must not be classified as an offline deletion either --
/// the Convergence Engine has not finished deciding this path's fate
/// yet (this is the shape of a freshly-admitted row a repair sweep
/// happens to run before the first materialize attempt, a hazard-hold
/// route that never demoted `materialization_state` itself, or any
/// future route with the same gap -- covered generically instead of
/// patched per route). Same setup as
/// `repair_does_not_resurrect_an_offline_deleted_symlink` immediately
/// above, with one addition: a projection-obligation row for the path.
#[test]
fn repair_does_not_classify_as_offline_deleted_while_a_projection_obligation_is_still_unsettled() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "not-yet-placed-link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    state.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();
    state
        .file_index_repository()
        .set_record_kind("group-1", "not-yet-placed-link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "not-yet-placed-link.txt", Some(b"target.txt"))
        .unwrap();
    // No intent opened, nothing on disk -- same as the offline-deleted
    // test above, EXCEPT this path still has an outstanding projection
    // obligation, simulating "admitted but never yet materialized"
    // rather than "materialized, then offline-deleted".
    state
        .sqlite()
        .dag_bump_projection_obligations_for_touched_paths(
            "group-1",
            &["not-yet-placed-link.txt"],
            1,
        )
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(
        report.offline_deleted,
        Vec::<String>::new(),
        "a path with an unsettled projection obligation must never be classified as an \
         offline deletion, even at startup"
    );
    // Not just "no tombstone" -- also "not silently resurrected". A
    // still-unsettled path must be deferred entirely, not reconstructed
    // either: falling through to reconstruction here would recreate a
    // symlink that might describe a genuine, still-fresh offline
    // deletion racing this unrelated obligation. `report.reconstructed`
    // being empty proves repair took neither side of that decision.
    assert_eq!(report.reconstructed, Vec::<String>::new());
    // `Path::exists()` follows symlinks and reports `false` for a
    // dangling one (this test's `record` names a `symlink_target` that
    // is never actually created on disk) -- it would read as "doesn't
    // exist" whether or not repair wrote a symlink here, so it cannot
    // tell "left alone" apart from "reconstructed". `symlink_metadata`
    // does not follow the link, so it distinguishes them correctly.
    assert!(
        std::fs::symlink_metadata(root.path().join("not-yet-placed-link.txt")).is_err(),
        "repair must not have written anything at all for a still-unsettled path"
    );
}

/// `RepairMode::Live`'s whole reason to exist: a `Hydrated` record
/// whose on-disk bytes are present but diverge from the index, with
/// NO open materialization intent, must NOT be treated the same way
/// `RepairMode::Startup` does (quarantine + heal from the index) --
/// it may be a live user edit still sitting in the debounce
/// accumulator, not an offline edit. Live mode must leave the file
/// completely untouched and instead hand it to the dirty-journal
/// backstop, which is what actually captures a real live edit.
#[test]
fn live_repair_does_not_quarantine_a_present_divergent_file_with_no_open_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let indexed_content = b"the synced, indexed content";
    let hash = hex::decode(store.put(indexed_content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("doc.txt", indexed_content, hash),
        &permit,
    );
    // No materialization intent opened -- and the on-disk bytes differ
    // from what's indexed, simulating a live user edit that has not
    // yet been captured (no crash, the "daemon" here never stopped).
    let live_edit_content = b"a live user edit still in flight";
    std::fs::write(root.path().join("doc.txt"), live_edit_content).unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert!(
        report.quarantined_dirty.is_empty(),
        "live mode must never quarantine a possibly-in-flight local edit: {:?}",
        report.quarantined_dirty
    );
    assert!(report.reconstructed.is_empty());
    assert_eq!(
        std::fs::read(root.path().join("doc.txt")).unwrap(),
        live_edit_content,
        "the canonical file must be left completely untouched by live repair"
    );
    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    assert!(
        dirty.iter().any(|d| d.path == "doc.txt"),
        "the live edit must be handed to the dirty-journal backstop instead: {dirty:?}"
    );
}

/// Regression pin: `RepairMode::Startup` keeps its original,
/// conservative behavior for the exact same present-but-divergent,
/// no-intent scenario `live_repair_does_not_quarantine_...` above
/// covers for `Live` -- at startup, before any watcher/live-capture
/// pipeline exists, this observation can only be an offline edit, so
/// quarantining and healing from the index is correct.
#[test]
fn startup_repair_still_quarantines_a_present_divergent_file_with_no_open_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let indexed_content = b"the synced, indexed content";
    let hash = hex::decode(store.put(indexed_content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("doc.txt", indexed_content, hash),
        &permit,
    );
    let offline_edit_content = b"an edit made while the daemon was stopped";
    std::fs::write(root.path().join("doc.txt"), offline_edit_content).unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.quarantined_dirty.len(), 1);
    assert_eq!(report.quarantined_dirty[0].0, "doc.txt");
    assert_eq!(
        std::fs::read(root.path().join("doc.txt")).unwrap(),
        indexed_content,
        "startup mode must heal the canonical path back to the indexed content"
    );
    let quarantine_path = &report.quarantined_dirty[0].1;
    assert_eq!(
        std::fs::read(root.path().join(quarantine_path)).unwrap(),
        offline_edit_content,
        "the offline edit's own bytes must be preserved in the quarantine copy"
    );
}

/// `RepairMode::Live`'s missing-file counterpart: a `Hydrated` record
/// whose file is missing, with no open intent, must not be classified
/// as an offline deletion the way `Startup` mode does -- it may be a
/// live delete in progress. Hand it to the dirty-journal backstop
/// instead of touching the index/emitting a tombstone directly.
#[test]
fn live_repair_records_a_dirty_removal_instead_of_classifying_an_offline_delete() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"content that is about to look deleted";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    // No intent, and the file simply never existed under `root` here --
    // standing in for "missing right now," the same disk state a live
    // in-progress delete produces.

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert!(
        report.offline_deleted.is_empty(),
        "live mode must not classify a missing file as an offline deletion: {:?}",
        report.offline_deleted
    );
    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    assert!(
        dirty.iter().any(|d| d.path == "doc.txt" && d.change_kind == "removed"),
        "the missing file must be handed to the dirty-journal backstop as a removal: {dirty:?}"
    );
}

#[test]
fn repair_demotes_to_placeholder_when_blocks_are_also_missing_locally() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("missing.bin", b"not present", vec![0xcd; 32]),
        &permit,
    );
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "missing.bin", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
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

/// Which block-store call supersedes the row in [`SupersedingStore`]:
/// `present_blocks` for the missing-blocks demotion arm, `get` (which then
/// fails, so the reconstruct fails) for the reconstruct-failed arm.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SupersedeOn {
    PresentBlocks,
    GetThenFail,
}

/// A block store that supersedes the repair's row to a new version in the
/// middle of the repair's iteration -- after the lane took its row snapshot
/// under the path lock, before it demotes the row to a placeholder. It does
/// what the lock-free rebootstrap install (`replace_group_files_from_
/// snapshot`) does to a live current row: a new version, left `Placeholder`.
struct SupersedingStore<'a> {
    inner: &'a SegmentBlockStore,
    state: &'a ReplicaCoordinator,
    group_id: &'a str,
    on: SupersedeOn,
    v2: std::sync::Mutex<Option<FileRecord>>,
}

impl SupersedingStore<'_> {
    fn supersede_once(&self) {
        let Some(v2) = self.v2.lock().unwrap().take() else { return };
        let permit = RootCommitPermit::for_tests();
        self.state.file_index_repository().upsert_file(self.group_id, &v2, &permit).unwrap();
        self.state
            .materialization_state_repository()
            .set_materialization_state(
                self.group_id,
                &v2.path,
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
    }
}

impl yadorilink_local_storage::BlockContentStore for SupersedingStore<'_> {
    fn put(
        &self,
        data: &[u8],
    ) -> Result<yadorilink_local_storage::ContentHash, yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put(self.inner, data)
    }

    fn put_prepared(
        &self,
        prepared: &yadorilink_local_storage::LocallyHashedBlock,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put_prepared(self.inner, prepared)
    }

    fn put_prepared_batch(
        &self,
        prepared: &[yadorilink_local_storage::LocallyHashedBlock],
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put_prepared_batch(self.inner, prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
        if self.on == SupersedeOn::GetThenFail {
            self.supersede_once();
            return Err(yadorilink_local_storage::StorageError::Io(std::io::Error::other(
                "test-injected block read failure",
            )));
        }
        yadorilink_local_storage::BlockStore::get(self.inner, hash)
    }

    fn present_blocks(
        &self,
        hashes: &[yadorilink_local_storage::ContentHash],
    ) -> Result<Vec<bool>, yadorilink_local_storage::StorageError> {
        let present = yadorilink_local_storage::BlockStore::present_blocks(self.inner, hashes)?;
        if self.on == SupersedeOn::PresentBlocks {
            self.supersede_once();
        }
        Ok(present)
    }
}

/// A repair pass whose row is superseded to V2 after its snapshot
/// must not demote or placeholder the path for V1. Runs both placeholder
/// arms: blocks missing, and reconstruct failed with every block present.
fn assert_a_superseded_repair_writes_no_v1_placeholder(on: SupersedeOn) {
    const GROUP: &str = "group-superseded-repair-demotion";
    let store_dir = tempfile::tempdir().unwrap();
    let inner = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let v1_content = b"version one, eleven";
    let v1 = match on {
        // Absent from the store: the missing-blocks arm.
        SupersedeOn::PresentBlocks => record_with_blocks("doc.bin", v1_content, vec![0xcd; 32]),
        // Present, so the lane reconstructs, and the read fails.
        SupersedeOn::GetThenFail => store_and_record(&inner, "doc.bin", v1_content),
    };
    upsert_hydrated_file(&state, GROUP, &v1, &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "doc.bin", &[0; 32], &permit)
        .unwrap();
    let v2_content = b"version two is a good deal longer than version one";
    let v2 = record_with_blocks("doc.bin", v2_content, vec![0xef; 32]);
    let store = SupersedingStore {
        inner: &inner,
        state: &state,
        group_id: GROUP,
        on,
        v2: std::sync::Mutex::new(Some(v2.clone())),
    };

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(store.v2.lock().unwrap().is_none(), "the supersession must have run mid-pass");
    let on_disk = std::fs::metadata(root.path().join("doc.bin")).ok().map(|m| m.len());
    assert_eq!(
        on_disk, None,
        "a repair about V1 wrote a placeholder (V1 is {} bytes, V2 {}) over the V2 row",
        v1.size, v2.size
    );
    assert!(report.demoted_to_placeholder.is_empty(), "{:?}", report.demoted_to_placeholder);
    assert_eq!(
        MaterializationExecutionPort::get_recorded_placeholder_identity(&state, GROUP, "doc.bin")
            .unwrap(),
        None,
        "no placeholder identity may be recorded for the V2 row from a V1 write"
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.bin")
            .unwrap(),
        Some(MaterializationState::Placeholder),
        "the V2 row keeps the state its own writer gave it"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "doc.bin")
            .unwrap(),
        "a stale attempt writes nothing, the intent included"
    );
}

#[test]
fn a_repair_whose_row_was_superseded_writes_no_placeholder_when_blocks_are_missing() {
    assert_a_superseded_repair_writes_no_v1_placeholder(SupersedeOn::PresentBlocks);
}

#[test]
fn a_repair_whose_row_was_superseded_writes_no_placeholder_when_the_reconstruct_fails() {
    assert_a_superseded_repair_writes_no_v1_placeholder(SupersedeOn::GetThenFail);
}

/// The tenth route in the "current, non-deleted row with nothing on
/// disk under its own name and no protecting intent/obligation/hold"
/// bug family, at this repair sweep's own missing-blocks placeholder-
/// demotion arm: `create_or_defer_placeholder` writes nothing on
/// Windows (real creation deferred to `cfapi-host.exe`'s own poll),
/// but this arm used to clear the row's protecting intent
/// unconditionally, exactly as if a real placeholder write had
/// happened. This sweep runs on a live ~90s periodic cadence, so the
/// window is not a rare crash race. Uses `create_or_defer_
/// placeholder`'s own test-only failure-injection seam (real Windows
/// behavior is not exercisable on this host) to force the deferred
/// outcome regardless of platform.
#[test]
fn repair_leaves_the_intent_open_when_the_windows_placeholder_write_is_deferred() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("missing-deferred.bin", b"not present either", vec![0xce; 32]),
        &permit,
    );
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "missing-deferred.bin", &[0; 32], &permit)
        .unwrap();

    // `repair_interrupted_materializations` canonicalizes `root` itself
    // (via `MaterializationExecutionPort::open_root` ->
    // `VerifiedRoot::open`, which calls `root.canonicalize()`) before
    // ever joining a path onto it -- see that type's own doc comment
    // ("Callers relativize walked entries against this, so it must be
    // the same resolution the caller's own scan performs internally").
    // The failure-injection seam below matches on exact `PathBuf`
    // equality, not on-disk identity, so this test must arm the SAME
    // canonicalized path repair will actually build internally, not
    // the raw `tempdir()` path -- on a host where the temp directory
    // itself sits behind a symlink (e.g. macOS's `/var` ->
    // `/private/var`, under which `TMPDIR` lives), those two differ:
    // arming the raw path would silently never match, and the real
    // (non-deferred) `write_placeholder` would run instead, leaving an
    // actual placeholder file this test's own sanity assertion below
    // expects to be absent.
    let canonical_root = root.path().canonicalize().unwrap();
    let out_path = canonical_root.join("missing-deferred.bin");
    yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
        &out_path, true,
    );
    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    );
    yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
        &out_path, false,
    );
    let report = report.unwrap();

    assert_eq!(report.demoted_to_placeholder, vec!["missing-deferred.bin"]);
    assert!(
        !root.path().join("missing-deferred.bin").exists(),
        "sanity: the deferred placeholder write must genuinely be absent"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "missing-deferred.bin")
            .unwrap(),
        "a materialization intent must protect this path while its real placeholder \
         creation is deferred to cfapi-host.exe -- clearing it here removes the only \
         thing telling the tombstone loop this is not a genuine offline deletion"
    );
}

/// A bounded batch's `open_projected_upserts_batch` commits the
/// row+intent for every upsert in one transaction, before ANY of their
/// temp files publish to their final path (see that method's own doc
/// comment). A crash in exactly that window -- after this commits, but
/// before `try_commit_ordinary_batch`'s own per-path `persist_
/// reconstructed_file` call ever runs for this candidate -- must look
/// identical to an unbatched `materialize()`'s own crash-after-intent-
/// open window to the existing repair pass: reconstructed from the
/// still-locally-present blocks, not silently classified as an offline
/// deletion.
#[test]
fn a_crash_after_the_batch_commits_a_rows_intent_but_before_its_disk_publish_is_repaired_from_local_blocks(
) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"batched upsert content, never published before the simulated crash";
    let record = store_and_record(&store, "batched.txt", content);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();

    let prepared = PreparedProjectedUpsert {
        rel_path: "batched.txt".to_string(),
        tmp_path: root.path().join(".never-published.tmp"),
        out_path: root.path().join("batched.txt"),
        record: record.clone(),
        origin_device_id: "device-b".to_string(),
        authoring_change_hash: None,
        target_version_hash: yadorilink_local_storage::intent_target_hash(&record.blocks),
        metadata: LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            xattrs: Vec::new(),
        },
        derived_head: None,
        newly_fetched_block_hashes: Vec::new(),
        realized_causal_basis: Vec::new(),
        // These fixtures build their record directly rather than from
        // a version, so derive the one that record names -- the same
        // canonical derivation the production payload carries.
        written_version: yadorilink_replica_domain::file::FileVersion::from_index_row(
            record.blocks.clone(),
            record.size,
            record.mtime_unix_nanos,
            RecordKind::File,
            None,
            None,
            Vec::new(),
        ),
    };
    state
        .open_projected_upserts_batch("group-1", std::slice::from_ref(&prepared), &permit)
        .unwrap();
    assert!(
        !root.path().join("batched.txt").exists(),
        "sanity: this test's whole point is that the disk publish never happened"
    );
    assert!(state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "batched.txt")
        .unwrap());

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["batched.txt".to_string()]);
    assert!(report.offline_deleted.is_empty(), "must not be misread as an offline deletion");
    assert_eq!(std::fs::read(root.path().join("batched.txt")).unwrap(), content);
}

/// The ordinary batch's other crash window: `try_commit_ordinary_batch` has already
/// published this candidate's temp file to its final path, but crashes
/// before its own `finalize_projected_mutations_batch` call -- so the
/// row stays `Hydrated` with a dangling open intent and no recorded
/// fingerprint. The published bytes already match the index, so repair
/// must recognize this as already-complete and just drop the stale
/// intent (matching an unbatched `materialize()`'s identical crash-
/// after-rename-before-intent-clear window) -- never quarantine or
/// otherwise disturb the correct, already-durable file.
#[test]
fn a_crash_after_the_batchs_disk_publish_but_before_finalize_only_clears_the_stale_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"batched upsert content, published to disk before the simulated crash";
    let record = store_and_record(&store, "batched2.txt", content);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();

    let prepared = PreparedProjectedUpsert {
        rel_path: "batched2.txt".to_string(),
        tmp_path: root.path().join(".pending.tmp"),
        out_path: root.path().join("batched2.txt"),
        record: record.clone(),
        origin_device_id: "device-b".to_string(),
        authoring_change_hash: None,
        target_version_hash: yadorilink_local_storage::intent_target_hash(&record.blocks),
        metadata: LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            xattrs: Vec::new(),
        },
        derived_head: None,
        newly_fetched_block_hashes: Vec::new(),
        realized_causal_basis: Vec::new(),
        // These fixtures build their record directly rather than from
        // a version, so derive the one that record names -- the same
        // canonical derivation the production payload carries.
        written_version: yadorilink_replica_domain::file::FileVersion::from_index_row(
            record.blocks.clone(),
            record.size,
            record.mtime_unix_nanos,
            RecordKind::File,
            None,
            None,
            Vec::new(),
        ),
    };
    state
        .open_projected_upserts_batch("group-1", std::slice::from_ref(&prepared), &permit)
        .unwrap();
    // Stands in for `try_commit_ordinary_batch`'s own `persist_
    // reconstructed_file` publish, which this test does not need to
    // exercise again (already covered by `yadorilink-local-storage`'s
    // own tests) -- only the resulting on-disk state matters here.
    std::fs::write(root.path().join("batched2.txt"), content).unwrap();
    assert!(state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "batched2.txt")
        .unwrap());

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(report.reconstructed.is_empty());
    assert!(report.quarantined_dirty.is_empty());
    assert!(report.offline_deleted.is_empty());
    assert!(
        !state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "batched2.txt")
            .unwrap(),
        "repair must clear the stale intent once it confirms the published bytes already \
         match the index"
    );
    assert_eq!(std::fs::read(root.path().join("batched2.txt")).unwrap(), content);
}

/// The version a row names is a hash over the mode and the xattrs as
/// well as the bytes, so bytes that match are not yet the version. A
/// lane that crashes after its bytes land and before its mode is applied
/// leaves the row's intent open over the right bytes
/// with the old mode. Repair's disk-matches arm used to prove the version
/// on the bytes alone, publishing an exact proof of a mode disk never got.
#[cfg(unix)]
#[test]
fn repair_does_not_prove_a_version_whose_mode_disk_never_got() {
    use std::os::unix::fs::PermissionsExt;
    const GROUP: &str = "group-repair-mode-mismatch";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"#!/bin/sh\necho the version says this is executable\n";
    let record = store_and_record(&store, "run.sh", content);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let prepared = PreparedProjectedUpsert {
        rel_path: "run.sh".to_string(),
        tmp_path: root.path().join(".pending.tmp"),
        out_path: root.path().join("run.sh"),
        record: record.clone(),
        origin_device_id: "device-b".to_string(),
        authoring_change_hash: None,
        target_version_hash: yadorilink_local_storage::intent_target_hash(&record.blocks),
        metadata: LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: Some(0o755),
            xattrs: Vec::new(),
        },
        derived_head: None,
        newly_fetched_block_hashes: Vec::new(),
        realized_causal_basis: Vec::new(),
        written_version: yadorilink_replica_domain::file::FileVersion::from_index_row(
            record.blocks.clone(),
            record.size,
            record.mtime_unix_nanos,
            RecordKind::File,
            Some(0o755),
            None,
            Vec::new(),
        ),
    };
    state.open_projected_upserts_batch(GROUP, std::slice::from_ref(&prepared), &permit).unwrap();
    // The crash: the bytes landed, the exec bit never did.
    let out_path = root.path().join("run.sh");
    std::fs::write(&out_path, content).unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    let disk_mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
    let proven =
        MaterializationExecutionPort::has_usable_materialized_generation(&state, GROUP, "run.sh")
            .unwrap();
    assert!(
        !(proven && disk_mode != 0o755),
        "repair proved a version whose mode is 0o755 over a file whose mode is {disk_mode:o}"
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), content);
    assert_eq!(disk_mode, 0o755, "repair finishes the write by applying the version's mode");
    assert!(proven, "and then proves what it wrote");
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

/// A recorded placeholder identity survives an in-process
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
        .record_placeholder_generation("group-1", "doc.txt", identity, "internal-inode", &permit)
        .unwrap();

    assert_eq!(
        state
            .materialization_state_repository()
            .get_placeholder_generation("group-1", "doc.txt")
            .unwrap(),
        Some(recorded(identity))
    );
}

/// `record_placeholder_generation_if_absent` must do its
/// check-then-write atomically in one `database.write` closure -- pins
/// the race a two-call form would have (`get_placeholder_generation` then a separate
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

    let windows_identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 99 };
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

/// A row that has since left
/// `Placeholder` (hydrated, say) must never expose its old identity
/// through this getter, even though nothing explicitly cleared it --
/// gated on the row's own current `materialization_state`, not merely
/// on the recorded columns being non-NULL.
#[test]
fn placeholder_generation_is_hidden_once_the_row_leaves_placeholder_state() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
    let repo = state.materialization_state_repository();
    repo.record_placeholder_generation("group-1", "doc.txt", identity, "internal-inode", &permit)
        .unwrap();

    repo.set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrated, &permit)
        .unwrap();

    assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
}

/// The opposite property from the test above, on the OTHER
/// accessor -- `get_recorded_placeholder_identity` must keep exposing
/// a row's identity after it leaves `Placeholder` for `Hydrated`,
/// since Windows eviction reads a `Hydrated` file's still-recorded
/// generation as the expected identity for its native dehydrate call.
/// If this ever regressed to also gating on `materialization_state =
/// 'placeholder'` (e.g. by accidentally sharing `get_placeholder_
/// generation`'s query), `evict_to_placeholder`'s Windows arm would
/// treat every genuinely-placeholdered `Hydrated` file as having "no
/// recorded identity" and refuse to evict it at all.
#[test]
fn recorded_placeholder_identity_survives_the_hydrated_transition() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 7 };
    let repo = state.materialization_state_repository();
    repo.record_placeholder_generation(
        "group-1",
        "doc.txt",
        identity,
        "windows-cfapi-generation",
        &permit,
    )
    .unwrap();

    repo.set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrated, &permit)
        .unwrap();

    // The dirty-detection accessor hides it (previous test) ...
    assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
    // ... but the eviction accessor still sees it.
    assert_eq!(
        repo.get_recorded_placeholder_identity("group-1", "doc.txt").unwrap(),
        Some(yadorilink_sync_sqlite::RecordedPlaceholderGeneration {
            identity,
            provider_kind: "windows-cfapi-generation".to_owned(),
        })
    );
    assert_eq!(
        state.get_recorded_placeholder_identity("group-1", "doc.txt").unwrap(),
        Some((identity, "windows-cfapi-generation".to_owned()))
    );
}

/// A newer placeholder write's identity must fully replace an older
/// one -- `record_placeholder_generation` called twice for the same
/// path leaves only the SECOND identity readable, never a stale first
/// one a caller could wrongly trust. This is the exact "stale
/// generation must not be trusted" invariant.
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
    repo.record_placeholder_generation("group-1", "doc.txt", identity, "internal-inode", &permit)
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
        .upsert_file("group-1", &record_with_blocks("has-one.bin", b"x", vec![0xab; 32]), &permit)
        .unwrap();
    state
        .file_index_repository()
        .upsert_file("group-1", &record_with_blocks("has-none.bin", b"y", vec![0xcd; 32]), &permit)
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

    let all =
        state.materialization_state_repository().list_placeholder_generations("group-1").unwrap();

    assert_eq!(all.get("has-one.bin"), Some(&recorded(identity)));
    assert!(!all.contains_key("has-none.bin"));
}

/// `RepairRowSnapshot` is named for a property it has to actually
/// have.
///
/// It used to take the version, authoring and state from one canonical
/// statement and then go back to the database twice more for the kind
/// and the record -- three read transactions with no isolation
/// spanning them. The struct could carry the version and authoring of
/// one incarnation of the row beside the blocks and kind of another,
/// and repair would then check a guard built from the first against
/// bytes chosen by the second.
///
/// The path lock does not close that. The mainline DAG appliers take
/// it, but a whole-group row replacement does not, and it can run
/// while a live repair pass is between reads.
mod repair_row_snapshot {
    use super::*;

    const GROUP: &str = "g";
    const PATH: &str = "notes.txt";

    fn record(size: u64, hash: u8) -> FileRecord {
        FileRecord {
            path: PATH.into(),
            size,
            mtime_unix_nanos: 0,
            blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                hash: vec![hash; 32],
                offset: 0,
                size: size as u32,
            }],
            deleted: false,
        }
    }

    /// Every field describes the same row, including the two that used
    /// to be fetched separately.
    #[test]
    fn every_field_comes_from_the_same_incarnation_of_the_row() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();
        coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record(4, 1), "device-a", &permit)
            .unwrap();
        coordinator
            .file_index_repository()
            .set_symlink_target(GROUP, PATH, Some(b"../elsewhere"))
            .unwrap();
        coordinator
            .file_index_repository()
            .set_record_kind(GROUP, PATH, RecordKind::Symlink, &permit)
            .unwrap();

        let snapshot = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            PATH,
        )
        .unwrap();

        assert_eq!(snapshot.record_kind, Some(RecordKind::Symlink));
        assert_eq!(
            snapshot.symlink_target.as_deref(),
            Some(&b"../elsewhere"[..]),
            "the target must come from the snapshot, not a fourth read at the point of use"
        );
        let file = snapshot.file.expect("a current row");
        assert_eq!(file.size, 4);
        assert!(snapshot.current_version.is_some());
    }

    /// The version a guard is built from and the blocks a verification
    /// runs against must move together. A read taken after a
    /// supersession must never yield the old version beside the new
    /// blocks.
    #[test]
    fn a_supersession_moves_every_field_together() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();
        coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record(4, 1), "device-a", &permit)
            .unwrap();
        let before = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            PATH,
        )
        .unwrap();

        coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record(7, 9), "device-a", &permit)
            .unwrap();
        let after = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            PATH,
        )
        .unwrap();

        assert_ne!(before.current_version, after.current_version, "the version must move");
        assert_ne!(
            before.file.as_ref().unwrap().blocks,
            after.file.as_ref().unwrap().blocks,
            "and so must the blocks -- a snapshot holding one of each is the defect"
        );
        assert_eq!(after.file.as_ref().unwrap().size, 7);
    }

    /// A path with no current row answers empty rather than a
    /// half-built struct whose `file` came from a row its
    /// `current_version` did not.
    #[test]
    fn a_missing_row_yields_nothing_rather_than_a_partial_snapshot() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let snapshot = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            "never-seen",
        )
        .unwrap();
        assert!(snapshot.file.is_none());
        assert!(snapshot.current_version.is_none());
        assert!(snapshot.record_kind.is_none());
        assert!(snapshot.symlink_target.is_none());
        assert!(snapshot.materialization_state.is_none());
    }
}

/// Eviction and sweep failures that are local to one path. A read-only
/// parent directory makes the placeholder write fail before its rename,
/// after the eviction has already marked the row `Evicting` and bumped the
/// path's fence; an unreadable file makes the repair sweep's byte compare
/// fail. Each test probes first that the permission actually denies this
/// process (a root user is not denied) and returns early when it does not.
#[cfg(unix)]
mod path_local_failure_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use yadorilink_filesystem_sync::materialization_eviction::run_eviction_sweep;
    use yadorilink_filesystem_sync::materialization_execution::AbandonedEviction;

    const GROUP: &str = "group-path-local-failure";

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Makes `dir` read-only; `false` (and the mode restored) when this
    /// process can still create a file in it.
    fn make_dir_unwritable(dir: &Path) -> bool {
        set_mode(dir, 0o555);
        let probe = dir.join(".write-probe");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            set_mode(dir, 0o755);
            return false;
        }
        true
    }

    fn hydrated_on_disk(
        state: &ReplicaCoordinator,
        store: &SegmentBlockStore,
        root: &Path,
        path: &str,
        content: &[u8],
        permit: &RootCommitPermit,
    ) {
        let record = store_and_record(store, path, content);
        upsert_hydrated_file(state, GROUP, &record, permit);
        let out_path = root.join(path);
        std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();
        std::fs::write(out_path, content).unwrap();
    }

    fn row_state(state: &ReplicaCoordinator, path: &str) -> Option<MaterializationState> {
        state.materialization_state_repository().get_materialization_state(GROUP, path).unwrap()
    }

    /// A failure after the fence bump must not leave the row `Evicting`
    /// until the next daemon start: nothing but the startup reset moves a
    /// row out of it, so the file stays reported as in flight, is no longer
    /// an eviction candidate and is not a repair candidate. The write never
    /// landed and the bytes still verify, so the row goes back to
    /// `Hydrated` with a proof published under the bumped fence.
    #[test]
    fn an_eviction_whose_placeholder_write_fails_goes_back_to_hydrated_with_a_proof() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        let content = b"bytes an eviction failed to replace";
        hydrated_on_disk(&state, &store, root.path(), "dir/a.bin", content, &permit);
        let dir = root.path().join("dir");
        if !make_dir_unwritable(&dir) {
            return;
        }

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            "dir/a.bin",
            false,
            &NeverConfirms,
        );
        set_mode(&dir, 0o755);

        assert!(result.is_err(), "the placeholder write failed, got {result:?}");
        assert_eq!(std::fs::read(root.path().join("dir/a.bin")).unwrap(), content);
        assert_eq!(
            row_state(&state, "dir/a.bin"),
            Some(MaterializationState::Hydrated),
            "a failed eviction must not leave its row Evicting"
        );
        assert!(
            MaterializationExecutionPort::has_usable_materialized_generation(
                &state,
                GROUP,
                "dir/a.bin"
            )
            .unwrap(),
            "the verified bytes are proven again under the fence the attempt bumped"
        );
    }

    /// One path whose eviction fails is that path's problem: the sweep
    /// goes on to the next candidate instead of returning the error.
    #[test]
    fn an_eviction_sweep_continues_past_one_paths_failed_eviction() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "dir/a.bin", b"least recently used", &permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"used after a.bin", &permit);
        state.file_index_repository().touch_last_accessed(GROUP, "dir/a.bin", 1).unwrap();
        state.file_index_repository().touch_last_accessed(GROUP, "b.bin", 2).unwrap();
        let dir = root.path().join("dir");
        if !make_dir_unwritable(&dir) {
            return;
        }

        let result = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            false,
            Some(0),
            &NeverConfirms,
        );
        set_mode(&dir, 0o755);

        assert_eq!(
            result.expect("one path's failed eviction must not fail the sweep"),
            vec!["b.bin".to_owned()]
        );
        assert_eq!(row_state(&state, "b.bin"), Some(MaterializationState::Placeholder));
        assert_eq!(row_state(&state, "dir/a.bin"), Some(MaterializationState::Hydrated));
    }

    /// The repair sweep, the same way: an unreadable file stops only its
    /// own repair, and the pass still re-proves the next path.
    #[test]
    fn a_repair_sweep_continues_past_one_paths_unreadable_file() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"unreadable to this user", &permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"readable, needs a proof", &permit);
        let unreadable = root.path().join("a.bin");
        set_mode(&unreadable, 0o000);
        if std::fs::read(&unreadable).is_ok() {
            set_mode(&unreadable, 0o644);
            return;
        }

        let result = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            GROUP,
            RepairMode::Startup,
            &permit,
        );
        set_mode(&unreadable, 0o644);

        let report = result.expect("one path's read failure must not fail the sweep");
        assert_eq!(report.reproven, vec!["b.bin".to_owned()]);
        assert_eq!(report.failed, vec!["a.bin".to_owned()], "and the failed path is reported");
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Hydrated));
    }

    /// A failed eviction's own failure is logged only when it, too, belongs
    /// to the path. When closing the row fails for a reason the whole
    /// transaction shares (a database failure), the eviction returns that
    /// error rather than the path-local one it was already carrying, so the
    /// sweep aborts instead of reaching the same failure on every candidate.
    #[test]
    fn a_failed_evictions_transaction_wide_abandon_failure_aborts_the_sweep() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "dir/a.bin", b"least recently used", &permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"used after a.bin", &permit);
        state.file_index_repository().touch_last_accessed(GROUP, "dir/a.bin", 1).unwrap();
        state.file_index_repository().touch_last_accessed(GROUP, "b.bin", 2).unwrap();
        let dir = root.path().join("dir");
        if !make_dir_unwritable(&dir) {
            return;
        }
        state
            .test_observers
            .abandon_eviction_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let result = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            false,
            Some(0),
            &NeverConfirms,
        );
        set_mode(&dir, 0o755);

        assert!(
            matches!(result, Err(MaterializationExecutionError::CorruptState(_))),
            "the abandon's transaction-wide failure must abort the sweep: {result:?}"
        );
        assert_eq!(
            row_state(&state, "b.bin"),
            Some(MaterializationState::Hydrated),
            "no later candidate may be evicted once the sweep aborts"
        );
    }

    /// Group-wide failures are told apart at their source, not by the
    /// error's variant: every eviction re-verifies the root before it
    /// touches anything, so a root that lost its identity (unmounted,
    /// replaced) fails the first candidate as a root-authority error and
    /// the sweep aborts, instead of failing every candidate as a
    /// path-local I/O error.
    #[test]
    fn an_eviction_sweep_under_a_lost_root_aborts_at_the_first_candidate() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"least recently used", &permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"used after a.bin", &permit);
        state.file_index_repository().touch_last_accessed(GROUP, "a.bin", 1).unwrap();
        state.file_index_repository().touch_last_accessed(GROUP, "b.bin", 2).unwrap();
        std::fs::remove_file(
            root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let result = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            false,
            Some(0),
            &NeverConfirms,
        );

        assert!(
            matches!(result, Err(MaterializationExecutionError::RootAuthority(_))),
            "a lost root must abort the sweep: {result:?}"
        );
        for path in ["a.bin", "b.bin"] {
            assert_eq!(row_state(&state, path), Some(MaterializationState::Hydrated));
        }
    }

    /// A held root lease whose root this process no longer owns: the lock
    /// sidecar was replaced, so every permit from it fails to verify, and
    /// fails as an I/O error, the variant a path-local failure also uses.
    fn lost_root_operation(
        locked: &Path,
    ) -> yadorilink_root_authority::root_commit::LinkOperation<'static> {
        let lock =
            yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(locked).unwrap();
        let lease: &'static _ = Box::leak(Box::new(
            yadorilink_root_authority::root_commit::RootLease::new(lock, GROUP.to_string(), 0),
        ));
        let operation = lease.begin_operation().unwrap();
        let lock_path =
            locked.join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();
        assert!(
            operation.permit().verify().is_err(),
            "fixture check: the root must really look lost, or this test proves nothing"
        );
        operation
    }

    /// A root lost while the eviction sweep runs surfaces from the first
    /// owner transaction as an I/O error. The sweep must stop there, not
    /// meet the same lost root at every remaining candidate.
    #[test]
    fn an_eviction_sweep_stops_when_its_root_is_lost_mid_sweep() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let setup_permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"first", &setup_permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"second", &setup_permit);
        state.file_index_repository().touch_last_accessed(GROUP, "a.bin", 1).unwrap();
        state.file_index_repository().touch_last_accessed(GROUP, "b.bin", 2).unwrap();
        let locked = tempfile::tempdir().unwrap();
        let operation = lost_root_operation(locked.path());

        let result = run_eviction_sweep(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &operation.permit(),
            },
            GROUP,
            false,
            Some(0),
            &NeverConfirms,
        );

        assert!(
            matches!(result, Err(MaterializationExecutionError::RootAuthority(_))),
            "a root lost mid-sweep must abort the sweep: {result:?}"
        );
        for path in ["a.bin", "b.bin"] {
            assert_eq!(row_state(&state, path), Some(MaterializationState::Hydrated));
        }
    }

    /// The repair sweep, the same way.
    #[test]
    fn a_repair_sweep_stops_when_its_root_is_lost_mid_sweep() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let setup_permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"needs a proof", &setup_permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"so does this", &setup_permit);
        let locked = tempfile::tempdir().unwrap();
        let operation = lost_root_operation(locked.path());

        let result = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            GROUP,
            RepairMode::Startup,
            &operation.permit(),
        );

        assert!(
            matches!(result, Err(MaterializationExecutionError::RootAuthority(_))),
            "a root lost mid-sweep must abort the sweep: {result:?}"
        );
    }

    /// A row the eviction lane left `Evicting` over `content` on disk, and
    /// the version it names.
    fn evicting_row(
        state: &ReplicaCoordinator,
        root: &Path,
        path: &str,
        content: &[u8],
    ) -> VersionHash {
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(state, &store, root, path, content, &permit);
        state
            .materialization_state_repository()
            .set_materialization_state(GROUP, path, MaterializationState::Evicting, &permit)
            .unwrap();
        state
            .file_index_repository()
            .canonical_current_row(GROUP, path)
            .unwrap()
            .unwrap()
            .version_hash()
    }

    fn has_proof(state: &ReplicaCoordinator, path: &str) -> bool {
        MaterializationExecutionPort::has_usable_materialized_generation(state, GROUP, path)
            .unwrap()
    }

    fn abandon(
        state: &ReplicaCoordinator,
        path: &str,
        version: &VersionHash,
        abandoned: AbandonedEviction,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError> {
        MaterializationExecutionPort::abandon_eviction(
            state, GROUP, path, version, abandoned, permit,
        )
    }

    #[test]
    fn an_abandoned_eviction_whose_file_no_longer_verifies_goes_back_to_hydrated_unproven() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"edited during the attempt");

        let permit = RootCommitPermit::for_tests();
        assert!(abandon(&state, "a.bin", &version, AbandonedEviction::NotWritten, &permit).unwrap());
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Hydrated));
        assert!(!has_proof(&state, "a.bin"), "bytes that did not verify earn no proof");
    }

    #[test]
    fn an_abandoned_eviction_whose_placeholder_may_exist_resolves_to_placeholder() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"dehydrated, or maybe not");

        let permit = RootCommitPermit::for_tests();
        assert!(abandon(
            &state,
            "a.bin",
            &version,
            AbandonedEviction::PlaceholderMayExist,
            &permit
        )
        .unwrap());
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Placeholder));
    }

    /// The row moved to another version while it was `Evicting`: whatever
    /// the file holds, it is not that version, so no claim of `Hydrated`
    /// and no proof, even for bytes that verified against the old one.
    #[test]
    fn an_abandoned_eviction_of_a_row_now_naming_another_version_resolves_to_placeholder() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        evicting_row(&state, root.path(), "a.bin", b"the version the eviction revalidated");
        let identity = yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
            &root.path().join("a.bin"),
        )
        .unwrap();
        let other_version = VersionHash([7u8; 32]);

        let permit = RootCommitPermit::for_tests();
        assert!(abandon(
            &state,
            "a.bin",
            &other_version,
            AbandonedEviction::Intact { identity },
            &permit
        )
        .unwrap());
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Placeholder));
        assert!(!has_proof(&state, "a.bin"));
    }

    #[test]
    fn abandoning_a_row_that_already_left_evicting_writes_nothing() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"settled by someone else");
        let permit = RootCommitPermit::for_tests();
        state
            .materialization_state_repository()
            .set_materialization_state(GROUP, "a.bin", MaterializationState::Placeholder, &permit)
            .unwrap();

        assert!(
            !abandon(&state, "a.bin", &version, AbandonedEviction::NotWritten, &permit).unwrap()
        );
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Placeholder));
    }

    /// Root swap: the permit is verified inside the abandon's transaction,
    /// so under a lost root it publishes no proof and moves nothing; the
    /// row stays `Evicting` for the startup reset rather than committing a
    /// claim about a root this device no longer owns.
    #[test]
    fn an_abandoned_eviction_under_a_lost_root_writes_nothing() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"bytes under a swapped root");
        let identity = yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
            &root.path().join("a.bin"),
        )
        .unwrap();
        let locked = tempfile::tempdir().unwrap();
        let lock = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(locked.path())
            .unwrap();
        let lease =
            yadorilink_root_authority::root_commit::RootLease::new(lock, GROUP.to_string(), 0);
        let operation = lease.begin_operation().unwrap();
        let lock_path =
            locked.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();
        assert!(
            operation.permit().verify().is_err(),
            "fixture check: the root must really look lost, or this test proves nothing"
        );

        let outcome = abandon(
            &state,
            "a.bin",
            &version,
            AbandonedEviction::Intact { identity },
            &operation.permit(),
        );

        assert!(outcome.is_err(), "an abandon under a lost root must fail");
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Evicting));
        assert!(!has_proof(&state, "a.bin"), "nothing may be published under a lost root");
    }
}

/// Runs a startup repair over one Hydrated row with an open intent, carrying
/// `mode` and `xattrs`, and reports what it reconstructed.
#[cfg(target_os = "linux")]
fn repair_one_with_metadata(
    mode: u32,
    xattrs: &[(String, Vec<u8>)],
) -> (ReplicaCoordinator, tempfile::TempDir, Vec<String>) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt with replicated metadata";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state.file_index_repository().set_unix_mode("group-1", "doc.txt", Some(mode), &permit).unwrap();
    state.file_index_repository().set_xattrs("group-1", "doc.txt", xattrs, &permit).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();
    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    (state, root, report.reconstructed)
}

/// Repair's reconstruct must not publish an exact proof when the replicated
/// attributes it set cannot be confirmed (a name the kernel rejects makes the
/// set fail silently), even though its bytes and mode landed.
#[cfg(target_os = "linux")]
#[test]
fn a_repair_reconstruct_publishes_no_proof_when_its_xattrs_cannot_be_confirmed() {
    let unsettable = vec![(format!("user.{}", "a".repeat(300)), b"v".to_vec())];

    let (state, _root, reconstructed) = repair_one_with_metadata(0o644, &unsettable);

    assert!(reconstructed.is_empty(), "an unproven reconstruct must not be reported as done");
    assert!(!MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
}

/// The positive half: valid attributes with a final owner-unreadable mode
/// reach the proof, on the check taken before the mode was applied.
#[cfg(target_os = "linux")]
#[test]
fn a_repair_reconstruct_to_an_owner_unreadable_mode_reaches_a_proof_with_its_xattr() {
    use std::os::unix::fs::PermissionsExt;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let (state, root, reconstructed) = repair_one_with_metadata(0o200, &xattrs);

    assert_eq!(reconstructed, vec!["doc.txt"]);
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
    let out_path = root.path().join("doc.txt");
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs
    );
}

/// Journals a restore of `doc.txt` whose version carries `mode` and
/// `xattrs`, leaves only its bytes on disk (as a process that died after
/// the rename and before applying the metadata would), then lets `prepare`
/// adjust the file and runs startup restore recovery.
#[cfg(target_os = "linux")]
fn recover_restore_with_metadata(
    mode: u32,
    xattrs: &[(String, Vec<u8>)],
    prepare: impl FnOnce(&Path),
) -> ReplicaCoordinator {
    let content = b"restored bytes left behind by a crash";
    let hash = <sha2::Sha256 as sha2::Digest>::digest(content).to_vec();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    state
        .restore_operation_repository()
        .record_restore_operation(&yadorilink_replica_domain::session_state::RestoreOperation {
            operation_id: "op-1".to_string(),
            group_id: "group-1".to_string(),
            path: "doc.txt".to_string(),
            target_version_seq: 1,
            expected_current_version_seq: None,
            state: yadorilink_replica_domain::session_state::RestoreOperationState::DiskCommitted,
            record: record_with_blocks("doc.txt", content, hash),
            origin_device_id: "device-a".to_string(),
            authoring_change_hash: None,
            meta: LocalFileMetaColumns {
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                unix_mode: Some(mode),
                xattrs: xattrs.to_vec(),
            },
        })
        .unwrap();
    let out_path = root.path().join("doc.txt");
    std::fs::write(&out_path, content).unwrap();
    prepare(&out_path);

    yadorilink_filesystem_sync::materialization_repair::reconcile_restore_operations(
        &state,
        root.path(),
        "group-1",
        &permit,
    )
    .unwrap();
    state
}

/// Recovery re-verified only the bytes, then published an exact proof for a
/// version whose mode and xattrs were never applied. It must re-prove them
/// from disk and publish nothing when they do not match.
#[cfg(target_os = "linux")]
#[test]
fn restore_recovery_publishes_no_proof_for_metadata_it_cannot_prove() {
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let state = recover_restore_with_metadata(0o640, &xattrs, |_| {});

    assert!(!MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
}

/// The positive half: when the bytes, the mode and the xattrs on disk are
/// all the journaled version's, recovery publishes its proof.
#[cfg(target_os = "linux")]
#[test]
fn restore_recovery_proves_a_file_whose_metadata_matches() {
    use std::os::unix::fs::PermissionsExt;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let state = recover_restore_with_metadata(0o640, &xattrs, |out_path| {
        yadorilink_local_storage::apply_xattrs(out_path, &xattrs).unwrap();
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    });

    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
}
