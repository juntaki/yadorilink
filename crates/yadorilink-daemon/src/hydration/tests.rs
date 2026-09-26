#![cfg(test)]

/// The version a seeded row currently names -- these guard fixtures
/// move only the materialization state, so this is the version the
/// simulated attempt is about.
fn current_version_hash_for(
    state: &std::sync::Arc<crate::replica_coordinator::ReplicaCoordinator>,
    group_id: &str,
    path: &str,
) -> yadorilink_replica_domain::ids::VersionHash {
    state
        .file_index_repository()
        .canonical_current_row(group_id, path)
        .expect("canonical current row")
        .expect("a seeded row")
        .version_hash()
}

use super::*;

/// The property this whole pipeline exists for: a lane must be able to
/// have several blocks awaiting durability at once.
///
/// Before, a lane awaited each block's commit inline, so the store saw
/// at most one submission per lane and a group commit could only ever
/// be as wide as the *fetch* window -- a number the peer's round-trip
/// behaviour chose, with nothing to do with storage. Asserted by
/// holding every ticket open until the last one has been pushed: if
/// pushing waited on the previous ticket, this deadlocks rather than
/// failing, which is exactly the shape of the bug.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lane_keeps_several_blocks_in_flight_for_durability_at_once() {
    let mut pipeline = DurabilityPipeline::new();
    let mut releases = Vec::new();

    // One short of the bound, so nothing is ever collected here and
    // every ticket stays outstanding.
    let held = DURABILITY_PIPELINE_DEPTH - 1;
    for _ in 0..held {
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        releases.push(release);
        pipeline.push(
            1,
            tokio::spawn(async move {
                let _ = wait.await;
                1
            }),
        );
        assert!(pipeline.settle_to_bound().await.is_none());
    }

    assert_eq!(
        pipeline.in_flight(),
        held,
        "every ticket pushed below the bound must still be outstanding -- a lane that \
         awaited each block's commit inline would show 0 here"
    );

    for release in releases {
        let _ = release.send(());
    }
    assert!(pipeline.settle_all().await.is_none());
    assert_eq!(pipeline.in_flight(), 0);
}

/// The count bound is what binds for tiny blocks: a folder of small
/// files reaches it long before any byte budget.
#[tokio::test]
async fn the_count_bound_binds_for_tiny_blocks() {
    let mut pipeline = DurabilityPipeline::new();
    for _ in 0..DURABILITY_PIPELINE_DEPTH * 3 {
        pipeline.push(1, tokio::spawn(async { 1u64 }));
        assert!(pipeline.settle_to_bound().await.is_none());
        assert!(
            pipeline.in_flight() < DURABILITY_PIPELINE_DEPTH,
            "the pipeline must settle back under its count bound, got {}",
            pipeline.in_flight()
        );
    }
    assert!(pipeline.settle_all().await.is_none());
}

/// The byte bound is what binds for large blocks, and it has to: a lane
/// holding sixteen-megabyte blocks would otherwise pin
/// `DURABILITY_PIPELINE_DEPTH` of them -- hundreds of megabytes per
/// lane, multiplied by every lane on every candidate.
#[tokio::test]
async fn the_byte_bound_binds_for_large_blocks() {
    let mut pipeline = DurabilityPipeline::new();
    let large = DURABILITY_PIPELINE_BYTES / 2;
    for _ in 0..8 {
        pipeline.push(large, tokio::spawn(async move { large }));
        assert!(pipeline.settle_to_bound().await.is_none());
        assert!(
            pipeline.in_flight_bytes() < DURABILITY_PIPELINE_BYTES,
            "the pipeline must settle back under its byte bound, got {} bytes in {} ticket(s)",
            pipeline.in_flight_bytes(),
            pipeline.in_flight()
        );
        assert!(
            pipeline.in_flight() < DURABILITY_PIPELINE_DEPTH,
            "blocks this size must be bounded by bytes, well before the count bound"
        );
    }
    assert!(pipeline.settle_all().await.is_none());
}

/// A panicking ticket must surface, not be swallowed: the dispatch
/// turns it into a fatal, and the block's own guard requeues on drop.
#[tokio::test]
async fn a_panicking_ticket_is_reported_rather_than_swallowed() {
    let mut pipeline = DurabilityPipeline::new();
    pipeline.push(1, tokio::spawn(async { panic!("ticket panicked") }));
    pipeline.push(1, tokio::spawn(async { 1u64 }));
    assert!(pipeline.settle_all().await.is_some(), "a join error must reach the caller");
}
use crate::replica_coordinator::ReplicaCoordinator;
use sha2::{Digest, Sha256};
use yadorilink_local_storage::SegmentBlockStore;

/// A fresh stall tracker at the production default -- for tests that
/// call `hydrate_inner` directly and don't care about stall-deadline
/// behavior specifically.
fn test_stall() -> Arc<HydrationStallTracker> {
    Arc::new(HydrationStallTracker::new(HYDRATION_TIMEOUT))
}

/// R3e: `per_block_fetch_timeout` (this module's own outer wrap around
/// `PeerSyncSession::fetch_block_sized`) must stay strictly above
/// `PeerSyncSession::fetch_response_timeout_for` (the inner deadline
/// that actually governs the fetch) with real margin, across a range
/// of block sizes -- not just the one size exercised by any single
/// integration test. If the outer wrap ever equalled or undercut the
/// inner one, it would preempt `fetch_block_sized` before its own
/// deadline could ever fire on its own, silently reintroducing the
/// exact "outer timeout masks the inner one" failure mode this pair of
/// constants exists to avoid (see `per_block_fetch_timeout`'s own doc
/// comment).
#[test]
fn outer_per_block_timeout_stays_above_the_inner_sized_deadline_with_margin() {
    for size in [0u64, 1, 4096, 128 * 1024, 1024 * 1024, 16 * 1024 * 1024] {
        let inner = PeerSyncSession::fetch_response_timeout_for(size);
        let outer = per_block_fetch_timeout(size);
        assert!(
            outer >= inner + PER_BLOCK_FETCH_TIMEOUT_MARGIN,
            "for size={size}: outer={outer:?} must be at least inner={inner:?} + \
             margin={PER_BLOCK_FETCH_TIMEOUT_MARGIN:?}"
        );
    }
}

fn block(hash_byte: u8) -> BlockInfo {
    BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 100 }
}

fn state_with_link(local_path: &str, group_id: &str) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    sync_state.link_repository().add_link(local_path, group_id).unwrap();
    DaemonState::new("device-a".into(), sync_state, store)
}

/// An orphaned link resolves the same as "no link registered for this
/// group" -- hydration must never fetch/write on-demand content into a
/// folder that is no longer a live sync target, even though the link
/// row itself is still present (and its files untouched).
#[tokio::test]
async fn local_root_for_group_treats_an_orphaned_link_as_absent() {
    let state = state_with_link("/home/alice/Photos", "group-1");

    assert_eq!(
        local_root_for_group(&state, "group-1").unwrap(),
        std::path::PathBuf::from("/home/alice/Photos")
    );

    state.replica_coordinator.link_repository().mark_link_orphaned("/home/alice/Photos").unwrap();

    assert!(
        local_root_for_group(&state, "group-1").is_err(),
        "an orphaned link must resolve the same as no link at all"
    );
}

/// A hydration attempt that cannot observe the file it just wrote must
/// leave the path RETRYABLE, not stuck.
///
/// `observe_path` failing is a transient filesystem condition. The
/// attempt has already bumped the mutation fence, so any earlier proof
/// is stale; stamping `Hydrated` anyway would produce the one state
/// `hydration_commit_decision` refuses to reconstruct over, and the
/// path would stay refused forever. Abandoning the attempt instead
/// drops the guard uncompleted, which reverts the row to `Placeholder`
/// -- so the next attempt runs normally and, once the observation
/// succeeds, the path ends `Hydrated` WITH a usable generation.
#[tokio::test]
async fn an_unobservable_write_leaves_the_path_retryable_not_stuck() {
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    sync_state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    let hash = yadorilink_replica_domain::ids::ChangeHash([7u8; 32]);
    sync_state
        .file_index_repository()
        .set_authoring_change_hash("group-1", "doc.txt", &hash)
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();

    // The attempt bumps the fence before its physical write, exactly as
    // `hydrate_inner` does, then fails to observe what it wrote.
    sync_state.dag_bump_mutation_fence("group-1", "doc.txt", "hydration_write").unwrap();
    {
        let _guard = crate::replica_coordinator::AccessHydration::armed_for_tests(
            sync_state.as_ref(),
            "group-1",
            "doc.txt",
            Some(hash),
            current_version_hash_for(&sync_state, "group-1", "doc.txt"),
            MaterializationState::Placeholder,
        );
        // never `complete()`d -- the observation failed
    }

    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Placeholder),
        "an attempt that could not prove its write must leave the row retryable, never \
         Hydrated-without-a-generation"
    );
    assert!(
        sync_state
            .sqlite()
            .dag_lookup_materialized_generation("group-1", "doc.txt")
            .unwrap()
            .is_none(),
        "no proof should have been published for a write that was never observed"
    );

    // The retry: a fresh attempt stamps `Hydrating`, bumps its own fence
    // before writing, and this time observes what it wrote -- so it
    // commits through the internal-mutator lane, the one a device that
    // performed its own write must use. That single transaction is what
    // publishes the proof and stamps the claim, so the two can never be
    // seeded apart here in an order no writer performs.
    let observed = tempfile::tempdir().unwrap();
    let observed_path = observed.path().join("doc.txt");
    std::fs::write(&observed_path, b"").unwrap();
    let identity =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&observed_path).unwrap();
    // A present object's proof has to carry the version the row names,
    // or it matches no desired resolution and closes nothing.
    let current_version_hash = current_version_hash_for(&sync_state, "group-1", "doc.txt");
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();
    let mutation_generation =
        sync_state.dag_bump_mutation_fence("group-1", "doc.txt", "hydration_write").unwrap();
    let committed = sync_state
        .materialization_state_repository()
        .commit_internal_materialized_state_if_fence_current(
            "group-1",
            "doc.txt",
            None,
            &ExactMaterializedState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::File,
                version: current_version_hash,
                identity: Box::new(Some(identity)),
            },
            mutation_generation,
            Some(ExpectedAuthoring {
                state: MaterializationState::Hydrating,
                authoring_change_hash: Some(&hash),
                expected_version: Some(&current_version_hash),
            }),
            &permit,
        )
        .unwrap();
    assert!(
        matches!(committed, InternalMaterializedCommit::Published(_)),
        "nothing moved this path's fence, so the retry's own commit must have landed"
    );

    assert!(
        sync_state
            .sqlite()
            .dag_lookup_materialized_generation("group-1", "doc.txt")
            .unwrap()
            .is_some(),
        "after a successful retry the claim must be backed by a usable generation"
    );
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "the same commit that published the proof is what stamps the claim"
    );
}

/// `AccessHydration`'s revert-on-drop must not clobber a
/// DIFFERENT hydration attempt's own legitimate `Hydrating` row for
/// the same path. `hydrate_inner` now holds `path_lock` for its whole
/// attempt, so two attempts for the SAME path can no longer be
/// mid-flight unlocked at once -- but `Drop` itself cannot await that
/// (or any) lock, so this binding is defense-in-depth against any
/// future caller of this guard that doesn't hold the lock for its
/// whole duration the way `hydrate_inner` does today. A state-only
/// CAS cannot tell "still my own in-flight attempt" apart from "a
/// different attempt that happens to also be `Hydrating` right
/// now" -- only binding to the authoring identity captured before
/// marking `Hydrating` closes that.
#[tokio::test]
async fn hydration_state_guard_does_not_clobber_a_differently_authored_hydrating_row() {
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    sync_state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    let old_hash = yadorilink_replica_domain::ids::ChangeHash([1u8; 32]);
    sync_state
        .file_index_repository()
        .set_authoring_change_hash("group-1", "doc.txt", &old_hash)
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();

    // This (stale) attempt's own guard, capturing the OLD identity --
    // as `hydrate_inner` does before marking the row `Hydrating`.
    let guard = crate::replica_coordinator::AccessHydration::armed_for_tests(
        sync_state.as_ref(),
        "group-1",
        "doc.txt",
        Some(old_hash),
        current_version_hash_for(&sync_state, "group-1", "doc.txt"),
        MaterializationState::Placeholder,
    );

    // A different, concurrent attempt supersedes the row with a
    // genuinely newer version and starts its OWN hydration --
    // landing back at `Hydrating`, but for a different identity.
    let new_hash = yadorilink_replica_domain::ids::ChangeHash([2u8; 32]);
    sync_state
        .file_index_repository()
        .set_authoring_change_hash("group-1", "doc.txt", &new_hash)
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();

    // The stale attempt's guard now drops (never `complete()`d) --
    // state alone matches (`Hydrating`), but the authoring identity
    // does not, so this must be a no-op.
    drop(guard);

    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrating),
        "a stale attempt's guard must not touch a newer version's own in-flight hydration \
         just because the state value happens to match"
    );
    assert_eq!(
        sync_state.file_index_repository().get_authoring_change_hash("group-1", "doc.txt").unwrap(),
        Some(new_hash),
        "the newer version's identity must be untouched"
    );
}

/// Two concurrent `hydrate_inner` calls for the SAME path and the
/// SAME version (same authoring hash) must not race destructively --
/// the counter-scenario to the authoring-bound guard alone: authoring identity distinguishes one FILE
/// VERSION from another, not one in-flight ATTEMPT from another, so
/// two attempts for the identical version are indistinguishable to
/// that binding. `hydrate_inner` now holds `path_lock` for its whole
/// duration specifically to close this: only one such attempt can be
/// in flight for a path at a time, so a slower attempt's own guard
/// can never drop while a faster, concurrent attempt for the same
/// version is still between `reconstruct_file` and its own final
/// commit. Both blocks are already locally present (seeded directly,
/// with provenance recorded) so this test needs no live peer and no
/// injected timing. `path_lock` fully serializes the two attempts,
/// so the second call only ever starts after the first has
/// committed; it re-marks the row `Hydrating` and redundantly
/// reconstructs rather than short-circuiting via `AlreadyComplete`
/// (there is no pre-lock fast path for an already-`Hydrated` row),
/// but both attempts still converge on the same correct end state.
/// Note: on the default single-threaded test
/// runtime, with both blocks resolving synchronously from local
/// state, this test cannot force the two attempts to interleave
/// inside the locked region -- it verifies the end state is correct
/// under strict serialization, not that a genuine interleaving is
/// handled safely. The race-closing argument rests on `path_lock`
/// being a real, shared, non-reentrant mutex (a structural
/// guarantee), not on this test empirically reproducing the race.
#[tokio::test]
async fn concurrent_hydrations_of_the_same_version_do_not_race() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let content = b"concurrent hydration content";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Placeholder, &permit)
        .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");

    let state_a = state.clone();
    let state_b = state.clone();
    let task_a = tokio::spawn(async move {
        hydrate_inner(&state_a, "group-1", "doc.txt", Some(&test_stall())).await
    });
    let task_b = tokio::spawn(async move {
        hydrate_inner(&state_b, "group-1", "doc.txt", Some(&test_stall())).await
    });

    let (result_a, result_b) = tokio::join!(task_a, task_b);

    assert!(result_a.unwrap().is_ok(), "concurrent attempt A must succeed");
    assert!(result_b.unwrap().is_ok(), "concurrent attempt B must succeed");
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "the row must end up genuinely Hydrated, not stuck at Placeholder despite correct \
         disk content"
    );
    assert_eq!(
        std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
        content,
        "disk content must be exactly what was hydrated"
    );
}

/// The same scenario as `concurrent_hydrations_of_the_same_
/// version_do_not_race` above, but through `hydrate_with_timeout` --
/// the real public entry point `shell_ipc.rs`'s `HydrateRequest`
/// handler actually calls, which now single-flights (see
/// `hydration_single_flight`) -- rather than `hydrate_inner` directly.
/// Proves the single-flight leader/follower wiring doesn't disturb
/// this race: two concurrent FETCH_DATA-driven
/// callers for the SAME path (a live scenario, e.g. two apps opening
/// the same file at once) must both still observe success and the
/// exact same end state, whichever of them becomes the leader.
#[tokio::test]
async fn concurrent_hydrate_with_timeout_calls_for_the_same_path_both_succeed() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let content = b"single-flight hydration content";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Placeholder, &permit)
        .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");

    let state_a = state.clone();
    let state_b = state.clone();
    let task_a = tokio::spawn(async move {
        hydrate_with_timeout(&state_a, "group-1", "doc.txt", HYDRATION_TIMEOUT).await
    });
    let task_b = tokio::spawn(async move {
        hydrate_with_timeout(&state_b, "group-1", "doc.txt", HYDRATION_TIMEOUT).await
    });

    let (result_a, result_b) = tokio::join!(task_a, task_b);

    assert!(result_a.unwrap().is_ok(), "concurrent caller A must succeed");
    assert!(result_b.unwrap().is_ok(), "concurrent caller B must succeed");
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
    );
    assert_eq!(std::fs::read(root_dir.path().join("doc.txt")).unwrap(), content);
}

/// The follower path specifically -- a caller that joins the
/// single-flight registry strictly AFTER the leader has already
/// started (not merely "concurrently spawned", which can't
/// deterministically prove who becomes the follower) must still
/// observe the leader's real result rather than starting (and
/// potentially failing) its own attempt.
#[tokio::test]
async fn a_late_joining_caller_observes_the_leaders_result_as_a_follower() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let content = b"late follower content";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Placeholder, &permit)
        .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");

    // Explicitly claim the leader role via the registry directly (not
    // `hydrate_with_timeout`, so this test controls exactly when the
    // late caller joins relative to it), matching how
    // `hydrate_with_timeout` itself would join.
    let leader = match state.hydrate_single_flight.join("group-1", "doc.txt") {
        crate::hydration_single_flight::Role::Leader(l) => l,
        crate::hydration_single_flight::Role::Follower(_) => {
            panic!("the first joiner in a fresh registry must be the leader")
        }
    };

    let state_follower = state.clone();
    let follower_task = tokio::spawn(async move {
        hydrate_with_timeout(&state_follower, "group-1", "doc.txt", HYDRATION_TIMEOUT).await
    });
    // Give the spawned follower task a chance to actually call `join`
    // and observe the still-registered leader before it completes.
    tokio::task::yield_now().await;

    let leader_result = hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await;
    leader.complete(leader_result.as_ref().map(|_| ()).map_err(|_| ()));

    let follower_result = follower_task.await.unwrap();

    assert!(leader_result.is_ok(), "the leader's own attempt must succeed");
    assert!(
        follower_result.is_ok(),
        "the follower must observe the leader's success, not fail independently: \
         {follower_result:?}"
    );
}

/// Counter-scenario: `hydrate` (the shell IPC
/// `HydrateRequest` handler's only entry point, per
/// `shell_ipc::handle_message`) is reachable for an arbitrary caller-
/// supplied path with no upstream check on whether that path is
/// already fully materialized -- a real client cannot be trusted to
/// only ever ask for a genuine `Placeholder`. Before this fast path,
/// `hydrate_inner` would still unconditionally mark an already-
/// `Hydrated` row `Hydrating` and reconstruct it from the *indexed*
/// blocks, silently overwriting any content an editor wrote to disk
/// after the row was last hydrated but before its own watcher event
/// reached the index. Returns `(state, sync_state, root_dir,
/// indexed_content)`.
async fn setup_legitimately_hydrated_doc(
) -> (Arc<DaemonState>, Arc<ReplicaCoordinator>, tempfile::TempDir, &'static [u8]) {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let indexed_content: &'static [u8] = b"indexed content from the last real hydration";
    let hash = Sha256::digest(indexed_content).to_vec();
    store.put(indexed_content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: indexed_content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: indexed_content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Placeholder, &permit)
        .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await.unwrap();
    assert_eq!(
        std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
        indexed_content,
        "setup's own real hydrate must have landed the indexed content first"
    );
    (state, sync_state, root_dir, indexed_content)
}

/// Pins the write contract a daemon-side on-demand hydration settles
/// under. This is an INTERNAL mutator: it bumps the mutation fence
/// itself before its own `reconstruct_file`, so everything it publishes
/// must go out under exactly that epoch.
///
/// Three distinct things are pinned here, and each one was separately
/// wrong before this path moved onto the internal-commit primitive:
///
/// 1. No versionless object generation. The proof has to name the
///    `VersionHash` it vouches for, because `resolved_path_state_hash`
///    encodes version PRESENCE -- a proof published with no version
///    matches no desired resolution at all, so it can never settle the
///    path and the convergence engine re-materializes it forever.
/// 2. No `Hydrated` without a usable proof. `dag_lookup_materialized_
///    generation` is fail-closed (a generation published under a
///    superseded fence reads as absent), so a `Some` here is the whole
///    invariant this branch exists to guarantee.
/// 3. No external-adoption epoch minted by an internal write. Adoption
///    (`adopt_local_capture_actual_state`) mints a FRESH epoch inside
///    its own transaction, which is correct only for a change this
///    device is discovering after the fact. Routing an internal mutator
///    through it means no concurrent mutator can ever make it lose, so
///    a racing write leaves a proof vouching for bytes that are no
///    longer on disk. Exactly one bump across the whole hydration is
///    what distinguishes the two, so this counts them.
#[tokio::test]
async fn a_daemon_hydration_publishes_a_versioned_proof_under_its_own_single_epoch() {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let content: &[u8] = b"content this hydration will have to vouch for";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Placeholder, &permit)
        .unwrap();

    // The version this hydration is about to materialize, read the same
    // way the production path reads it.
    let expected_version = yadorilink_replica_domain::session_state::CurrentVersionRecord::from(
        sync_state
            .sqlite()
            .get_current_version_record(
                &yadorilink_replica_domain::ids::FolderGroupId("group-1".into()),
                "doc.txt",
            )
            .unwrap()
            .expect("the row just upserted must be current"),
    )
    .to_file_version()
    .version_hash;

    // Reads the live fence without bumping it, so the delta below
    // counts only the bumps the hydration itself performs.
    let fence_before = sync_state.dag_snapshot_mutation_fence("group-1", "doc.txt").unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await.unwrap();

    assert_eq!(
        std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
        content,
        "the hydration must actually have put the indexed content on disk"
    );
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "a hydration that reconstructed and observed its own write must claim Hydrated"
    );

    let basis = sync_state
        .sqlite()
        .dag_lookup_materialized_generation("group-1", "doc.txt")
        .unwrap()
        .expect(
            "Hydrated must come with a usable actual-state generation in the same durable \
             commit -- this lookup is fail-closed, so None means the proof is absent or was \
             published under an epoch that has already been superseded",
        );
    assert_eq!(
        basis.version,
        Some(expected_version),
        "the proof must name the version it vouches for; a versionless object generation \
         matches no desired resolution and leaves the path re-materializing forever"
    );

    let fence_after = sync_state.dag_snapshot_mutation_fence("group-1", "doc.txt").unwrap();
    assert_eq!(
        fence_after,
        fence_before + 1,
        "an internal mutator bumps exactly once, before its own write, and publishes under \
         that epoch. A second bump means the proof was minted by external adoption, which no \
         concurrent mutator can make lose"
    );
}

#[tokio::test]
async fn hydrate_of_an_already_hydrated_path_is_a_no_op_and_never_touches_disk() {
    let (state, sync_state, root_dir, _indexed_content) = setup_legitimately_hydrated_doc().await;

    // An unnoticed local edit: disk now differs from the indexed
    // blocks, but nothing has reprocessed this path through the local
    // watcher yet. A stray `HydrateRequest` for this same path must
    // not touch it.
    let edited_content = b"an editor's unsaved-by-the-index-yet edit";
    std::fs::write(root_dir.path().join("doc.txt"), edited_content).unwrap();

    hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await.unwrap();

    assert_eq!(
        std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
        edited_content,
        "an already-Hydrated row must never be reconstructed from its indexed blocks"
    );
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "the row's state must be left exactly as it was"
    );
}

/// The specific failure mode a
/// bare `len() > 0`/`len() == indexed size` check cannot catch -- a
/// local edit that truncates the file to EXACTLY ZERO bytes before the
/// watcher journals it. Treating zero bytes as "not real content" and
/// reconstructing over it would silently destroy the truncation. The persisted-fingerprint
/// check must recognize the file was legitimately hydrated once and
/// has since been touched (regardless of its new size, including
/// zero) and refuse to touch it again.
#[tokio::test]
async fn hydrate_never_overwrites_a_local_edit_that_truncates_the_file_to_zero_bytes() {
    let (state, sync_state, root_dir, _indexed_content) = setup_legitimately_hydrated_doc().await;

    // The local edit: truncate to zero bytes, exactly as a `truncate`/
    // `ftruncate`/editor-clear-and-not-yet-saved sequence would leave
    // it -- WITHOUT updating the indexed version, simulating the
    // window before the local watcher/debounce pipeline has caught up.
    std::fs::write(root_dir.path().join("doc.txt"), b"").unwrap();

    hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await.unwrap();

    assert_eq!(
        std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
        b"",
        "a zero-byte local edit must never be silently overwritten with the stale indexed \
         content"
    );
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "the row's state must be left exactly as it was -- local capture picks this edit up \
         normally on its own next pass, exactly like any other local edit"
    );
}

/// A `Hydrated` row with no usable actual-state generation is REFUSED,
/// not reconstructed over.
///
/// This replaces a test that asserted the opposite. Under the retired
/// fingerprint mechanism, "Hydrated with no recorded fingerprint" meant
/// "this device never wrote these bytes", so falling through to a real
/// reconstruct was right. Under the generation invariant it means
/// something the device cannot distinguish from a legitimate external
/// edit -- `Hydrated` is a claim that a proof exists, and reconstructing
/// over content nothing vouches for would destroy exactly the local
/// change the old mechanism was trying to protect.
///
/// Producing this row is itself a defect (see the writer sites that
/// stamp `Hydrated` only alongside a published proof); what this pins
/// is that when one does exist, it fails closed and loudly rather than
/// silently overwriting.
#[tokio::test]
async fn hydrate_refuses_a_hydrated_row_with_no_usable_generation() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let indexed_content = b"indexed content from the last real hydration";
    let hash = Sha256::digest(indexed_content).to_vec();
    store.put(indexed_content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: indexed_content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: indexed_content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    // Directly marked Hydrated with NO reconstruct ever having run --
    // no fingerprint gets recorded this way, matching the real race
    // this simulates: the index believes this row is Hydrated, but
    // this device never actually, verifiably wrote the bytes itself.
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrated, &permit)
        .unwrap();
    // A genuinely empty leftover artifact, exactly like the confirmed
    // restart-mid-relay-sync race this shortcut was originally built
    // to fix.
    std::fs::write(root_dir.path().join("doc.txt"), b"").unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    let result = hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await;

    assert!(
        matches!(result, Err(SyncError::CorruptState(ref m)) if m.contains("no usable actual-state generation")),
        "a Hydrated row with no usable generation must be refused, not reconstructed over: \
         got {result:?}"
    );
    assert_eq!(
        std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
        b"",
        "the refusal must leave the on-disk bytes untouched -- overwriting them is what \
         this invariant exists to prevent"
    );
    let _ = indexed_content;
}

/// A symlink or directory record is never a `Placeholder` waiting on
/// `hydrate` -- it is always fully materialized the moment it's
/// adopted (`peer_session::materialize_symlink_at`). Before this kind
/// guard, `hydrate_inner` had no way to know a given path wasn't an
/// ordinary file, so it would call `reconstruct_file` with this
/// record's (always-empty, for a symlink) block list, replacing the
/// real on-disk symlink with an empty regular file.
#[tokio::test]
async fn hydrate_of_a_symlink_path_never_replaces_it_with_a_regular_file() {
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "link.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .file_index_repository()
        .set_record_kind(
            "group-1",
            "link.txt",
            yadorilink_replica_domain::file::RecordKind::Symlink,
            &permit,
        )
        .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("target.txt", root_dir.path().join("link.txt")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("target.txt", root_dir.path().join("link.txt")).unwrap();

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    hydrate_inner(&state, "group-1", "link.txt", Some(&test_stall())).await.unwrap();

    let out_path = root_dir.path().join("link.txt");
    assert!(
        std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
        "hydrate must never replace a symlink record's on-disk symlink"
    );
    assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
}

/// `verify_write_target_within_root`
/// is not a pure check -- it `create_dir_all`s the sync root and the
/// target's parent directory as a side effect. If `VerifiedRoot::
/// verify` ran AFTER that call instead of before, a root whose
/// mountpoint was unmounted and replaced by something else at the
/// same path would still get a brand-new directory created on it
/// (for a nested path whose parent doesn't exist yet) before the
/// identity mismatch was ever detected.
#[tokio::test]
async fn hydrate_creates_no_directories_under_a_root_whose_marker_no_longer_matches() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let content = b"nested placeholder content";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "sub/nested/doc.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "sub/nested/doc.txt",
            MaterializationState::Placeholder,
            &permit,
        )
        .unwrap();

    std::fs::remove_file(
        root_dir.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    )
    .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    let result = hydrate_inner(&state, "group-1", "sub/nested/doc.txt", Some(&test_stall())).await;

    assert!(
        result.is_err(),
        "hydration under a root whose marker no longer matches must be refused"
    );
    assert!(
        !root_dir.path().join("sub").exists(),
        "no directory must be created under a root that fails identity verification, even \
         for a nested path whose parent doesn't exist yet"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn hydrate_applies_the_recorded_unix_mode_after_reconstruct() {
    use std::os::unix::fs::PermissionsExt;

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let content = b"#!/bin/sh\necho hi\n";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "run.sh".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .file_index_repository()
        .set_unix_mode("group-1", "run.sh", Some(0o755), &permit)
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "run.sh", MaterializationState::Placeholder, &permit)
        .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    hydrate_inner(&state, "group-1", "run.sh", Some(&test_stall())).await.unwrap();

    let mode = std::fs::metadata(root_dir.path().join("run.sh")).unwrap().permissions().mode();
    assert_ne!(
        mode & 0o100,
        0,
        "hydration must apply the recorded exec bit, not just fetch the content"
    );
}

/// A `Placeholder` row whose placeholder this device really wrote: the
/// block is in the store, the sparse stand-in is on disk, and its
/// identity is recorded exactly as the materialization lane records it.
#[cfg(unix)]
async fn setup_real_placeholder_doc(
) -> (Arc<DaemonState>, Arc<ReplicaCoordinator>, tempfile::TempDir, &'static [u8]) {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();

    let indexed_content: &'static [u8] = b"the remote content this placeholder stands in for";
    let hash = Sha256::digest(indexed_content).to_vec();
    store.put(indexed_content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: indexed_content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: indexed_content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    let identity = yadorilink_local_storage::write_placeholder(
        &root_dir.path().join("doc.txt"),
        indexed_content.len() as u64,
        0,
    )
    .unwrap()
    .expect("a unix placeholder has an inode identity");
    let repo = sync_state.materialization_state_repository();
    repo.set_materialization_state(
        "group-1",
        "doc.txt",
        MaterializationState::Placeholder,
        &permit,
    )
    .unwrap();
    repo.record_placeholder_generation(
        "group-1",
        "doc.txt",
        identity,
        yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND,
        &permit,
    )
    .unwrap();

    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    (state, sync_state, root_dir, indexed_content)
}

/// The positive control for the two tests below: a placeholder nobody has
/// touched hydrates.
#[cfg(unix)]
#[tokio::test]
async fn an_untouched_placeholder_hydrates() {
    let (state, sync_state, root_dir, content) = setup_real_placeholder_doc().await;

    hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await.unwrap();

    assert_eq!(std::fs::read(root_dir.path().join("doc.txt")).unwrap(), content);
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
}

/// An edit written into a placeholder before a hydration attempt starts,
/// and not yet journalled by the watcher, is not overwritten.
///
/// The attempt has nothing on disk to take as its baseline but the edit
/// itself, so comparing disk against itself cannot protect it. What the
/// attempt can compare against is the placeholder this device wrote: the
/// identity it recorded, and the placeholder still being sparse. A file
/// that is no longer that placeholder is an uncaptured local edit, so the
/// attempt refuses and journals it for capture.
#[cfg(unix)]
#[tokio::test]
async fn an_edit_made_before_the_attempt_started_is_never_overwritten() {
    for rename_save in [false, true] {
        let (state, sync_state, root_dir, _content) = setup_real_placeholder_doc().await;
        let out_path = root_dir.path().join("doc.txt");
        let edit = b"a local edit the watcher has not journalled yet";
        if rename_save {
            let tmp = root_dir.path().join(".doc.txt.save");
            std::fs::write(&tmp, edit).unwrap();
            std::fs::rename(&tmp, &out_path).unwrap();
        } else {
            std::fs::write(&out_path, edit).unwrap();
        }

        let result = hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await;

        assert!(
            result.is_err(),
            "rename_save={rename_save}: hydration took a local edit as its baseline and \
             reported success: {result:?}"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            edit,
            "rename_save={rename_save}: hydration overwrote an edit made before it started"
        );
        assert_ne!(
            sync_state
                .materialization_state_repository()
                .get_materialization_state("group-1", "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "rename_save={rename_save}: the row claims Hydrated over a local edit"
        );
        assert!(
            sync_state.dirty_path_repository().is_path_dirty("group-1", "doc.txt").unwrap(),
            "rename_save={rename_save}: the refused edit must be journalled for local capture, \
             or nothing stops a later attempt that samples it as its baseline"
        );
    }
}

/// A crash after an attempt renamed the hydrated file into place and before
/// it committed leaves a `Placeholder` row over a file that is no longer the
/// placeholder -- but whose bytes are exactly the ones the row names. That is
/// not a local edit, and refusing it would refuse forever: the next attempt
/// settles it.
#[cfg(unix)]
#[tokio::test]
async fn a_crash_between_the_rename_and_the_commit_settles_on_the_next_attempt() {
    let (state, sync_state, root_dir, content) = setup_real_placeholder_doc().await;
    let out_path = root_dir.path().join("doc.txt");
    // What the interrupted attempt left: the assembled file renamed over
    // the placeholder, a new inode with real allocated bytes.
    let tmp = root_dir.path().join(".doc.txt.hydrating");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, &out_path).unwrap();

    hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await.unwrap();

    assert_eq!(std::fs::read(&out_path).unwrap(), content);
    assert_eq!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "the interrupted hydration must settle, not refuse forever"
    );
    assert!(
        sync_state
            .sqlite()
            .dag_lookup_materialized_generation("group-1", "doc.txt")
            .unwrap()
            .is_some(),
        "the settled claim must be backed by a usable proof"
    );
    assert!(
        !sync_state.dirty_path_repository().is_path_dirty("group-1", "doc.txt").unwrap(),
        "bytes the row already names are not a local edit"
    );
}

/// A placeholder the user deleted before a hydration attempt started, and
/// whose removal the watcher has not journalled yet, is not recreated.
///
/// This device recorded writing a placeholder there, so an empty path is
/// a local delete, not a path that never had content: hydrating would put
/// the file back, and the watcher's late remove event would then find it
/// present and never tombstone it.
#[cfg(unix)]
#[tokio::test]
async fn a_placeholder_deleted_before_the_attempt_started_is_not_recreated() {
    let (state, sync_state, root_dir, _content) = setup_real_placeholder_doc().await;
    let out_path = root_dir.path().join("doc.txt");
    std::fs::remove_file(&out_path).unwrap();

    let result = hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await;

    assert!(result.is_err(), "hydration recreated a deleted placeholder: {result:?}");
    assert!(
        std::fs::symlink_metadata(&out_path).is_err(),
        "hydration undid a local delete by writing the file back"
    );
    assert_ne!(
        sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
    );
    assert!(
        sync_state.dirty_path_repository().is_path_dirty("group-1", "doc.txt").unwrap(),
        "the refused delete must be journalled for local capture"
    );
}

/// The crash-recovery arm accepts a file whose bytes are the ones the row
/// names only when its mode is too: an interrupted attempt's leftover that
/// the user has since `chmod`ed carries a local change, and the attempt's
/// own metadata apply would revert it. The control, a leftover whose mode
/// still matches the row, settles as before.
#[cfg(unix)]
#[tokio::test]
async fn a_mode_change_on_a_crash_leftover_is_not_reverted() {
    use std::os::unix::fs::PermissionsExt as _;
    for chmodded in [false, true] {
        let (state, sync_state, root_dir, content) = setup_real_placeholder_doc().await;
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        sync_state
            .file_index_repository()
            .set_unix_mode("group-1", "doc.txt", Some(0o644), &permit)
            .unwrap();
        let out_path = root_dir.path().join("doc.txt");
        let tmp = root_dir.path().join(".doc.txt.hydrating");
        std::fs::write(&tmp, content).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::rename(&tmp, &out_path).unwrap();
        if chmodded {
            std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let result = hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await;

        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        let hydrated = sync_state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap()
            == Some(MaterializationState::Hydrated);
        let dirty = sync_state.dirty_path_repository().is_path_dirty("group-1", "doc.txt").unwrap();
        if chmodded {
            assert!(result.is_err(), "hydration settled over a local mode change: {result:?}");
            assert_eq!(mode, 0o755, "hydration reverted a local chmod on a crash leftover");
            assert!(!hydrated);
            assert!(dirty, "the refused mode change must be journalled for local capture");
        } else {
            result.unwrap();
            assert_eq!(mode, 0o644);
            assert!(hydrated);
            assert!(!dirty);
        }
    }
}

fn block_for_data(data: &[u8]) -> BlockInfo {
    BlockInfo { hash: Sha256::digest(data).to_vec(), offset: 0, size: data.len() as u32 }
}

#[test]
fn block_data_matches_requires_expected_hash_and_size() {
    let data = b"valid block bytes";
    let block = block_for_data(data);
    assert!(block_data_matches(&block, data));
    assert!(!block_data_matches(&block, b"different bytes"));

    let wrong_size = BlockInfo { size: block.size + 1, ..block };
    assert!(!block_data_matches(&wrong_size, data));
}

/// Blocks split across two peers each holding a disjoint subset
/// resolve correctly — each peer only ever pops blocks it hasn't
/// tried yet, and different peers can pop
/// different blocks from the same queue without stepping on each other.
#[test]
fn disjoint_subsets_resolve_independently() {
    let mut queue = BlockWorkQueue::new(vec![block(1), block(2)]);
    let first = queue.pop_for("peer-a").unwrap();
    let second = queue.pop_for("peer-b").unwrap();
    assert_ne!(first.hash, second.hash, "two peers should not pop the same block concurrently");
    assert!(queue.pop_for("peer-a").is_none());
    assert!(queue.pop_for("peer-b").is_none());
}

/// A block not-found on one peer is requeued and successfully served
/// by a different candidate that hasn't tried it yet.
#[test]
fn not_found_block_is_reassigned_to_a_different_peer() {
    let mut queue = BlockWorkQueue::new(vec![block(1)]);
    let b = queue.pop_for("peer-a").unwrap();
    queue.mark_not_found(b, "peer-a", &["peer-a".into(), "peer-b".into()]);

    // peer-a already tried it — must not get it again.
    assert!(queue.pop_for("peer-a").is_none());
    // peer-b hasn't tried it yet — must be offered it.
    let retried = queue.pop_for("peer-b").unwrap();
    assert_eq!(retried.hash, block(1).hash);
}

/// A block a peer merely timed out on (as opposed to explicitly
/// reported not-found) must not be immediately re-offered to that same
/// peer -- see `timeout_backoff`'s doc comment for why an unthrottled
/// immediate retry can amplify the very congestion that caused the
/// timeout. A different peer is unaffected by another peer's cooldown.
#[test]
fn timed_out_block_cools_down_before_the_same_peer_can_retry_it() {
    let mut queue = BlockWorkQueue::new(vec![block(1)]);
    let b = queue.pop_for("peer-a").unwrap();
    queue.mark_timed_out(b, "peer-a");

    assert!(
        queue.pop_for("peer-a").is_none(),
        "peer-a just timed out on this block and must cool down before retrying it"
    );
    let retried = queue.pop_for("peer-b").unwrap();
    assert_eq!(
        retried.hash,
        block(1).hash,
        "a different peer's own cooldown is independent and must not be held back"
    );
}

/// `has_pending_backoff` must report a block cooling down after a
/// timeout so a worker whose own `pop_for` just returned `None` knows
/// to keep polling rather than conclude the queue is genuinely empty
/// (see `has_pending_backoff`'s own doc comment).
#[test]
fn has_pending_backoff_reflects_a_block_cooling_down_after_a_timeout() {
    let mut queue = BlockWorkQueue::new(vec![block(1)]);
    assert!(!queue.has_pending_backoff(), "nothing has timed out yet");

    let b = queue.pop_for("peer-a").unwrap();
    queue.mark_timed_out(b, "peer-a");
    assert!(queue.has_pending_backoff(), "peer-a's block is now cooling down");
}

/// A block missing from every candidate is correctly reported as
/// still-missing (dropped from the queue) rather than retried forever.
#[test]
fn block_missing_from_every_candidate_is_dropped_not_retried_forever() {
    let mut queue = BlockWorkQueue::new(vec![block(1)]);
    let candidates = vec!["peer-a".to_string(), "peer-b".to_string()];

    let b = queue.pop_for("peer-a").unwrap();
    queue.mark_not_found(b, "peer-a", &candidates);
    let b = queue.pop_for("peer-b").unwrap();
    queue.mark_not_found(b, "peer-b", &candidates);

    assert!(queue.pop_for("peer-a").is_none());
    assert!(queue.pop_for("peer-b").is_none());
    assert_eq!(queue.remaining(), vec![block(1)], "exhausted block must surface as still-missing");
}

/// An empty missing-block list is a no-op — `fetch_blocks_from_sessions`
/// itself short-circuits before ever touching the queue, but the queue
/// type must also behave sanely if constructed empty.
#[test]
fn empty_queue_has_nothing_to_pop() {
    let mut queue = BlockWorkQueue::new(vec![]);
    assert!(queue.pop_for("peer-a").is_none());
    assert!(queue.remaining().is_empty());
}

/// Worker-starvation race: a block checked out via
/// `pop_for` but not yet resolved must be reflected as `outstanding`,
/// even though the queue itself is momentarily empty — this is exactly
/// what tells a `fetch_blocks_from_sessions` worker with nothing left
/// to pop that giving up right now would be premature, since the
/// checked-out block could still turn back into queued work.
#[test]
fn has_outstanding_reflects_a_block_still_checked_out() {
    let mut queue = BlockWorkQueue::new(vec![block(1)]);
    assert!(!queue.has_outstanding(), "nothing checked out yet");

    let b = queue.pop_for("peer-a").unwrap();
    assert!(queue.has_outstanding(), "peer-a is holding the only block");
    assert!(queue.pop_for("peer-b").is_none(), "queue is empty while peer-a still holds the block");

    queue.mark_not_found(b, "peer-a", &["peer-a".into(), "peer-b".into()]);
    assert!(!queue.has_outstanding(), "resolved (as not-found) — no longer outstanding");
    assert!(
        queue.pop_for("peer-b").is_some(),
        "requeued by mark_not_found and now available to a different peer"
    );
}

/// The success path (`resolve_fetched`) must release `outstanding` just
/// like the not-found path does — it's the only other way a checked-out
/// block gets resolved, and forgetting to call it would leave
/// `has_outstanding` permanently (and wrongly) true, stalling every
/// other worker in an endless idle-poll once the real work is done.
#[test]
fn resolve_fetched_clears_outstanding_on_success() {
    let mut queue = BlockWorkQueue::new(vec![block(1)]);
    let _b = queue.pop_for("peer-a").unwrap();
    assert!(queue.has_outstanding());

    queue.resolve_fetched();
    assert!(!queue.has_outstanding());
}

/// Without `PoppedBlock`,
/// `remaining()` (`queue` + `exhausted`) would have no way to account for a
/// block popped via `pop_for` and never resolved -- e.g. a worker
/// task panicking somewhere in its own loop body between the pop and
/// whichever of `resolve_fetched`/`mark_not_found`/`mark_timed_out`
/// it was heading toward. That block would vanish from every
/// tracking set at once: not `queue`, not `exhausted`, `outstanding`
/// never decremented -- and `fetch_blocks_from_sessions` resolves a
/// block (and records this group's provenance for it) only via the
/// success arm that runs immediately after its bytes are durably
/// written, so a vanished block must never silently read back as
/// resolved. `PoppedBlock::drop`, simulated directly here without
/// needing a real panic, must requeue instead.
#[test]
fn a_popped_block_dropped_without_being_resolved_is_requeued_not_lost() {
    let work = Arc::new(StdMutex::new(BlockWorkQueue::new(vec![block(1)])));
    let (popped, _still_pending) = PoppedBlock::pop_for(&work, "peer-a");
    let guard = popped.expect("the only block is eligible for peer-a");
    assert_eq!(work.lock().unwrap().outstanding, 1, "pop_for must mark the block outstanding");

    drop(guard); // simulates the owning worker task panicking here

    let q = work.lock().unwrap();
    assert_eq!(q.outstanding, 0, "an unresolved drop must release outstanding");
    assert_eq!(q.queue.len(), 1, "the block must be requeued, not lost");
    drop(q);

    // Requeued with no `tried_by` penalty against peer-a and no
    // cooldown backoff either -- a worker panic is not evidence
    // about the peer, so the exact same peer must be immediately
    // eligible to retry it.
    let (popped_again, _) = PoppedBlock::pop_for(&work, "peer-a");
    assert!(
        popped_again.is_some(),
        "the requeued block must still be immediately eligible for the same peer"
    );
}

#[tokio::test]
async fn fetch_blocks_from_sessions_is_a_no_op_for_empty_missing_list() {
    let result = fetch_blocks_from_sessions(
        "group-1",
        "file.bin",
        vec![],
        &[],
        Arc::new(
            yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().path())
                .unwrap(),
        ),
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap()),
        crate::transfer_progress::TransferProgressTracker::new(),
        crate::recent_errors::RecentErrorLog::new(),
        None,
    )
    .await;
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn fetch_blocks_from_sessions_returns_missing_blocks_when_no_candidates() {
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().path())
            .unwrap(),
    );
    let missing = vec![block(1), block(2)];
    let result = fetch_blocks_from_sessions(
        "group-1",
        "file.bin",
        missing.clone(),
        &[],
        store,
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap()),
        crate::transfer_progress::TransferProgressTracker::new(),
        crate::recent_errors::RecentErrorLog::new(),
        None,
    )
    .await;
    assert_eq!(result.unwrap(), missing, "with no candidate sessions, nothing can be fetched");
}

// --- disk-space preflight tests ---

const GROUP: &str = "group-1";
const PATH: &str = "big.bin";

/// The returned `TempDir` backs the *block store*, kept alive for the
/// caller's whole test — never used as a link root itself (each test
/// creates its own separate `tempfile::tempdir` for that, so a
/// "leaves nothing on disk under the link root" assertion isn't
/// confused by the block store's own directory tree living alongside it).
fn test_state() -> (Arc<DaemonState>, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-under-test".to_string(), sync_state, store);
    (state, store_dir)
}

/// Registers a link at `root` and indexes a hydrated file record for it.
fn seed_link(
    state: &DaemonState,
    root: &std::path::Path,
    on_demand: bool,
    size: u64,
) -> yadorilink_replica_domain::file::FileRecord {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    // `evict_file` now verifies the root's adopted identity before
    // touching it -- without this, eviction fails closed on every
    // caller of this fixture, silently (callers here use `let _ =
    // preflight_disk_pressure(...)`), leaving the file materialized
    // and masking the actual eviction-path assertions this fixture
    // exists to exercise.
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root,
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    if on_demand {
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(
                &local_path,
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            )
            .unwrap();
    }
    let record = yadorilink_replica_domain::file::FileRecord {
        path: PATH.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![block_for_data(&vec![0u8; size as usize])],
        deleted: false,
    };
    // Record the seeded version as originating on a peer ("device-seed",
    // matching the version-vector author above), not this device. On-demand
    // cache reclamation only confirms custody for peer-origin content, so
    // eviction-path tests need a real peer origin here.
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &record, "device-seed", &permit)
        .unwrap();
    record
}

#[tokio::test]
async fn hydration_commit_rejects_a_disk_edit_after_its_initial_snapshot() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let record = seed_link(&state, root.path(), true, 1000);
    let out_path = root.path().join(PATH);
    let initial_identity = disk_identity(&out_path).unwrap();

    std::fs::write(&out_path, b"local edit while hydration fetched blocks").unwrap();

    assert!(
        hydration_commit_decision(
            &state,
            GROUP,
            PATH,
            &record,
            root.path(),
            &out_path,
            initial_identity,
        )
        .unwrap()
            == HydrationCommitDecision::Stale,
        "a changed disk identity must prevent stale hydration from overwriting local bytes"
    );
}

#[tokio::test]
async fn hydration_commit_rejects_a_journaled_local_edit() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let record = seed_link(&state, root.path(), true, 1000);
    let out_path = root.path().join(PATH);
    let initial_identity = disk_identity(&out_path).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .dirty_path_repository()
        .record_dirty_path(GROUP, PATH, "created_or_modified", 1, &permit)
        .unwrap();

    assert!(
        hydration_commit_decision(
            &state,
            GROUP,
            PATH,
            &record,
            root.path(),
            &out_path,
            initial_identity,
        )
        .unwrap()
            == HydrationCommitDecision::Stale,
        "a dirty-journal entry must prevent stale hydration commit"
    );
}

/// The gap the old `(size, mtime)`-only `DiskIdentity` could not see: a
/// same-size overwrite whose mtime is restored exactly. Only `ctime`
/// can still distinguish it (see `fs_identity::disk_race_fingerprint`'s
/// own doc comment) -- proves `hydration_commit_decision` now goes
/// through that stronger fingerprint rather than the weaker local pair
/// it used to compute. Skips gracefully, like
/// `peer_session.rs`'s own `disk_race_fingerprint` tests, if this
/// filesystem's ctime granularity happens not to distinguish a
/// same-tick write-restore-observe sequence.
#[cfg(unix)]
fn raw_ctime(path: &std::path::Path) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.ctime(), meta.ctime_nsec())
}

#[cfg(unix)]
#[tokio::test]
async fn hydration_commit_rejects_a_same_size_same_mtime_edit_ctime_permitting() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let record = seed_link(&state, root.path(), true, 4);
    let out_path = root.path().join(PATH);

    std::fs::write(&out_path, b"AAAA").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, PATH, MaterializationState::Hydrating, &permit)
        .unwrap();
    let initial_identity = disk_identity(&out_path).unwrap();
    let original_mtime = std::fs::symlink_metadata(&out_path).unwrap().modified().unwrap();
    let ctime_before = raw_ctime(&out_path);

    std::fs::write(&out_path, b"BBBB").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&out_path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
        .unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&out_path).unwrap().modified().unwrap(),
        original_mtime,
        "precondition: the mtime was restored exactly, so only ctime can betray the write"
    );
    // Independent of `disk_identity`/`disk_race_fingerprint` (the
    // function under test) on purpose: reads raw `ctime` off metadata
    // directly, so this skip-if-coarse check stays meaningful even if
    // `disk_identity` itself were ever weakened back to a (size, mtime)
    // pair -- comparing two `disk_identity()` calls here for the skip
    // condition would make it tautological with the assertion below and
    // silently stop testing anything the moment the fix regressed.
    if raw_ctime(&out_path) == ctime_before {
        eprintln!(
            "skipping: this filesystem's ctime granularity could not distinguish a \
             same-tick write-restore-observe sequence"
        );
        return;
    }
    assert_eq!(
        hydration_commit_decision(
            &state,
            GROUP,
            PATH,
            &record,
            root.path(),
            &out_path,
            initial_identity,
        )
        .unwrap(),
        HydrationCommitDecision::Stale,
        "a same-size, same-mtime local edit must still be caught via ctime and must prevent \
         a stale hydration commit from overwriting it"
    );
}

/// `hydrate_inner` captures the group's root once at hydration start and
/// reuses it for the whole (possibly multi-second) block-fetch window.
/// If the group is unlinked and relinked to a different root during
/// that window, the commit must refuse rather than write to the now
/// no-longer-linked root `out_path` was built from --
/// `local_root_for_group` re-reads the live link table fresh on every
/// call (see its own doc comment), so re-resolving and comparing here
/// is enough to catch it.
#[tokio::test]
async fn hydration_commit_rejects_after_the_group_is_relinked_elsewhere() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let record = seed_link(&state, root.path(), true, 1000);
    let out_path = root.path().join(PATH);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, PATH, MaterializationState::Hydrating, &permit)
        .unwrap();
    let initial_identity = disk_identity(&out_path).unwrap();

    state
        .replica_coordinator
        .link_repository()
        .remove_link(&root.path().to_string_lossy())
        .unwrap();
    let new_root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&new_root.path().to_string_lossy(), GROUP)
        .unwrap();

    assert_eq!(
        hydration_commit_decision(
            &state,
            GROUP,
            PATH,
            &record,
            root.path(),
            &out_path,
            initial_identity,
        )
        .unwrap(),
        HydrationCommitDecision::Stale,
        "a group relinked to a different root during the fetch must not let hydration \
         commit to the now-stale root"
    );
}

/// a preflight that would breach headroom fails with
/// `DiskPressure` and marks the link Degraded — forced deterministically
/// via a headroom override far larger than any real disk's free space
/// (this crate's tests must not depend on the host machine's actual
/// free space; confirmed a real concern elsewhere in this change).
#[tokio::test]
async fn preflight_disk_pressure_rejects_and_marks_degraded_when_it_would_breach() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    seed_link(&state, root.path(), false, 1000);

    let err = preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(u64::MAX / 2))
        .unwrap_err();
    assert!(matches!(err, SyncError::DiskPressure { .. }));
    assert!(state.is_link_degraded(&root.path().to_string_lossy()));
}

/// The converse: a write comfortably under headroom (a zero-byte
/// override) is allowed and never marks the link degraded.
#[tokio::test]
async fn preflight_disk_pressure_allows_a_write_under_headroom() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    seed_link(&state, root.path(), false, 1000);

    preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(0)).unwrap();
    assert!(!state.is_link_degraded(&root.path().to_string_lossy()));
}

/// Under disk pressure, an `OnDemand` link's eviction
/// sweep runs *before* the preflight fails — evicting an
/// already-hydrated, unpinned file back to a placeholder. Doesn't
/// assert the overall preflight then succeeds (that depends on freeing
/// enough *real* bytes to satisfy an intentionally enormous forced
/// headroom, not practical to stage in a test); asserts the sweep
/// itself ran, which is the behavior this actually adds.
#[tokio::test]
async fn preflight_disk_pressure_runs_eviction_sweep_for_on_demand_link_first() {
    let _pipeline_connected =
        yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let record = seed_link(&state, root.path(), true, 1000);
    state.install_test_root_commit_authority(GROUP);
    let block_hash = state.block_store.put(&vec![0u8; 1000]).unwrap();
    // Materialize it as "hydrated" on disk and record an access time so
    // it's a real eviction candidate (least-recently-used).
    std::fs::write(root.path().join(PATH), vec![0u8; 1000]).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated, &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .touch_last_accessed(GROUP, PATH, 100)
        .unwrap();
    // On a Windows build, `evict_to_placeholder`'s Windows arm requires
    // a recorded CfAPI placeholder identity for this row (see that
    // function's own doc comment) -- a real precondition this test must
    // seed, same as `dst_eviction_crash_recovery.rs` does, since this
    // row was indexed directly rather than through a real create/hydrate
    // lifecycle. Harmless on non-Windows: `evict_to_placeholder`'s
    // non-Windows arm never reads it.
    state
        .replica_coordinator
        .materialization_state_repository()
        .record_placeholder_generation(
            GROUP,
            PATH,
            yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 1 },
            yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            &permit,
        )
        .unwrap();
    // Bypasses the real `cfapi-host.exe` pipe round trip on a Windows
    // build -- this test asserts on the custody/lease gate, not on the
    // native dehydrate mechanism, and no live CfAPI provider process
    // runs in this unit test. No-op on non-Windows. See
    // `set_test_windows_dehydrate_confirmed_for_path`'s own doc comment.
    crate::replica_coordinator::set_test_windows_dehydrate_confirmed_for_path(
        &root.path().join(PATH),
        true,
    );
    // An instantaneous peer confirmation is deliberately insufficient for
    // physical CAS deletion until durable remote custody leases exist.
    state.set_custody_confirmer(std::sync::Arc::new(
        |_: &str, _: &str, _: &yadorilink_replica_domain::ids::VersionHash, _: &[VersionBlock]| {
            true
        },
    ));

    let _ =
        preflight_disk_pressure(&state, GROUP, PATH, root.path(), record.size, Some(u64::MAX / 2));

    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Placeholder),
        "the disk-pressure-triggered eviction sweep should have evicted the only candidate"
    );
    assert!(
        state.block_store.exists(&block_hash).unwrap(),
        "without a durable remote custody lease, placeholdering must retain the CAS block"
    );
}

/// a pinned file is never evicted by the disk-pressure sweep,
/// even when it's the only OnDemand content on a pressured volume.
#[tokio::test]
async fn preflight_disk_pressure_never_evicts_a_pinned_file() {
    // Otherwise the on-demand-pipeline gate alone would make this
    // assertion pass vacuously (nothing evicted because eviction is
    // refused outright, not because pinning was honored) -- see
    // `preflight_disk_pressure`'s own doc comment for the gate this
    // enables past.
    let _pipeline_connected =
        yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let record = seed_link(&state, root.path(), true, 1000);
    state.install_test_root_commit_authority(GROUP);
    std::fs::write(root.path().join(PATH), vec![0u8; 1000]).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated, &permit)
        .unwrap();
    state.replica_coordinator.file_index_repository().set_pinned(GROUP, PATH, true).unwrap();

    let _ =
        preflight_disk_pressure(&state, GROUP, PATH, root.path(), record.size, Some(u64::MAX / 2));

    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "a pinned file must never be evicted by the disk-pressure trigger"
    );
}

/// A `DiskPressure` rejection leaves no partial temp file
/// under the link root — the preflight runs (and fails) before
/// `reconstruct_file`'s temp-path-then-rename write ever begins.
#[tokio::test]
async fn preflight_disk_pressure_rejection_leaves_no_partial_temp_file() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    seed_link(&state, root.path(), false, 1000);

    let _ = preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(u64::MAX / 2));

    // The root-identity marker `seed_link`'s adoption wrote is
    // legitimate infrastructure, not a partial materialization
    // artefact -- excluded from sync and never something a preflight
    // rejection is responsible for cleaning up.
    let entries: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .filter(|entry| {
            entry.as_ref().is_ok_and(|e| {
                !yadorilink_root_authority::root_identity::is_root_marker_relative_path(
                    e.file_name(),
                )
            })
        })
        .collect();
    assert!(
        entries.is_empty(),
        "a rejected preflight must leave nothing on disk under the link root, found {entries:?}"
    );
}

/// disk pressure on one file's preflight doesn't affect a
/// second, independent file on an unrelated (unpressured) volume —
/// modeled here as two calls with different headroom overrides against
/// two different roots, since `preflight_disk_pressure` is inherently
/// scoped to the `root` it's given.
#[tokio::test]
async fn disk_pressure_on_one_link_does_not_affect_another() {
    let (state, _store_dir) = test_state();
    let root_a = tempfile::tempdir().unwrap();
    seed_link(&state, root_a.path(), false, 1000);
    let root_b = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root_b.path().to_string_lossy(), "group-2")
        .unwrap();
    let record_b = yadorilink_replica_domain::file::FileRecord {
        path: "other.bin".to_string(),
        size: 500,
        mtime_unix_nanos: 0,
        blocks: vec![block_for_data(&[1u8; 500])],
        deleted: false,
    };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file("group-2", &record_b, &permit)
        .unwrap();

    let err_a =
        preflight_disk_pressure(&state, GROUP, PATH, root_a.path(), 1000, Some(u64::MAX / 2))
            .unwrap_err();
    assert!(matches!(err_a, SyncError::DiskPressure { .. }));
    assert!(state.is_link_degraded(&root_a.path().to_string_lossy()));

    // The second link's volume was never checked, let alone marked —
    // a completely independent `preflight_disk_pressure` call for it
    // (0 headroom required) still succeeds.
    preflight_disk_pressure(&state, "group-2", "other.bin", root_b.path(), 500, Some(0)).unwrap();
    assert!(!state.is_link_degraded(&root_b.path().to_string_lossy()));
}

// --- restore engine ---

/// Writes `data`'s block into `state`'s block store, records it as
/// obtained through `group_id` (mirroring what `LocalChangeProcessor`
/// does for a real local edit — see `record_group_block_provenance`'s
/// doc comment), and returns the `BlockInfo` describing it — the
/// restore tests' equivalent of `seed_link`, but for a version whose
/// content actually needs to be present (or deliberately absent) in the
/// block store, not just referenced by an index row the way `seed_link`'s
/// single-block records are.
/// The version the row itself derives, the one canonical way -- what
/// every guard and reader in this area recomputes.
fn current_version_hash(
    state: &DaemonState,
    path: &str,
) -> yadorilink_replica_domain::ids::VersionHash {
    let snapshot = state
        .replica_coordinator
        .sqlite()
        .get_current_version_record(
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            path,
        )
        .unwrap()
        .expect("the row under test");
    yadorilink_replica_domain::session_state::CurrentVersionRecord::from(snapshot)
        .to_file_version()
        .version_hash
}

fn put_block(state: &DaemonState, group_id: &str, data: &[u8]) -> BlockInfo {
    let hash = state.block_store.put(data).unwrap();
    let hash_bytes = hex::decode(&hash).unwrap();
    state
        .replica_coordinator
        .change_history_repository()
        .record_group_block_provenance(group_id, std::slice::from_ref(&hash_bytes))
        .unwrap();
    BlockInfo { hash: hash_bytes, offset: 0, size: data.len() as u32 }
}

fn record_with_blocks(
    path: &str,
    blocks: Vec<BlockInfo>,
    size: u64,
) -> yadorilink_replica_domain::file::FileRecord {
    yadorilink_replica_domain::file::FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks,
        deleted: false,
    }
}

/// restoring a version whose blocks are all still present
/// locally succeeds without needing any peer, writes the restored
/// content to disk, and — the load-bearing assertion —
/// creates a **new** version rather than mutating the one being
/// restored: the original version-1 row is unchanged and still
/// queryable, and the restored content becomes version 3 (not a
/// renumbered/rewritten version 1).
#[tokio::test]
async fn restore_to_version_of_a_fully_local_version_succeeds_and_creates_a_new_version() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits route through `replica_coordinator`
    // (`LocalChangeProcessor` is built from it, not `sync_state`)
    // -- mirror the override there too, or this test's real
    // provider (wired by `DaemonState::new`/`build`) fires instead and
    // requires actual group-policy setup this fixture doesn't have.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    #[cfg(windows)]
    state
        .replica_coordinator
        .link_repository()
        .set_windows_symlink_opt_in(&local_path, true)
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1_block = put_block(&state, GROUP, b"version one content");
    let v1 = record_with_blocks(PATH, vec![v1_block.clone()], 19);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();

    let v2_block = put_block(&state, GROUP, b"version two content!!");
    let v2 = record_with_blocks(PATH, vec![v2_block], 21);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();

    // Restore back to version 1's content.
    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

    assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"version one content");

    let versions = state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap();
    assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite an old one");
    assert_eq!(versions[0].version_seq, 3, "the restored content is the newest version");
    assert_eq!(versions[0].blocks, vec![v1_block]);
    assert_eq!(versions[0].state, yadorilink_replica_domain::session_state::VersionState::Current);
    let author = state
        .replica_coordinator
        .file_index_repository()
        .get_authoring_change_hash(GROUP, PATH)
        .unwrap();
    assert!(author.is_some(), "restore must publish its own DAG author identity");
    assert!(state
        .replica_coordinator
        .change_history_repository()
        .dag_has_change_or_pruned(GROUP, &author.unwrap())
        .unwrap());
    // Version 1 itself is completely untouched.
    let original_v1 = versions.iter().find(|v| v.version_seq == 1).unwrap();
    assert_eq!(original_v1.size, 19);
    // `commit_restore_operation`'s explicit `Hydrated` stamp is what
    // earns this -- the restored content genuinely matches disk, but
    // nothing marks that automatically; the schema's own default is
    // `Placeholder`.
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
}

/// `restore_to_version_inner`'s physical write (`reconstruct_file`)
/// must bump the mutation fence, like every sibling physical mutator (`hydrate_inner`'s equivalent
/// write, `materialization_repair.rs`'s reconstruct path) -- otherwise an
/// existing `path_materialized_generations` proof for this path would
/// survive the restore's write completely untouched, so a concurrent,
/// unrelated completion for the same path could read that proof as
/// still "usable" right up to the instant the restore silently changed
/// the bytes it describes. This proves the fence is genuinely bumped by the restore write itself, not merely that
/// restore succeeds.
#[tokio::test]
async fn restore_to_version_bumps_the_mutation_fence_before_its_physical_write() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    #[cfg(windows)]
    state
        .replica_coordinator
        .link_repository()
        .set_windows_symlink_opt_in(&local_path, true)
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1_block = put_block(&state, GROUP, b"version one content");
    let v1 = record_with_blocks(PATH, vec![v1_block.clone()], 19);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();

    let v2_block = put_block(&state, GROUP, b"version two content!!");
    let v2 = record_with_blocks(PATH, vec![v2_block], 21);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();

    let fence_before = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, PATH).unwrap();

    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

    let fence_after = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, PATH).unwrap();
    assert!(
        fence_after > fence_before,
        "restore's physical write must bump the mutation fence like every other physical \
         mutator (before: {fence_before}, after: {fence_after})"
    );
}

/// `pin` was tightened to require the standing proof to name the row's
/// current version, but `pin` delegates to `hydrate` whenever that is
/// not the case -- and `hydrate`'s own fast path asked only whether a
/// proof existed. So the tightening bought nothing on its own: pin
/// called hydrate, hydrate said "already hydrated" on a proof about a
/// version the path had moved off, and pin reported success.
///
/// A metadata-only version bump is the ordinary way to reach this. It
/// moves the version the row derives while leaving every byte, and the
/// proof beside them, exactly right -- so the answer is to re-prove
/// for the version the row now names, not to refetch content that is
/// already correct.
#[tokio::test]
async fn hydrate_reproves_a_row_whose_proof_names_a_superseded_version() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let content = b"already exactly right on disk";
    let block = put_block(&state, GROUP, content);
    let record = record_with_blocks(PATH, vec![block], content.len() as u64);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &record, "device-a", &permit)
        .unwrap();
    std::fs::write(root.path().join(PATH), content).unwrap();

    // A prior cycle's proof, for the version the row named then.
    let stale_version = crate::test_support::seed_prior_cycle_proof(
        &state.replica_coordinator,
        GROUP,
        PATH,
        &root.path().join(PATH),
        &permit,
    );

    // A metadata-only bump: same bytes, new version. Nothing physical
    // happened, so the fence never moved and the old proof is still
    // usable -- it simply describes a version the row has left.
    state
        .replica_coordinator
        .file_index_repository()
        .set_unix_mode(GROUP, PATH, Some(0o755), &permit)
        .unwrap();
    let current_version = current_version_hash(&state, PATH);
    assert_ne!(current_version, stale_version, "the bump must move the derived version");
    assert!(
        !state
            .replica_coordinator
            .sqlite()
            .dag_usable_proof_names_current_version(GROUP, PATH)
            .unwrap(),
        "the standing proof must now be about a version the row has moved off"
    );

    hydrate(&state, GROUP, PATH).await.expect("bytes that are already correct must not fail");

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_usable_proof_names_current_version(GROUP, PATH)
            .unwrap(),
        "hydrate must leave the claim standing on a proof about the version the row names, \
         not return success and leave the invariant broken behind it"
    );
    assert_eq!(
        std::fs::read(root.path().join(PATH)).unwrap(),
        content,
        "the bytes were already correct and must come back unchanged"
    );
    // The bump was a MODE bump, so disk did not hold the version the
    // row names until this call applied it. Re-proving without
    // applying it -- which is what this lane used to do -- published
    // an ExactObject whose version bakes in 0o755 beside a
    // FileIdentity fingerprinted over the mode disk actually had.
    // Nothing downstream compares those two halves, so the
    // contradiction was durable and invisible; the only way the proof
    // can be true is for the mode to really be there.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root.path().join(PATH)).unwrap().permissions().mode() & 0o777,
            0o755,
            "a proof naming this version claims this mode is on disk, so hydrate has to \
             have put it there"
        );
    }
}

/// The other half: when the bytes are NOT what the row now names, the
/// proof cannot be healed and the path must not be reconstructed over
/// either -- a stale write of this device's own and a local edit
/// nobody has journalled are the same observation from here.
#[tokio::test]
async fn hydrate_refuses_a_superseded_proof_whose_bytes_do_not_match_the_row() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let v1 = b"the bytes a prior cycle proved";
    let v1_block = put_block(&state, GROUP, v1);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            GROUP,
            &record_with_blocks(PATH, vec![v1_block], v1.len() as u64),
            "device-a",
            &permit,
        )
        .unwrap();
    std::fs::write(root.path().join(PATH), v1).unwrap();
    crate::test_support::seed_prior_cycle_proof(
        &state.replica_coordinator,
        GROUP,
        PATH,
        &root.path().join(PATH),
        &permit,
    );

    // A genuine content supersession: the row names new bytes that are
    // not on disk. The fence is untouched, so the V1 proof is still
    // usable and still wrong.
    let v2 = b"genuinely different content for this path";
    let v2_block = put_block(&state, GROUP, v2);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            GROUP,
            &record_with_blocks(PATH, vec![v2_block], v2.len() as u64),
            "device-a",
            &permit,
        )
        .unwrap();

    let err = hydrate(&state, GROUP, PATH)
        .await
        .expect_err("a Hydrated row whose proof is about other content must not read as done");
    assert!(
        err.to_string().contains("moved off"),
        "the refusal must name what is actually wrong, not a generic failure: {err}"
    );
    assert_eq!(
        std::fs::read(root.path().join(PATH)).unwrap(),
        v1,
        "and it must not reconstruct over bytes it cannot tell from an unjournalled edit"
    );
}

/// Restore is an internal physical mutator: it bumps the fence, writes
/// the bytes, and publishes under exactly the epoch it bumped to. It
/// used to bump that epoch and then throw it away, committing its index
/// write through the external-adoption API -- which mints a SECOND
/// epoch on its way to recording the write, and took no version at all.
/// The result was a `Hydrated` row whose proof named no version and sat
/// one epoch behind the fence: unusable on both counts, so the path
/// stayed outstanding no matter how correct the bytes on disk were.
#[tokio::test]
async fn restore_publishes_a_versioned_proof_under_the_epoch_its_own_write_bumped() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1_block = put_block(&state, GROUP, b"version one content");
    let v1 = record_with_blocks(PATH, vec![v1_block], 19);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    let v2_block = put_block(&state, GROUP, b"version two content!!");
    let v2 = record_with_blocks(PATH, vec![v2_block], 21);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();

    let fence_before = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, PATH).unwrap();

    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

    // Exactly two epochs, not three. Authoring the restore's change
    // retires the path's old basis (one advance), and the one physical
    // write is one mutation (a second). A third advance means the commit
    // went through an API that mints its own, which is precisely the
    // lane confusion this closes. Asserting the count is what pins
    // that down -- both shapes leave a usable proof behind, since the
    // adopting one publishes under the epoch it just minted.
    let fence_after = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, PATH).unwrap();
    assert_eq!(
        fence_after,
        fence_before + 2,
        "restore retires the old basis when it authors its change and then performs one \
         physical mutation, so it must advance the fence exactly twice \
         (before: {fence_before}, after: {fence_after})"
    );

    // Usable: the read fails closed unless the proof's epoch still
    // equals the path's live fence, so a second bump anywhere between
    // the write and the commit shows up here as `None`.
    let proof = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, PATH)
        .unwrap()
        .expect("the restore's own write must leave a usable proof behind");

    // And versioned, naming exactly what the row now says the path is.
    let current = state
        .replica_coordinator
        .sqlite()
        .get_current_version_record(
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            PATH,
        )
        .unwrap()
        .expect("the restored row");
    let current_version =
        yadorilink_replica_domain::session_state::CurrentVersionRecord::from(current)
            .to_file_version()
            .version_hash;
    assert_eq!(
        proof.version,
        Some(current_version),
        "the proof must name the version the restored row itself derives"
    );
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "and the claim that rests on it must be stamped in the same commit"
    );
}

/// `VersionRecord` carries its own
/// per-row `record_kind`/`symlink_target`/`unix_mode` (captured at the
/// time that row was current, not just read live off the `current`
/// row -- see `VersionRecord::record_kind`'s own doc comment); restore
/// must honour all three rather than unconditionally calling
/// `reconstruct_file`, which always writes an ordinary regular file.
/// Restoring a symlink version must recreate a real symlink, not an
/// empty regular file.
#[tokio::test]
async fn restoring_a_symlink_version_recreates_a_real_symlink_not_an_empty_regular_file() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits route through `replica_coordinator`
    // (`LocalChangeProcessor` is built from it, not `sync_state`)
    // -- mirror the override there too, or this test's real
    // provider (wired by `DaemonState::new`/`build`) fires instead and
    // requires actual group-policy setup this fixture doesn't have.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    #[cfg(windows)]
    state
        .replica_coordinator
        .link_repository()
        .set_windows_symlink_opt_in(&local_path, true)
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    // Version 1: a symlink.
    let v1 = record_with_blocks(PATH, vec![], 0);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_record_kind(GROUP, PATH, yadorilink_replica_domain::file::RecordKind::Symlink, &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_symlink_target(
            GROUP,
            PATH,
            Some(&yadorilink_root_authority::fs_identity::target_to_bytes(std::path::Path::new(
                "v1-target",
            ))),
        )
        .unwrap();

    // Version 2: an ordinary regular file, superseding the symlink.
    let v2_block = put_block(&state, GROUP, b"version two content");
    let v2 = record_with_blocks(PATH, vec![v2_block], 20);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_record_kind(GROUP, PATH, yadorilink_replica_domain::file::RecordKind::File, &permit)
        .unwrap();

    // Restore back to the symlink version.
    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

    let out_path = root.path().join(PATH);
    assert!(
        std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
        "restoring a symlink version must recreate a real symlink"
    );
    assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("v1-target"));
    // The `current` row's own classification must move too -- not just
    // the disk write. A bare `upsert_file_in_tx` (a `FileRecord`, which
    // has no room for `record_kind`) would leave the index still saying
    // `File` even after a symlink was correctly recreated on disk. A
    // later `hydrate_inner` trusting that stale `record_kind` (via its
    // own kind guard) would then treat the just-restored
    // symlink as an ordinary file and could destroy it.
    assert_eq!(
        state.replica_coordinator.file_index_repository().get_record_kind(GROUP, PATH).unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink),
        "the current row's record_kind must be updated to match the restored version"
    );
    assert_eq!(
        state.replica_coordinator.file_index_repository().get_symlink_target(GROUP, PATH).unwrap(),
        Some(yadorilink_root_authority::fs_identity::target_to_bytes(std::path::Path::new(
            "v1-target"
        ))),
        "the current row's symlink_target must be updated to match the restored version"
    );
}

/// A targetless symlink version (`symlink_target == None` on a
/// `RecordKind::Symlink` row) looks, at first glance, like it would hit
/// `restore_to_version_inner`'s write-nothing `None` dispatch arm and
/// still get stamped `Hydrated` by `commit_restore_operation` -- an
/// all-platform twin of the Windows-not-opted-in write-nothing case.
/// It is not reachable: `record_restore_operation_emitting_change`,
/// which runs earlier in the same restore, validates the identical
/// `symlink_target` field via `FileVersion::verify_hash` and rejects a
/// targetless symlink before either the disk-write dispatch or the
/// `Hydrated` stamp is ever reached. This test proves that directly
/// (a version constructed by directly manipulating the file index, the
/// only way to get a targetless symlink row queryable at all, since
/// every validated construction path refuses one) rather than trusting
/// that reasoning alone -- a regression here would mean an unstamped,
/// unwritten row silently starts claiming `Hydrated`.
#[tokio::test]
async fn restoring_a_targetless_symlink_version_fails_before_any_write_or_stamp() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits route through `replica_coordinator`
    // (`LocalChangeProcessor` is built from it, not `sync_state`)
    // -- mirror the override there too, or this test's real
    // provider (wired by `DaemonState::new`/`build`) fires instead and
    // requires actual group-policy setup this fixture doesn't have.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    // Version 1: a symlink record with no `symlink_target` at all --
    // the low-reachability shape `commit_restore_operation`'s doc
    // comment describes (`FileVersion::validate_structure` normally
    // rejects one, but `get_version` reads the raw stored row, not a
    // re-validated `FileVersion`).
    let v1 = record_with_blocks(PATH, vec![], 0);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_record_kind(GROUP, PATH, yadorilink_replica_domain::file::RecordKind::Symlink, &permit)
        .unwrap();

    // Version 2: an ordinary file, to supersede version 1 so restoring
    // back to it is a genuine restore, not a same-version no-op.
    let v2_block = put_block(&state, GROUP, b"version two content");
    let v2 = record_with_blocks(PATH, vec![v2_block], 20);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_record_kind(GROUP, PATH, yadorilink_replica_domain::file::RecordKind::File, &permit)
        .unwrap();

    let result = restore_to_version(&state, GROUP, PATH, 1).await;
    assert!(
        result.is_err(),
        "a targetless symlink version must be rejected by domain validation before any \
         disk write or index stamp, not silently accepted as a write-nothing restore"
    );

    let out_path = root.path().join(PATH);
    assert!(
        !out_path.exists(),
        "the rejected restore must leave the path untouched -- no content was ever safe \
         to write for a targetless symlink"
    );
}

/// The specific danger a stale `current` row classification creates:
/// without updating `record_kind` at restore commit time, a later
/// ordinary `hydrate` for the same path would read the STALE `File`
/// classification, pass `hydrate_inner`'s own kind guard (added this
/// round specifically to protect symlinks from exactly this), and
/// destroy the symlink this test just restored.
#[tokio::test]
async fn hydrate_after_a_symlink_restore_does_not_destroy_it() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits route through `replica_coordinator`
    // (`LocalChangeProcessor` is built from it, not `sync_state`)
    // -- mirror the override there too, or this test's real
    // provider (wired by `DaemonState::new`/`build`) fires instead and
    // requires actual group-policy setup this fixture doesn't have.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    #[cfg(windows)]
    state
        .replica_coordinator
        .link_repository()
        .set_windows_symlink_opt_in(&local_path, true)
        .unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1 = record_with_blocks(PATH, vec![], 0);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_record_kind(GROUP, PATH, yadorilink_replica_domain::file::RecordKind::Symlink, &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_symlink_target(
            GROUP,
            PATH,
            Some(&yadorilink_root_authority::fs_identity::target_to_bytes(std::path::Path::new(
                "v1-target",
            ))),
        )
        .unwrap();

    let v2_block = put_block(&state, GROUP, b"version two content");
    let v2 = record_with_blocks(PATH, vec![v2_block], 20);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_record_kind(GROUP, PATH, yadorilink_replica_domain::file::RecordKind::File, &permit)
        .unwrap();

    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();
    // Deliberately `Placeholder`, not `Hydrated`, so this test isolates
    // the kind guard specifically rather than being saved by the
    // separate already-`Hydrated` fast path: if `record_kind` were
    // still stale (`File`) because the restore commit hadn't updated
    // it, the kind guard would silently do nothing and hydration would
    // fall through to `reconstruct_file` with this symlink's empty
    // block list, destroying it.
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, PATH, MaterializationState::Placeholder, &permit)
        .unwrap();

    hydrate_inner(&state, GROUP, PATH, Some(&test_stall())).await.unwrap();

    let out_path = root.path().join(PATH);
    assert!(
        std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
        "a later hydrate must never destroy a just-restored symlink"
    );
}

/// `restore_to_version_inner`'s `reconstruct_file` call has no
/// escape-checking of its own (see `reconstruct_file`'s doc comment --
/// it is always the caller's job). If an intermediate directory
/// component of `path` is a symlink out of the sync root, the write
/// must be refused rather than following it -- the write-side twin of
/// the tombstone symlink-escape guard `verify_delete_target` closes on
/// the delete side, and the same gap `hydrate_inner`'s own
/// `verify_write_target_within_root` call closes for ordinary
/// hydration. Verified against a REAL file living entirely outside the
/// sync root, so a regression here shows up as real data loss in the
/// assertions, not a passing-by-accident check.
#[cfg(unix)]
#[tokio::test]
async fn restore_refuses_to_write_through_an_intermediate_directory_symlink() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits route through `replica_coordinator`
    // (`LocalChangeProcessor` is built from it, not `sync_state`)
    // -- mirror the override there too, or this test's real
    // provider (wired by `DaemonState::new`/`build`) fires instead and
    // requires actual group-policy setup this fixture doesn't have.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);

    // A real, valuable file living entirely outside the sync root.
    let outside_dir = tempfile::tempdir().unwrap();
    let victim_path = outside_dir.path().join("victim.txt");
    std::fs::write(&victim_path, b"do not overwrite me").unwrap();

    // An intermediate directory symlink inside the sync root,
    // redirecting "external/*" to the outside directory.
    std::os::unix::fs::symlink(outside_dir.path(), root.path().join("external")).unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let escaping_path = "external/victim.txt";
    let v1_block = put_block(&state, GROUP, b"version one content");
    let v1 = record_with_blocks(escaping_path, vec![v1_block.clone()], 19);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    let v2_block = put_block(&state, GROUP, b"version two content!!");
    let v2 = record_with_blocks(escaping_path, vec![v2_block], 21);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();

    let result = restore_to_version(&state, GROUP, escaping_path, 1).await;
    assert!(result.is_err(), "a restore through an intermediate symlink must be refused");
    assert_eq!(
        std::fs::read(&victim_path).unwrap(),
        b"do not overwrite me",
        "a restore must never write through an intermediate directory symlink out of the \
         sync root"
    );
}

/// A version whose blocks are missing locally and
/// unavailable from any peer (none connected here) fails with the
/// specific `VersionContentUnavailable` error — not a generic
/// I/O/not-found error — and leaves both the index and the on-disk
/// file completely untouched.
#[tokio::test]
async fn restore_fails_clearly_when_no_peer_holds_the_missing_blocks() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);

    // A version referencing a block that was never actually written to
    // this device's block store (as if evicted, or an on-demand link
    // that never fetched it) — `record_with_blocks` only builds the
    // `BlockInfo`/index row, it never calls `put_block`.
    let phantom_block =
        BlockInfo { hash: Sha256::digest(b"never fetched").to_vec(), offset: 0, size: 13 };
    let v1 = record_with_blocks(PATH, vec![phantom_block], 13);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();

    let err = restore_to_version_with_timeout(
        &state,
        GROUP,
        PATH,
        1,
        std::time::Duration::from_millis(200),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, SyncError::VersionContentUnavailable(_)),
        "expected a specific version-content error, got {err:?}"
    );

    assert!(
        !root.path().join(PATH).exists(),
        "a failed restore must not leave a partial file on disk"
    );
    let versions = state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap();
    assert_eq!(versions.len(), 1, "a failed restore must not add or change any version row");
}

/// Restoring a trashed file recovers its last version
/// before deletion as a new current version, and the file is live
/// again — the `trash restore` path (`SyncState::mark_deleted` is this
/// crate's local-delete primitive, exercised directly here rather than
/// through the full watcher, matching this module's other tests'
/// direct-`SyncState`-manipulation style).
#[tokio::test]
async fn restore_trashed_recovers_a_deleted_files_last_content_as_a_new_current_version() {
    let (state, _store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits route through `replica_coordinator`
    // (`LocalChangeProcessor` is built from it, not `sync_state`)
    // -- mirror the override there too, or this test's real
    // provider (wired by `DaemonState::new`/`build`) fires instead and
    // requires actual group-policy setup this fixture doesn't have.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let block = put_block(&state, GROUP, b"about to be deleted");
    let v1 = record_with_blocks(PATH, vec![block], 19);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .mark_deleted(GROUP, PATH, "device-a", &permit)
        .unwrap();

    assert!(
        state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, PATH)
            .unwrap()
            .unwrap()
            .deleted
    );
    assert_eq!(
        state.replica_coordinator.file_index_repository().list_trashed(GROUP).unwrap().len(),
        1
    );

    restore_trashed(&state, GROUP, PATH).await.unwrap();

    assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"about to be deleted");
    let current =
        state.replica_coordinator.file_index_repository().get_file(GROUP, PATH).unwrap().unwrap();
    assert!(!current.deleted, "the file must be live again after a trash restore");
}

/// `yadorilink restore <path>` without `--version` resolves
/// to the most recent *superseded* version, not the current one (there
/// would be nothing to restore *to* if it picked the current version)
/// and not an older superseded version if a newer one exists.
#[tokio::test]
async fn most_recent_superseded_version_seq_picks_the_newest_non_current_version() {
    let (state, _store_dir) = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/unused", GROUP).unwrap();
    assert_eq!(
        most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(),
        None,
        "no rows at all yet"
    );

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1 = record_with_blocks(PATH, vec![], 0);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    assert_eq!(
        most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(),
        None,
        "only a current version exists, nothing superseded yet"
    );

    let v2 = record_with_blocks(PATH, vec![], 0);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();
    let v3 = record_with_blocks(PATH, vec![], 0);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v3, "device-a", &permit)
        .unwrap();

    assert_eq!(most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(), Some(2));
}

/// Fixture: a linked root under a REAL `SyncRootLock`-backed lease
/// (not the always-valid test lease), with version 1 and version 2 of
/// `PATH` indexed and nothing on disk yet. `on_policy_read` runs every time
/// the restore asks for the group's policy head, which it does once, from
/// inside its own operation: after admission and the block fetch, before
/// the journal/DAG write, the fence bump, the physical write and the
/// commit. It is the only seam a test has into the middle of a restore.
fn restore_under_a_real_lease(
    on_policy_read: impl Fn(&yadorilink_root_authority::root_commit::RootLease) + Send + Sync + 'static,
) -> (
    Arc<DaemonState>,
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<yadorilink_root_authority::root_commit::RootLease>,
) {
    let (state, store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    #[cfg(windows)]
    state
        .replica_coordinator
        .link_repository()
        .set_windows_symlink_opt_in(&local_path, true)
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    let lock =
        yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path()).unwrap();
    let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::new(
        lock,
        GROUP.to_string(),
        0,
    ));
    state.test_root_commit_authorities.lock().unwrap().insert(GROUP.to_string(), lease.clone());

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1_block = put_block(&state, GROUP, b"version one content");
    let v1 = record_with_blocks(PATH, vec![v1_block], 19);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
        .unwrap();
    let v2_block = put_block(&state, GROUP, b"version two content!!");
    let v2 = record_with_blocks(PATH, vec![v2_block], 21);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
        .unwrap();

    let hook_lease = lease.clone();
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(move |_| {
        on_policy_read(&hook_lease);
        Ok([0u8; 32])
    }));
    (state, store_dir, root, lease)
}

/// Pulls the ground out from under a lease: the root's lock file is
/// unlinked and recreated under the same name, so the `SyncRootLock` the
/// lease holds no longer names the object at that path.
fn swap_root_lock(root: &std::path::Path) {
    let lock_path = root.join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    let _ = std::fs::remove_file(&lock_path);
    std::fs::File::create(&lock_path).unwrap();
}

/// A live restore must be ONE root-authorized operation. When the
/// root is swapped after the restore was admitted and its blocks fetched,
/// but before anything is written, nothing may be committed anywhere:
/// no journal row and DAG change, no bytes on disk, no new index version,
/// no proof. Before the fix the restore held no `LinkOperation` and
/// checked no permit, so it wrote and committed straight through.
#[tokio::test]
async fn a_restore_commits_nothing_once_its_root_is_swapped_mid_restore() {
    let root_path = std::sync::Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
    let hook_root = root_path.clone();
    let (state, _store_dir, root, lease) = restore_under_a_real_lease(move |_| {
        if let Some(root) = hook_root.lock().unwrap().as_ref() {
            swap_root_lock(root);
        }
    });
    assert!(lease.begin_operation().is_ok(), "fixture check: the lease must start out good");
    *root_path.lock().unwrap() = Some(root.path().to_path_buf());
    let fence_before = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, PATH).unwrap();
    let author_before = state
        .replica_coordinator
        .file_index_repository()
        .get_authoring_change_hash(GROUP, PATH)
        .unwrap();

    let result = restore_to_version(&state, GROUP, PATH, 1).await;

    assert!(
        lease.begin_operation().is_err(),
        "fixture check: the root must really look lost, or this test proves nothing"
    );
    assert!(result.is_err(), "a restore whose root was swapped mid-restore must fail");
    assert!(
        !root.path().join(PATH).exists(),
        "no bytes may be written through a root this device no longer owns"
    );
    let versions = state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap();
    assert_eq!(versions.len(), 2, "no index version may be committed under a lost root");
    assert_eq!(
        state
            .replica_coordinator
            .file_index_repository()
            .get_authoring_change_hash(GROUP, PATH)
            .unwrap(),
        author_before,
        "no DAG change may be authored under a lost root"
    );
    assert!(
        state
            .replica_coordinator
            .restore_operation_repository()
            .list_restore_operations(GROUP)
            .unwrap()
            .is_empty(),
        "no restore journal row may be recorded under a lost root"
    );
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, PATH)
            .unwrap()
            .is_none(),
        "no proof may be published under a lost root"
    );
    assert_eq!(
        state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, PATH).unwrap(),
        fence_before,
        "the fence is bumped only for a write that is actually going out"
    );
}

/// The restore must hold the SAME `LinkOperation` from before its
/// first write through its last commit, so a link stop that begins in the
/// middle of it waits for it to finish instead of releasing the root lock
/// under a write still in flight. A restore started after the stop began
/// is refused and changes nothing.
#[tokio::test]
async fn a_restore_holds_its_link_operation_until_its_last_commit() {
    use futures_util::FutureExt;
    let drained_mid_restore = Arc::new(std::sync::Mutex::new(None::<bool>));
    let observed = drained_mid_restore.clone();
    let (state, _store_dir, root, lease) = restore_under_a_real_lease(move |lease| {
        lease.begin_stopping();
        *observed.lock().unwrap() = Some(lease.wait_drained().now_or_never().is_some());
    });

    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

    assert_eq!(
        *drained_mid_restore.lock().unwrap(),
        Some(false),
        "a stop that began mid-restore must still see the restore's operation in flight"
    );
    assert!(
        lease.wait_drained().now_or_never().is_some(),
        "the restore's operation must be released once it has returned"
    );
    assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"version one content");

    let result = restore_to_version(&state, GROUP, PATH, 2).await;
    assert!(result.is_err(), "a restore started after the stop began must be refused");
    assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"version one content");
    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap().len(),
        3,
        "a refused restore commits no version"
    );
}

/// A crash while an access hydration held a row that was `Hydrated`
/// on entry must not cost that row its local-edit protection.
///
/// The metadata-repair fallthrough is the ordinary way into this lane
/// from `Hydrated`: the row's version moved on a mode bump, the bytes on
/// disk are already the ones it names, and the attempt CASes the row to
/// `Hydrating` before it rewrites anything. A crash there -- during the
/// block resolution, before the fence bump -- leaves `Hydrating` with no
/// intent and the prior proof still standing against an unmoved fence.
/// While the daemon is down the user saves an edit to the file. On the
/// way back up the startup reset used to demote the row to `Placeholder`,
/// and a `Placeholder` is exactly what access hydration reconstructs over
/// without asking: the next fetch or pin, arriving before the startup
/// scan has journalled the edit, wrote the stale indexed bytes over it.
/// Left `Hydrated` -- the state this attempt's own guard would have
/// reverted to had it failed instead of crashed -- the proof still
/// stands, disk no longer matches, and hydrate refuses.
#[tokio::test]
async fn a_crash_mid_access_hydration_from_hydrated_keeps_an_offline_edit_protected() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let content = b"already exactly right on disk";
    let block = put_block(&state, GROUP, content);
    let record = record_with_blocks(PATH, vec![block], content.len() as u64);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &record, "device-a", &permit)
        .unwrap();
    std::fs::write(root.path().join(PATH), content).unwrap();
    crate::test_support::seed_prior_cycle_proof(
        &state.replica_coordinator,
        GROUP,
        PATH,
        &root.path().join(PATH),
        &permit,
    );
    // Metadata-only bump: the proof is still usable, about the old version.
    state
        .replica_coordinator
        .file_index_repository()
        .set_unix_mode(GROUP, PATH, Some(0o755), &permit)
        .unwrap();
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "setup: the attempt enters from Hydrated"
    );

    // The attempt's entry CAS, then a crash: the guard never runs.
    let canonical = state
        .replica_coordinator
        .file_index_repository()
        .canonical_current_row(GROUP, PATH)
        .unwrap()
        .unwrap();
    let guard = state
        .replica_coordinator
        .begin_access_hydration(
            GROUP,
            PATH,
            Some(MaterializationState::Hydrated),
            canonical.authoring_change_hash,
            canonical.version_hash(),
        )
        .unwrap()
        .expect("the entry CAS lands");
    std::mem::forget(guard);

    // The user's save while the daemon is down.
    let edit = b"an edit the user saved while the daemon was down";
    std::fs::write(root.path().join(PATH), edit).unwrap();

    // Restart.
    let (hydrating, evicting) = state.replica_coordinator.reset_stale_transient_states();
    hydrating.unwrap();
    evicting.unwrap();
    let after_reset = state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(GROUP, PATH)
        .unwrap();

    // An access hydration before the startup scan has journalled the edit.
    let _ = hydrate(&state, GROUP, PATH).await;
    assert_eq!(
        std::fs::read(root.path().join(PATH)).unwrap(),
        edit,
        "an offline edit to a file that was Hydrated must never be overwritten by a hydrate \
         after the restart"
    );
    assert_eq!(
        after_reset,
        Some(MaterializationState::Hydrated),
        "the reset must give back the Hydrated the attempt entered from, not demote it"
    );
}

/// A convergence rehydration that entered from `Hydrated` and
/// failed after its fence bump must not leave the row `Hydrated` with no
/// usable proof.
///
/// The bump invalidates the proof the row stood on, so reverting to the
/// entry state claims content nothing vouches for. That pair is the one
/// access hydration refuses as `CorruptState` without touching disk, so
/// every open or pin of the path failed until something re-drove the
/// convergence lane. Driven through the owner's guard in the lane's
/// order: the entry CAS, the `peer_hydration_write` bump, then a failure
/// (a reconstruct I/O error, or the metadata apply) dropping the guard.
#[tokio::test]
async fn a_convergence_rehydration_that_fails_after_its_fence_bump_leaves_no_proofless_hydrated() {
    let (state, _store_dir) = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let content = b"content the row proves on disk";
    let block = put_block(&state, GROUP, content);
    let record = record_with_blocks(PATH, vec![block], content.len() as u64);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(GROUP, &record, "device-a", &permit)
        .unwrap();
    std::fs::write(root.path().join(PATH), content).unwrap();
    crate::test_support::seed_prior_cycle_proof(
        &state.replica_coordinator,
        GROUP,
        PATH,
        &root.path().join(PATH),
        &permit,
    );
    let sqlite = state.replica_coordinator.sqlite();
    assert!(
        sqlite.dag_usable_proof_names_current_version(GROUP, PATH).unwrap(),
        "setup: the row enters Hydrated on a usable proof"
    );

    let canonical = state
        .replica_coordinator
        .file_index_repository()
        .canonical_current_row(GROUP, PATH)
        .unwrap()
        .unwrap();
    let mut guard = state
        .replica_coordinator
        .begin_convergence_hydration(
            GROUP,
            PATH,
            Some(MaterializationState::Hydrated),
            canonical.authoring_change_hash,
            canonical.version_hash(),
        )
        .unwrap()
        .expect("the entry CAS lands");
    guard.begin_physical_write().unwrap();
    // The reconstruct (or the metadata apply) fails: the lane returns Err
    // and the guard drops uncommitted.
    drop(guard);

    let after = state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(GROUP, PATH)
        .unwrap();
    let usable = sqlite.dag_usable_proof_names_current_version(GROUP, PATH).unwrap();
    assert!(
        after != Some(MaterializationState::Hydrated) || usable,
        "a rehydration that failed after its fence bump left the row Hydrated with no usable \
         proof (state {after:?})"
    );
    assert_eq!(after, Some(MaterializationState::Placeholder));
    hydrate(&state, GROUP, PATH)
        .await
        .expect("the next access hydration must re-drive the path, not refuse it as corrupt");
    assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), content);
    assert!(sqlite.dag_usable_proof_names_current_version(GROUP, PATH).unwrap());
}

/// Seeds one Placeholder row with `mode` and `xattrs`, and hydrates it.
#[cfg(target_os = "linux")]
async fn hydrate_one_with_metadata(
    mode: u32,
    xattrs: &[(String, Vec<u8>)],
) -> (Arc<ReplicaCoordinator>, tempfile::TempDir, Result<(), SyncError>) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    sync_state.link_repository().add_link(&root_dir.path().to_string_lossy(), "group-1").unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root_dir.path(),
        "group-1",
        sync_state.as_ref(),
    )
    .unwrap();
    let content = b"hydrated with replicated metadata";
    let hash = Sha256::digest(content).to_vec();
    store.put(content).unwrap();
    sync_state
        .change_history_repository()
        .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    sync_state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "doc.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    sync_state
        .file_index_repository()
        .set_unix_mode("group-1", "doc.txt", Some(mode), &permit)
        .unwrap();
    sync_state.file_index_repository().set_xattrs("group-1", "doc.txt", xattrs, &permit).unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Placeholder, &permit)
        .unwrap();
    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    state.install_test_root_commit_authority("group-1");
    let result = hydrate_inner(&state, "group-1", "doc.txt", Some(&test_stall())).await;
    (sync_state, root_dir, result)
}

/// Access hydration must not publish an exact proof when the replicated
/// attributes it set cannot be confirmed, even though the bytes and the mode
/// landed. A name longer than the kernel accepts makes the set fail silently,
/// which is exactly the failure the strict in-attempt check exists to catch.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn hydration_publishes_no_proof_when_its_xattrs_cannot_be_confirmed() {
    use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
    let unsettable = vec![(format!("user.{}", "a".repeat(300)), b"v".to_vec())];

    let (sync_state, _root, result) = hydrate_one_with_metadata(0o644, &unsettable).await;

    assert!(result.is_err(), "an unconfirmed attribute set must fail the attempt: {result:?}");
    assert!(
        !MaterializationExecutionPort::has_usable_materialized_generation(
            sync_state.as_ref(),
            "group-1",
            "doc.txt"
        )
        .unwrap(),
        "no proof may be published for attributes that were not confirmed"
    );
}

/// The positive half: valid attributes with a final owner-unreadable mode
/// reach a proof, on the check taken before the mode was applied.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn hydration_to_an_owner_unreadable_mode_reaches_a_proof_with_its_xattr() {
    use std::os::unix::fs::PermissionsExt;
    use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let (sync_state, root, result) = hydrate_one_with_metadata(0o200, &xattrs).await;

    result.expect("valid attributes and a write-only mode must hydrate");
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        sync_state.as_ref(),
        "group-1",
        "doc.txt"
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

/// Restores version 1 of `PATH`, whose row carried `mode` and `xattrs`
/// while it was current, and returns the state for inspection.
#[cfg(target_os = "linux")]
async fn restore_v1_with_metadata(
    mode: u32,
    xattrs: &[(String, Vec<u8>)],
) -> (Arc<DaemonState>, tempfile::TempDir, tempfile::TempDir) {
    let (state, store_dir) = test_state();
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state.install_test_root_commit_authority(GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        GROUP,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let v1_block = put_block(&state, GROUP, b"version one content");
    let v1 = record_with_blocks(PATH, vec![v1_block], 19);
    let index = state.replica_coordinator.file_index_repository();
    index.upsert_file_with_origin(GROUP, &v1, "device-a", &permit).unwrap();
    index.set_unix_mode(GROUP, PATH, Some(mode), &permit).unwrap();
    index.set_xattrs(GROUP, PATH, xattrs, &permit).unwrap();
    let v2_block = put_block(&state, GROUP, b"version two content!!");
    let v2 = record_with_blocks(PATH, vec![v2_block], 21);
    index.upsert_file_with_origin(GROUP, &v2, "device-a", &permit).unwrap();

    restore_to_version(&state, GROUP, PATH, 1).await.unwrap();
    (state, store_dir, root)
}

/// A restore whose replicated attributes cannot be confirmed (a name the
/// kernel rejects makes the set fail silently) still happens, but it must
/// not publish an exact proof or claim to hold the content.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_restore_whose_xattrs_cannot_be_confirmed_publishes_no_proof() {
    let unsettable = vec![(format!("user.{}", "a".repeat(300)), b"v".to_vec())];

    let (state, _store, _root) = restore_v1_with_metadata(0o644, &unsettable).await;

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, PATH)
            .unwrap()
            .is_none(),
        "no proof may be published for attributes that were not confirmed"
    );
    assert_ne!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "the row must not claim to hold content it has no proof for"
    );
}

/// The positive half: valid attributes with a final owner-unreadable mode
/// reach the versioned proof, on the check taken before the mode.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_restore_to_an_owner_unreadable_mode_reaches_a_proof_with_its_xattr() {
    use std::os::unix::fs::PermissionsExt;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let (state, _store, root) = restore_v1_with_metadata(0o200, &xattrs).await;

    assert!(state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, PATH)
        .unwrap()
        .is_some());
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
    let out_path = root.path().join(PATH);
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs
    );
}
