#![cfg(test)]

use super::{
    drive_obligations_once_for_test, drive_obligations_once_for_test_with_heads_hook,
    drive_obligations_once_for_test_with_hooks, BeforeCompletionHook, BeforeHeadsAfterHook,
    ConvergenceEngine, DaemonState, MAX_PATHS_PER_RECONCILE_ATTEMPT,
};
use crate::convergence::engine_impl::complete_one_obligation;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::Arc;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_root_authority::root_identity::VerifiedRoot;

const GROUP: &str = "group-a";

fn empty_version(mtime: i64) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Builds a maintenance-free `DaemonState` (via `DaemonState::build`,
/// not `DaemonState::new`) with `GROUP` fully adopted (link + verified
/// root + startup-ready) and a stubbed root-commit authority (the
/// sanctioned test-only escape hatch `DaemonState::test_root_commit_
/// authorities` documents -- the real `impl RootCommitAuthorityProvider
/// for DaemonState` otherwise needs a live `LinkRuntime`, which nothing
/// here starts), plus one registered candidate `PeerSyncSession` so
/// `process_group` has somewhere to route its reconcile attempt.
async fn build_state_with_adopted_group(
) -> (Arc<DaemonState>, tempfile::TempDir, std::path::PathBuf) {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let replica_coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let block_store =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());

    replica_coordinator.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
    // Real symlink materialization on Windows is per-link opt-in
    // (`materialize_symlink_windows`'s own doc comment) -- without this,
    // `materialize_symlink_at` takes the default skip-with-visible-status
    // policy and every symlink candidate in this module's tests would
    // settle as `SymlinkMaterializeOutcome::PolicySkipped` ->
    // `MaterializeResult::RetryRequired` on a real Windows host, never
    // closing its obligation, regardless of how many ticks run. Opting
    // in here (mirroring `hydration.rs`'s own `#[cfg(windows)]` call
    // sites) makes this fixture's real materialize path exercise the
    // same real on-disk write on every platform.
    #[cfg(windows)]
    replica_coordinator
        .link_repository()
        .set_windows_symlink_opt_in(&root.to_string_lossy(), true)
        .unwrap();
    VerifiedRoot::open(&root, GROUP, replica_coordinator.as_ref()).unwrap();
    let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP);
    replica_coordinator.startup_readiness().mark_group_ready(GROUP, generation);

    let build = DaemonState::build("device-local".to_string(), replica_coordinator, block_store);
    let state = build.state;
    state.test_root_commit_authorities.lock().unwrap().insert(
        GROUP.to_string(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );

    let deps = crate::peer_orchestrator::peer_sync_session_deps(&state);
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("device-local", "device-peer").await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), root.clone())]),
        transports,
        Some(state.forward_tx.clone()),
        deps,
    );
    state.peers.register_session("device-peer".to_string(), session, state.local_convergence());

    (state, root_dir, root)
}

/// This author's latest change here, so the next one it writes continues
/// its chain instead of starting a second one.
///
/// A device that writes several files writes several changes in a row, each
/// descending the last; it does not produce a fan of parentless roots under
/// one identity, and admission refuses that shape because a second root
/// claims a position the author's own history has already passed. Keyed per
/// device and held per thread, which is per test, so each test's fresh store
/// gets a fresh chain.
fn admit_change(
    state: &DaemonState,
    device: &str,
    key: &SigningKey,
    path: &str,
    version: &FileVersion,
) -> Change {
    thread_local! {
        static AUTHOR_TIPS: std::cell::RefCell<
            std::collections::BTreeMap<String, (ChangeHash, u64)>,
        > = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    }
    let (parents, max_parent_lamport) = AUTHOR_TIPS.with(|tips| match tips.borrow().get(device) {
        Some((hash, lamport)) => (vec![*hash], *lamport),
        None => (Vec::new(), 0),
    });
    let change = create_signed_for_tests(
        parents,
        max_parent_lamport,
        DeviceId(device.to_string()),
        FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath(path.to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        key,
    );
    let admitted = state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&change, std::slice::from_ref(version))
        .unwrap();
    assert!(
        matches!(admitted.outcome, yadorilink_sync_sqlite::dag_store::AdmitOutcome::Applied),
        "this fixture's change must land: {:?}",
        admitted.outcome
    );
    AUTHOR_TIPS.with(|tips| {
        tips.borrow_mut().insert(device.to_string(), (change.compute_hash(), change.lamport))
    });
    change
}

/// End to end: with nothing racing the obligation-driven worker's
/// single reconcile attempt, admitting a change must both publish the
/// real materialized generation AND close its `projection_obligations`
/// row via the exact-outcome compound completion primitive -- proven
/// not merely by "the row is gone" but by cross-checking the desired
/// hash the completion closed against equals the same hash the
/// desired-side builder independently computes for this content.
/// Confirmed genuinely RED by passing the WRONG claimed generation
/// (`claimed_g + 1`) to the completion call inside
/// `complete_one_obligation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stable_frontier_closes_the_obligation_via_the_exact_completion_primitive() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[81u8; 32]);
    let version = empty_version(1_700_000_100);
    admit_change(&state, "device-a", &key, "obligated.txt", &version);

    let obligation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "obligated.txt")
        .unwrap()
        .expect("admission must have created an obligation");
    assert_eq!(obligation_before.invalidation_generation, 1);

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy, "the one, unraced candidate attempt must be trustworthy");

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "obligated.txt")
            .unwrap()
            .is_none(),
        "a stable-frontier, fully-settled attempt must close the obligation"
    );
    let basis = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "obligated.txt")
        .unwrap()
        .expect("the exact outcome must also publish a usable materialized generation");
    let resolution = yadorilink_replica_engine::conflict::PathResolution::Present {
        winner: 0,
        conflict_copies: vec![],
    };
    let desired_hash = state
        .replica_coordinator
        .sqlite()
        .dag_desired_resolved_path_state_hash(
            GROUP,
            "obligated.txt",
            &resolution,
            Some(&version.version_hash),
        )
        .unwrap();
    assert_eq!(
        basis.resolved_path_state_hash, desired_hash,
        "the published proof's own hash must equal the independently-computed desired \
         hash for the same content -- not merely 'some hash'"
    );
}

/// Regression test (hazard-held case, 1 of 2 sibling cases guarded
/// here): a hazard-held settlement must close its obligation via the
/// non-exact completion
/// primitive, but must never publish an exact materialized generation
/// -- `path_materialized_generations` staying empty is what lets a
/// later hazard-clear-and-recheck genuinely re-materialize the path
/// instead of a stale exact row short-circuiting it. Genuine hazard
/// detection is not reliably reachable through this Linux sandbox's
/// real `process_group` pipeline (`NamePolicy::local()` is POSIX here,
/// and this host's filesystems are case/normalization-sensitive), so
/// this test manufactures the held state directly and drives the SAME
/// completion primitive `process_group_via_obligations` calls in
/// production -- exactly the pattern `hazard_recheck_tests::a_held_
/// path_is_re_examined_and_cleared_by_the_sweep_alone` (`engine_
/// wrapper.rs`) already uses for the same reason. Confirmed genuinely
/// RED by temporarily swapping the `HazardHeld` evidence below for an
/// `ExactAbsent` one: the exact/non-exact split routes through
/// materially different completion machinery (the exact side CASes on
/// a filesystem mutation fence this test never bumped), so the swap
/// fails this test's very first assertion (obligation completion
/// itself) rather than reaching the exact-generation check -- equally
/// conclusive proof this test is not vacuous, and a stronger failure
/// mode than a silently-wrong classification would be.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hazard_held_settlement_does_not_publish_an_exact_generation() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let key = SigningKey::from_bytes(&[92u8; 32]);
    let version = empty_version(1_700_001_000);
    let change = admit_change(&state, "device-a", &key, "held.txt", &version);

    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "held.txt".to_string(),
                size: 0,
                mtime_unix_nanos: 1_700_001_000,
                blocks: vec![],
                deleted: false,
            },
            "device-a",
            &change.change_hash(),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_held(GROUP, "held.txt", "case_collision", 1_000)
        .unwrap();

    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "held.txt")
        .unwrap()
        .expect("admission must have created an obligation");

    complete_one_obligation(
        &state,
        GROUP,
        "held.txt",
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &crate::local_convergence::types::SettlementEvidence::HazardHeld {
            reason: "case_collision".to_string(),
        },
        &[],
        None,
    )
    .await;

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "held.txt")
            .unwrap()
            .is_none(),
        "a hazard-held settlement must still close the obligation via the non-exact primitive"
    );
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "held.txt")
            .unwrap()
            .is_none(),
        "a hazard hold must never publish an exact materialized generation -- nothing was \
         written to disk"
    );
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_held_state(GROUP, "held.txt")
            .unwrap()
            .map(|h| h.reason),
        Some("case_collision".to_string()),
        "the durable held-reason record must still be the source of truth for why this path \
         is stuck"
    );
}

/// Regression test (on-demand placeholder case, 2 of 2 sibling cases
/// guarded here): a path settled by writing an on-demand placeholder
/// must still close its
/// obligation (via the non-exact completion primitive), but
/// `path_materialized_generations` must hold NO row for it -- a
/// placeholder is a policy-authorized deferral, never an exact claim
/// about disk. Confirmed genuinely RED by temporarily swapping the
/// OnDemand branch's terminal `Ok(MaterializeResult::Settled(
/// SettlementEvidence::PolicyPlaceholder))` in `peer_session.rs` for an
/// `ExactAbsent` one: the exact/non-exact split routes through
/// materially different completion machinery (the exact side CASes on
/// a filesystem mutation fence this scenario's fence snapshot does not
/// satisfy), so the swap fails this test's very first assertion
/// (obligation completion itself) rather than reaching the exact-
/// generation check -- equally conclusive proof this test is not
/// vacuous, and a stronger failure mode than a silently-wrong
/// classification would be.
///
/// The obligation-closes-synchronously half of this is genuinely
/// platform-specific, not a portability oversight: on a real Windows
/// host `create_or_defer_placeholder` unconditionally defers the actual
/// on-disk write to `cfapi-host.exe`'s own poll (see that function's
/// own doc comment) -- nothing in this crate's `test-support` seam can
/// force the opposite (synchronous) outcome on real Windows the way it
/// can force the deferred one on every OTHER platform, because the
/// synchronous outcome this test's non-Windows half exercises simply
/// does not exist on Windows. So the one tick here settles as
/// `MaterializeResult::RetryRequired` on Windows instead of
/// `Settled(PolicyPlaceholder)`, and the obligation is left outstanding
/// (mirroring `materialization_execution.rs`'s own
/// `repair_leaves_the_intent_open_when_the_windows_placeholder_write_
/// is_deferred`, the sibling regression for the repair-sweep side of
/// this exact platform split) rather than closed. Confirmed against
/// real windows-latest CI (not merely reasoned from the doc comment):
/// this test failed there with the obligation still present after the
/// single tick, precisely this branch's own expectation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_demand_placeholder_settlement_does_not_publish_an_exact_generation() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(
            &root.to_string_lossy(),
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();
    let key = SigningKey::from_bytes(&[91u8; 32]);
    let version = empty_version(1_700_000_900);
    admit_change(&state, "device-a", &key, "deferred.txt", &version);

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy, "the one, unraced candidate attempt must be trustworthy");

    #[cfg(windows)]
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "deferred.txt")
            .unwrap()
            .is_some(),
        "on Windows the real placeholder write is deferred to cfapi-host.exe -- one tick \
         must leave the obligation outstanding, not close it via a settlement that never \
         happened"
    );
    #[cfg(not(windows))]
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "deferred.txt")
            .unwrap()
            .is_none(),
        "a placeholder settlement under a stable frontier must still close the obligation"
    );
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "deferred.txt")
            .unwrap()
            .is_none(),
        "an on-demand placeholder must never publish an exact materialized generation -- it \
         is a scheduler-level settlement, not a claim about disk"
    );
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, "deferred.txt")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder),
        "the durable record of what actually happened must be the placeholder state itself"
    );

    // With no exact record published, a later policy change to eager
    // must still find real hydration
    // work outstanding for this path -- not silently short-circuited by
    // a stale `path_materialized_generations` row that was never there.
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(
            &root.to_string_lossy(),
            yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
        )
        .unwrap();
    let candidates = state
        .replica_coordinator
        .materialization_state_repository()
        .list_materialization_repair_candidates(GROUP)
        .unwrap();
    assert_eq!(
        candidates,
        vec!["deferred.txt".to_string()],
        "an eager policy change must find the placeholder path as real outstanding \
         hydration work"
    );
}

/// Proves the `redelivered_known` removal was safe -- once admission-
/// time invalidation (`bump_projection_obligations_for_touched_paths`)
/// is the ONLY re-arm mechanism left (no redelivery-triggered re-
/// enqueue exists anywhere any more), a path whose obligation already
/// closed must still be correctly re-invalidated by a genuinely NEW,
/// causally-descended admission -- not stuck forever just because its
/// prior obligation row was deleted on completion. No redelivery of
/// the first change happens anywhere in this test; the second
/// admission alone is what re-arms it. Uses the real exact-outcome
/// completion primitive (via `drive_obligations_once_for_test`, a real
/// materialize + a real `dag_complete_obligation_if_exact_proof_
/// current` call) rather than a hand-simulated non-exact stand-in, so
/// the "obligation disappears" half of this proof is as faithful as
/// this crate's own harness can make it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn completed_projection_is_invalidated_by_new_admission_without_any_duplicate_or_redelivery_traffic(
) {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[85u8; 32]);
    let version_1 = empty_version(1_700_000_500);
    let change_1 = admit_change(&state, "device-a", &key, "reinvalidated.txt", &version_1);

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "reinvalidated.txt")
            .unwrap()
            .is_none(),
        "sanity: the first admission must fully settle and close its obligation"
    );

    // A genuinely NEW admission -- causally descended from the first,
    // never a redelivery of it -- touching the same path a second time.
    let version_2 = empty_version(1_700_000_600);
    let change_2 = create_signed_for_tests(
        vec![change_1.compute_hash()],
        change_1.lamport,
        DeviceId("device-a".to_string()),
        yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath("reinvalidated.txt".to_string()),
            version: version_2.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key,
    );
    state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&change_2, std::slice::from_ref(&version_2))
        .unwrap();

    let obligation_after_new_admission = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "reinvalidated.txt")
        .unwrap()
        .expect(
            "a genuinely new admission on an already-settled path must re-create its \
             obligation -- nothing else re-arms it any more",
        );
    assert_eq!(
        obligation_after_new_admission.invalidation_generation, 1,
        "a fresh row after the prior one was deleted on completion starts at generation 1 \
         again -- generation only needs to be locally monotonic between claim and close, \
         not globally monotonic across the path's whole history"
    );

    let healthy_again = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy_again, "the second, genuinely new obligation must also resolve cleanly");
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "reinvalidated.txt")
            .unwrap()
            .is_none(),
        "the second admission's own obligation must also close"
    );
}

/// The raced counterpart of the previous test: a concurrent,
/// UNRELATED admission ("other2.txt") landing mid-reconcile must NOT
/// block "raced2.txt"'s own settlement -- this is the same scenario as
/// `unrelated_path_head_movement_must_not_discard_an_already_settled_
/// attempt` above, proven end to end here via a real `path_lock`-forced
/// delay instead of `BeforeHeadsAfterHook`. A group-wide `before ==
/// after` heads-stability guard would discard raced2.txt's own
/// already-resolved settlement purely because an unrelated path moved
/// the group's heads in between (see `unrelated_path_head_movement_
/// must_not_discard_an_already_settled_attempt`'s own doc comment), and
/// a group under steady catch-up admission would then barely converge.
/// Confirmed to fail with such a guard in place: raced2.txt's
/// publish/completion never ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frontier_moving_mid_reconcile_on_an_unrelated_path_does_not_block_completion() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key_a = SigningKey::from_bytes(&[82u8; 32]);
    let key_b = SigningKey::from_bytes(&[83u8; 32]);
    let version = empty_version(1_700_000_200);
    admit_change(&state, "device-a", &key_a, "raced2.txt", &version);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced2.txt")
            .unwrap()
            .is_some(),
        "sanity: admission must have created an obligation"
    );

    let path_lock = state.replica_coordinator.path_lock(GROUP, "raced2.txt");
    let held = path_lock.lock().await;

    let engine2 = engine.clone();
    let handle =
        tokio::spawn(async move { drive_obligations_once_for_test(&engine2, 128, 256).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let version_b = empty_version(1_700_000_201);
    admit_change(&state, "device-b", &key_b, "other2.txt", &version_b);

    drop(held);
    let _ = handle.await.unwrap();

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "raced2.txt")
            .unwrap()
            .is_some(),
        "raced2.txt's own settlement must publish even though an UNRELATED path's admission \
         moved the group's heads mid-reconcile"
    );
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced2.txt")
            .unwrap()
            .is_none(),
        "raced2.txt's obligation must close -- nothing about raced2.txt itself changed \
         during this attempt"
    );
}

/// The index half of "a prior cycle already materialized this path".
///
/// A real materialize commits the projected row and publishes the
/// proof; a fixture that publishes only the proof is simulating half
/// of it, and the half it leaves out is the one the publication guard
/// checks. `dag_publish_materialized_generation_if_fence_current`
/// refuses to record a proof naming a version the current row does
/// not name -- including when there is no current row at all, which
/// is what `admit_change` alone leaves behind.
fn seed_projected_row(state: &DaemonState, path: &str, version: &FileVersion, author: &Change) {
    state
        .replica_coordinator
        .apply_projected_row_atomic(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: path.to_string(),
                size: version.size,
                mtime_unix_nanos: version.meta.mtime_unix_nanos,
                blocks: version
                    .blocks
                    .iter()
                    .map(|b| yadorilink_replica_domain::file::BlockInfo {
                        hash: b.hash.0.clone(),
                        offset: 0,
                        size: b.size,
                    })
                    .collect(),
                deleted: false,
            },
            "device-a",
            Some(&author.change_hash()),
            &yadorilink_replica_domain::session_state::LocalFileMetaColumns {
                record_kind: version.meta.record_kind,
                symlink_target: version.meta.symlink_target.clone(),
                symlink_out_of_root: false,
                unix_mode: version.meta.unix_mode,
                xattrs: version.meta.xattrs.clone(),
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
}

fn symlink_version(mtime: i64, target: &[u8]) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: Some(target.to_vec()),
            record_kind: RecordKind::Symlink,
            xattrs: Vec::new(),
        },
    )
}

/// Zero-work half: an obligation whose desired hash already
/// matches a usable, disk-revalidating `path_materialized_generations`
/// record -- published here directly, simulating a prior successful
/// cycle, WITHOUT ever calling the obligation-driven worker first --
/// closes on its very first claim with zero physical work. Proven not
/// merely by "it closed" but by the published row's own `GenerationId`
/// being byte-for-byte unchanged (a real materialize+republish always
/// mints a fresh one) and the symlink's own filesystem identity
/// (`object_id`, its inode) being unchanged (a real write always
/// replaces the object via a fresh temp+rename). Uses a symlink, not a
/// plain file: its `symlink_target_digest` discriminator is content,
/// not a clock reading, so the assertion holds regardless of this
/// sandbox's own birth-time-clock granularity (confirmed `Coarse` here
/// via the real probe, which alone would leave a plain regular file's
/// identity permanently `Ambiguous`, never `Confirmed`, on this exact
/// filesystem). Confirmed genuinely RED by making `zero_work_
/// settlement_for_path` unconditionally return `Ok(None)` (never
/// authorizing the skip) -- that version made this test's
/// `generation_id` assertion fail, since a real materialize ran and
/// minted a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_work_close_performs_no_physical_work() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[91u8; 32]);
    let version = symlink_version(1_700_000_300, b"target-content");
    let author = admit_change(&state, "device-a", &key, "already-correct-link", &version);
    seed_projected_row(&state, "already-correct-link", &version, &author);

    // Simulate "a prior successful materialize already left disk and
    // the proof table in agreement" -- written directly, never through
    // `drive_obligations_once_for_test`, which must not be called
    // before this point: the very first claim of this obligation must
    // already find zero work to do.
    let out_path = root.join("already-correct-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink("target-content", &out_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("target-content", &out_path).unwrap();
    let identity =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    assert!(
        identity.symlink_target_digest.is_some(),
        "sanity: a symlink observation must populate its content-based discriminator"
    );
    let heads = state.replica_coordinator.sqlite().dag_group_heads(GROUP).unwrap();
    let fence = state
        .replica_coordinator
        .dag_snapshot_mutation_fence(GROUP, "already-correct-link")
        .unwrap();
    let published = state
        .replica_coordinator
        .dag_publish_materialized_generation_if_fence_current(
            GROUP,
            "already-correct-link",
            &heads,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: RecordKind::Symlink,
                version: version.version_hash,
                identity: Box::new(Some(identity)),
            },
            fence,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(published, "sanity: the simulated prior-cycle publish must itself succeed");

    let basis_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "already-correct-link")
        .unwrap()
        .unwrap();

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy, "the zero-work close itself still counts as a trustworthy tick");

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "already-correct-link")
            .unwrap()
            .is_none(),
        "the obligation must close"
    );
    let basis_after = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "already-correct-link")
        .unwrap()
        .unwrap();
    assert_eq!(
        basis_after.generation_id, basis_before.generation_id,
        "a zero-work close must never re-publish -- the GenerationId must be byte-for-byte \
         unchanged, not merely equal in content"
    );
    let identity_after =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    assert_eq!(
        identity_after.object_id, identity.object_id,
        "a zero-work close must never touch disk -- the symlink's own inode must be \
         unchanged, not merely its content"
    );
}

/// The zero-work close's companion: a usable record whose hash matches but whose
/// disk revalidation fails (here, by publishing with no recorded
/// `filesystem_identity` at all -- `revalidate_identity_against_disk`'s
/// own doc comment: "there is nothing to revalidate against, so this
/// check cannot confirm anything") must fail closed into a REAL
/// materialize, not a zero-work close -- proven by a freshly minted
/// `GenerationId` after the tick, this time carrying a real recorded
/// identity a real write always produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_usable_record_that_fails_revalidation_performs_real_work_instead() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[92u8; 32]);
    let version = empty_version(1_700_000_400);
    let author = admit_change(&state, "device-a", &key, "unrevalidatable.txt", &version);
    seed_projected_row(&state, "unrevalidatable.txt", &version, &author);

    let out_path = root.join("unrevalidatable.txt");
    std::fs::write(&out_path, b"").unwrap();
    let heads = state.replica_coordinator.sqlite().dag_group_heads(GROUP).unwrap();
    let fence = state
        .replica_coordinator
        .dag_snapshot_mutation_fence(GROUP, "unrevalidatable.txt")
        .unwrap();
    let published = state
        .replica_coordinator
        .dag_publish_materialized_generation_if_fence_current(
            GROUP,
            "unrevalidatable.txt",
            &heads,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: RecordKind::File,
                version: version.version_hash,
                // No identity recorded -- revalidation can never
                // confirm this record, by design.
                identity: Box::new(None),
            },
            fence,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(published, "sanity: the simulated prior-cycle publish must itself succeed");

    let basis_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "unrevalidatable.txt")
        .unwrap()
        .unwrap();

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy);

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "unrevalidatable.txt")
            .unwrap()
            .is_none(),
        "the obligation must still close -- via real work this time"
    );
    let basis_after = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "unrevalidatable.txt")
        .unwrap()
        .unwrap();
    assert_ne!(
        basis_after.generation_id, basis_before.generation_id,
        "a record that fails revalidation must be closed by a REAL materialize -- a fresh \
         GenerationId, not the pre-existing unrevalidatable one"
    );
    assert!(
        basis_after.filesystem_identity.is_some(),
        "the real materialize's own publish always records a real identity"
    );
}

/// Sanity check for `BeforeCompletionHook` itself, before it becomes
/// load-bearing for any race regression: parking and resuming with
/// nothing interleaved must reproduce the exact same outcome as the
/// unhooked entrypoint -- the hook must be able to observe the worker
/// reaching its pause point without changing what happens afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn before_completion_hook_pauses_and_resumes_without_changing_the_outcome() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key = SigningKey::from_bytes(&[93u8; 32]);
    let version = empty_version(1_700_000_500);
    admit_change(&state, "device-a", &key, "hooked.txt", &version);

    let hooks = BeforeCompletionHook::new();
    let engine2 = engine.clone();
    let hooks2 = hooks.clone();
    let handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hooks2).await
    });

    hooks.wait_parked().await;
    // Nothing interleaved here -- this is the sanity case, not a race.
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "hooked.txt")
            .unwrap()
            .is_some(),
        "the obligation must still be outstanding while the worker is parked before its own \
         completion CAS"
    );
    hooks.resume();

    let healthy = handle.await.unwrap();
    assert!(healthy);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "hooked.txt")
            .unwrap()
            .is_none(),
        "resuming an uninterleaved pause must close the obligation exactly as the unhooked \
         path does"
    );
}

/// The publication race: a real materialize succeeds and publishes
/// evidence under a live mutation-fence value E, but before the
/// completion CAS runs, an INDEPENDENT mutator (one the DAG never saw)
/// bumps the fence to E+1 and rewrites the path. The claimed DAG-side
/// generation `G` never moves in this scenario at all -- proving that
/// the completion's refusal comes from the live fence mismatch (b), not
/// from any generation check (a). Confirmed genuinely RED by
/// temporarily dropping the fence/hash `EXISTS` clause from
/// `complete_obligation_if_exact_proof_current`'s `DELETE` statement
/// (leaving only the generation check): the completion then wrongly
/// reported success and closed the obligation despite the independent
/// mutation. Restored and reconfirmed GREEN.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_succeeds_but_later_mutation_before_close_prevents_completion() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key = SigningKey::from_bytes(&[94u8; 32]);
    let version = empty_version(1_700_000_600);
    admit_change(&state, "device-a", &key, "raced-publish.txt", &version);

    let obligation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "raced-publish.txt")
        .unwrap()
        .expect("admission must have created an obligation");
    let claimed_g = obligation_before.invalidation_generation;

    let hooks = BeforeCompletionHook::new();
    let engine2 = engine.clone();
    let hooks2 = hooks.clone();
    let handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hooks2).await
    });

    // The worker parks only after a real materialize published its
    // evidence under a live fence value -- confirm that proof is
    // genuinely usable right now, before racing it.
    hooks.wait_parked().await;
    let proof_before_race = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "raced-publish.txt")
        .unwrap()
        .expect("the publish this worker just made must be usable at the moment it parks");

    // An independent mutator the DAG never saw: bumps the fence AND
    // rewrites the path, entirely outside this attempt's own view.
    let out_path = root.join("raced-publish.txt");
    std::fs::write(&out_path, b"independent-mutator-content").unwrap();
    state
        .replica_coordinator
        .dag_bump_mutation_fence(GROUP, "raced-publish.txt", "independent-mutator")
        .unwrap();

    hooks.resume();
    let _ = handle.await.unwrap();

    let obligation_after = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "raced-publish.txt")
        .unwrap()
        .expect("a raced completion must never close the obligation");
    assert_eq!(
        obligation_after.invalidation_generation, claimed_g,
        "G never moved in this scenario -- the obligation must be left at exactly the \
         generation it was claimed at, proving the refusal came from the live fence \
         mismatch, not a generation check"
    );
    assert_eq!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "raced-publish.txt")
            .unwrap(),
        None,
        "the proof this attempt published is now unusable -- its own fence value no longer \
         equals the path's live fence, which the independent mutator advanced"
    );
    // Sanity: the proof really was different before and after the race,
    // not merely absent both times for an unrelated reason.
    assert!(proof_before_race.filesystem_identity.is_some());
}

/// The zero-work variant of the same race: a worker's identity
/// revalidation passes (the record is usable and its hash matches the
/// freshly resolved desired state), genuinely entering the zero-work
/// branch -- proven here by the path's own inode being unchanged right
/// up to the pause point, since a real materialize would already have
/// rewritten it via a fresh temp+rename before ever reaching this same
/// pause point. Then, before the completion statement runs, an
/// independent mutator bumps the fence and rewrites the path. The
/// completion must still refuse to close -- proving explicitly that
/// 3.16's revalidation could not have caught this (its own stat ran
/// *before* the interleaving mutation) and that the only real
/// guarantee comes from the completion's own live fence re-check. A
/// second, uninterleaved tick afterward must then perform REAL
/// physical work (not another zero-work skip) and succeed, since the
/// record the first attempt would have relied on is no longer usable.
/// Confirmed genuinely RED against an `invalidation_generation`-only
/// completion by temporarily replacing the fence/hash `EXISTS` clause
/// with a tautology: the completion then wrongly closed the obligation
/// despite the independent mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_work_revalidation_raced_by_mutator_cannot_close() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key = SigningKey::from_bytes(&[95u8; 32]);
    let version = symlink_version(1_700_000_700, b"original-target");
    let author = admit_change(&state, "device-a", &key, "raced-zero-work-link", &version);
    seed_projected_row(&state, "raced-zero-work-link", &version, &author);

    let obligation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "raced-zero-work-link")
        .unwrap()
        .expect("admission must have created an obligation");
    let claimed_g = obligation_before.invalidation_generation;

    // Simulate a prior successful cycle, exactly like `zero_work_close_
    // performs_no_physical_work` -- disk and the proof table already
    // agree, entirely independent of anything the worker itself does.
    let out_path = root.join("raced-zero-work-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink("original-target", &out_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("original-target", &out_path).unwrap();
    let identity_at_seed =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    let heads = state.replica_coordinator.sqlite().dag_group_heads(GROUP).unwrap();
    let fence = state
        .replica_coordinator
        .dag_snapshot_mutation_fence(GROUP, "raced-zero-work-link")
        .unwrap();
    let published = state
        .replica_coordinator
        .dag_publish_materialized_generation_if_fence_current(
            GROUP,
            "raced-zero-work-link",
            &heads,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: RecordKind::Symlink,
                version: version.version_hash,
                identity: Box::new(Some(identity_at_seed)),
            },
            fence,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(published, "sanity: the simulated prior-cycle publish must itself succeed");

    let hooks = BeforeCompletionHook::new();
    let engine2 = engine.clone();
    let hooks2 = hooks.clone();
    let handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hooks2).await
    });

    hooks.wait_parked().await;
    // The zero-work branch was genuinely entered: the object's own
    // inode is unchanged since seeding, proving no real write ran
    // between the claim and this pause point.
    let identity_at_pause =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    assert_eq!(
        identity_at_pause.object_id, identity_at_seed.object_id,
        "the worker must have taken the zero-work path -- a real materialize would already \
         have rewritten this object via a fresh temp+rename before reaching this pause point"
    );

    // An independent mutator the DAG never saw: bumps the fence AND
    // rewrites the path out from under the revalidation that already
    // passed.
    std::fs::remove_file(&out_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("independent-mutator-target", &out_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("independent-mutator-target", &out_path).unwrap();
    state
        .replica_coordinator
        .dag_bump_mutation_fence(GROUP, "raced-zero-work-link", "independent-mutator")
        .unwrap();

    hooks.resume();
    let _ = handle.await.unwrap();

    let obligation_after = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "raced-zero-work-link")
        .unwrap()
        .expect("a raced zero-work completion must never close the obligation");
    assert_eq!(
        obligation_after.invalidation_generation, claimed_g,
        "G never moved -- the refusal must come from the live fence mismatch the \
         revalidation's own earlier stat could not have observed, not a generation check"
    );
    let basis_after_race = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "raced-zero-work-link")
        .unwrap();
    assert_eq!(
        basis_after_race, None,
        "the record the zero-work decision relied on is now unusable -- its fence no longer \
         equals the path's live fence"
    );

    // A second, uninterleaved tick must perform REAL physical work
    // this time (the old record is unusable, so there is nothing left
    // to skip against) and actually close.
    let healthy_second_tick = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy_second_tick);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced-zero-work-link")
            .unwrap()
            .is_none(),
        "the second tick must close the obligation via real work"
    );
    let basis_final = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, "raced-zero-work-link")
        .unwrap()
        .expect("the second tick's real materialize must publish a fresh, usable proof");
    let identity_final =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    assert_ne!(
        identity_final.object_id, identity_at_pause.object_id,
        "the second tick's real materialize must have actually rewritten the object -- a \
         fresh inode, not the independent mutator's own leftover one"
    );
    assert_eq!(
        basis_final.filesystem_identity.map(|i| i.object_id),
        Some(identity_final.object_id),
        "the freshly published proof must describe the object the real materialize actually \
         produced"
    );
}

/// The deferred crash-cycle regression: desired state cycles A -> B ->
/// A around a crash that lands strictly between B's physical mutation
/// and its publication/close. The path materializes to A and closes
/// normally; a second admission makes B desired; a mutator (standing
/// in for the worker's own materialize call, immediately before an
/// unmodeled crash) bumps the fence and rewrites disk to B, but the
/// crash means NEITHER the publish NOR the completion for B ever runs;
/// a third admission cycles the desired state back to A. The worker
/// must not read the still-present, hash-matching original A proof as
/// "already satisfied" -- its fence no longer matches (B's mutator
/// moved it), so it must perform a REAL materialize back to A rather
/// than a false zero-work close that would silently leave disk on B
/// forever.
///
/// "With identity revalidation disabled" (this task's own extra
/// requirement) is proven architecturally rather than via a runtime
/// toggle: `dag_zero_work_settlement_if_already_current`'s own code
/// returns `None` the instant `dag_lookup_materialized_generation`
/// reports no usable row, before `revalidate_identity_against_disk` is
/// ever called -- so asserting that lookup already returns `None`
/// right after the third admission (checked explicitly below, before
/// the recovering tick even runs) proves the fence check alone
/// accounts for this, independent of whatever identity revalidation
/// would or would not have separately concluded.
///
/// Confirmed genuinely RED by temporarily replacing `lookup_
/// materialized_generation`'s own fence-join predicate
/// (`g.published_under_mutation_generation = f.mutation_generation`)
/// with a tautology: the stale A proof was then wrongly reported
/// usable immediately after the third admission, exactly reproducing
/// what a "the fence only moves when a publish actually succeeds"
/// implementation would do -- a crashed, unpublished mutation would
/// leave the fence (and thus the old proof's apparent validity)
/// completely untouched, letting a later desired-state cycle-back
/// silently confirm zero work while disk was actually still on B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desired_state_cycling_back_after_a_crash_mid_mutation_does_not_close_with_zero_work() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[96u8; 32]);
    let path = "cycle-link";
    let out_path = root.join(path);

    // A materializes and closes normally.
    let version_a = symlink_version(1_700_000_800, b"content-a");
    let change_a = admit_change(&state, "device-a", &key, path, &version_a);
    assert!(drive_obligations_once_for_test(&engine, 128, 256).await);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, path)
            .unwrap()
            .is_none(),
        "sanity: A must materialize and close normally"
    );
    assert_eq!(std::fs::read_link(&out_path).unwrap().to_str().unwrap().as_bytes(), b"content-a");
    let basis_a = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, path)
        .unwrap()
        .unwrap();

    // A second admission, causally descending from the first, makes B
    // desired. Deliberately never ticked.
    let version_b = symlink_version(1_700_000_801, b"content-b");
    let change_b = create_signed_for_tests(
        vec![change_a.change_hash()],
        change_a.lamport,
        DeviceId("device-a".to_string()),
        FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath(path.to_string()),
            version: version_b.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key,
    );
    state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&change_b, std::slice::from_ref(&version_b))
        .unwrap();

    // Stands in for the worker's own materialize call immediately
    // before an unmodeled crash: the fence is bumped (the established
    // "before the first mutating syscall" ordering) and disk is
    // physically rewritten to B, but the crash means neither the
    // publish nor the completion for B ever runs.
    std::fs::remove_file(&out_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("content-b", &out_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("content-b", &out_path).unwrap();
    state
        .replica_coordinator
        .dag_bump_mutation_fence(GROUP, path, "simulated-crash-write")
        .unwrap();

    // A third admission, causally descending from the second, cycles
    // the desired state back to A.
    let change_a2 = create_signed_for_tests(
        vec![change_b.change_hash()],
        change_b.lamport,
        DeviceId("device-a".to_string()),
        FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath(path.to_string()),
            version: version_a.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key,
    );
    state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&change_a2, std::slice::from_ref(&version_a))
        .unwrap();

    // Architectural proof that the fence check alone rejects the stale
    // A proof, before any identity revalidation could even run.
    assert_eq!(
        state.replica_coordinator.sqlite().dag_lookup_materialized_generation(GROUP, path).unwrap(),
        None,
        "the crash-orphaned A proof must already be unusable via the fence check alone, \
         even though its hash matches the freshly-restored desired state and disk still \
         visibly holds B"
    );

    // The recovering tick must perform REAL work, not a false
    // zero-work close.
    assert!(drive_obligations_once_for_test(&engine, 128, 256).await);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, path)
            .unwrap()
            .is_none(),
        "the obligation must close via real work"
    );
    assert_eq!(
        std::fs::read_link(&out_path).unwrap().to_str().unwrap().as_bytes(),
        b"content-a",
        "disk must end holding A, not the crash-orphaned B a false zero-work close would \
         have silently left behind forever"
    );
    let basis_final = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(GROUP, path)
        .unwrap()
        .unwrap();
    assert_ne!(
        basis_final.generation_id, basis_a.generation_id,
        "a fresh publish from the recovering real materialize, not the original A publish \
         reused"
    );
}

/// The obligation-driven scheduler's own version of the publication
/// race: a lost fence CAS (`Ok(false)`, a perfectly normal outcome, not
/// an error) must never be treated as "this path settled" --
/// `complete_one_obligation` must leave the obligation outstanding for
/// re-resolution, not silently close it, while disk actually holds
/// whatever the independent mutator wrote. The obligation-driven completion path handles
/// this race differently (leaves the row completely untouched rather
/// than an explicit penalized backoff, since it's evidence of
/// legitimate concurrent activity, not a real failure), but the
/// essential property is identical: never falsely mark complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_publication_cas_leaves_the_obligation_outstanding_not_completed() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key = SigningKey::from_bytes(&[97u8; 32]);
    let version = empty_version(1_700_000_900);
    admit_change(&state, "device-a", &key, "obligation-scheduler-race.txt", &version);

    let generation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "obligation-scheduler-race.txt")
        .unwrap()
        .expect("sanity: an obligation must exist after admission")
        .invalidation_generation;

    let hooks = BeforeCompletionHook::new();
    let engine2 = engine.clone();
    let hooks2 = hooks.clone();
    let handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hooks2).await
    });

    // The worker parks only after a real materialize succeeded and is
    // about to publish -- an independent mutator races it here.
    hooks.wait_parked().await;
    let out_path = root.join("obligation-scheduler-race.txt");
    std::fs::write(&out_path, b"independent-mutator-content").unwrap();
    state
        .replica_coordinator
        .dag_bump_mutation_fence(GROUP, "obligation-scheduler-race.txt", "independent-mutator")
        .unwrap();
    hooks.resume();
    let _ = handle.await.unwrap();

    let obligation_after_race = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "obligation-scheduler-race.txt")
        .unwrap()
        .expect(
            "a lost publication CAS must never let the obligation close -- this device can \
             no longer vouch for what disk holds, exactly the race the mutation-fence \
             mechanism exists to detect",
        );
    assert_eq!(
        obligation_after_race.invalidation_generation, generation_before,
        "sanity: no new admission happened here, only an independent disk mutation"
    );
    assert_eq!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "obligation-scheduler-race.txt")
            .unwrap(),
        None,
        "sanity: nothing was actually published under the now-stale fence value"
    );
    assert_eq!(
        std::fs::read(&out_path).unwrap(),
        b"independent-mutator-content",
        "the independent mutator's own content must survive -- the raced worker's publish \
         lost and must not have overwritten it"
    );
}

/// A second candidate session, registered for a test that needs two
/// distinct peer slots so `process_group_via_obligations`'s own
/// rotation window (`MAX_PEERS_PER_TICK = 2`) actually tries a second
/// one -- mirrors `build_state_with_adopted_group`'s own
/// session-construction exactly, under a different device id.
async fn register_second_candidate_session(state: &Arc<DaemonState>, root: &std::path::Path) {
    let deps = crate::peer_orchestrator::peer_sync_session_deps(state);
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("device-local", "device-peer-2").await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer-2".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), root.to_path_buf())]),
        transports,
        Some(state.forward_tx.clone()),
        deps,
    );
    state.peers.register_session("device-peer-2".to_string(), session, state.local_convergence());
}

/// A version whose one content block was never stored anywhere -- both
/// candidates in this test's harness have a block lane nobody serves on
/// the far end, so materializing this version can never
/// succeed via either one, leaving it `RetryRequired` forever. Exists
/// purely to force a tick's rotation to try a SECOND candidate (the
/// first one's own attempt never empties `remaining`).
fn version_with_an_unfetchable_block(mtime: i64) -> FileVersion {
    FileVersion::new(
        vec![yadorilink_replica_domain::file::VersionBlock {
            hash: yadorilink_replica_domain::ids::BlockHash(vec![0x42; 32]),
            size: 4,
        }],
        4,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Both the live job-based scheduler and the obligation-driven worker
/// share this shape: `if remaining.is_empty() { break }`, but the
/// reconcile call handed to the NEXT candidate was the ORIGINAL
/// `budget`, not the shrunk `remaining` -- meaning a path a candidate
/// already settled and closed gets handed to a SECOND candidate again
/// within the very same tick, purely because SOME OTHER path in the
/// budget is still unresolved. Proven here at the obligation-driven
/// worker (the more consequential of the two: a redundant re-attempt
/// there means a real second materialize/publish against a path whose
/// obligation the first attempt already deleted): a fully-resolvable
/// path is settled by the first candidate; an unrelated,
/// permanently-unfetchable path forces the rotation to try a second
/// candidate; `complete_one_obligation`'s own `BeforeCompletionHook`
/// pause must fire EXACTLY ONCE for the settled path this tick, since
/// a correct worker never asks the second candidate to examine it
/// again -- counted directly by racing the hook's pause against the
/// worker task's own completion, rather than inferring it indirectly
/// from published state, since (as an earlier draft of this exact test
/// found) a redundant republish under an unchanged fence is not
/// otherwise distinguishable from a legitimate one by the time the
/// whole tick has already finished. Confirmed genuinely RED by
/// temporarily reverting the reconcile call back to `budget.clone()`:
/// the pause fired twice, once per candidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_path_is_never_handed_to_a_second_candidate_in_the_same_tick() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    register_second_candidate_session(&state, &root).await;
    // `live_authorized_groups` only ever starts from the constructor's
    // one-time snapshot; nothing in this bare unit-test harness performs
    // the ongoing netmap-driven re-validation a running daemon
    // (`run(state)`) would (see `shares_group`'s own doc comment). An
    // earlier draft of this exact test silently ran with only ONE
    // candidate ever authorized -- the very race window this test needs
    // two live candidates to exercise -- until this explicit re-grant
    // was added; it is a direct stand-in for the real netmap grant a
    // live daemon would issue.
    for (_, session) in state.peers.all_sessions() {
        session.grant_group(GROUP);
    }

    let key = SigningKey::from_bytes(&[98u8; 32]);
    admit_change(
        &state,
        "device-a",
        &key,
        "settles-on-first-candidate.txt",
        &empty_version(1_700_001_000),
    );
    admit_change(
        &state,
        "device-a",
        &key,
        "never-resolves.txt",
        &version_with_an_unfetchable_block(1_700_001_001),
    );

    let hooks = BeforeCompletionHook::new();
    let engine2 = engine.clone();
    let hooks2 = hooks.clone();
    let mut handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hooks2).await
    });

    let mut pause_count = 0usize;
    let healthy = loop {
        tokio::select! {
            _ = hooks.wait_parked() => {
                pause_count += 1;
                hooks.resume();
            }
            result = &mut handle => {
                break result.unwrap();
            }
        }
    };
    assert!(healthy);

    assert_eq!(
        pause_count, 1,
        "the settled path's own completion pause must fire exactly once this tick -- a \
         second firing means a second candidate redundantly re-examined a path the first \
         one already closed"
    );
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "settles-on-first-candidate.txt")
            .unwrap()
            .is_none(),
        "sanity: the resolvable path must have closed"
    );
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "never-resolves.txt")
            .unwrap()
            .is_some(),
        "sanity: the unfetchable path must still be outstanding -- this is what forces a \
         second candidate to be tried at all"
    );
}

/// The obligation-driven scheduler's own per-group path-budget rotation
/// (ported from `process_group`'s `MAX_PATHS_PER_RECONCILE_ATTEMPT`
/// windowing): a group with more outstanding paths than one attempt's
/// cap must only have a bounded window resolved per call, with the
/// unresolved remainder picked up by a later call, not handed to
/// `reconcile_paths_directly` all at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn obligation_driven_path_budget_rotation_resolves_the_remainder_on_a_later_call() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[91u8; 32]);
    let path_count = MAX_PATHS_PER_RECONCILE_ATTEMPT + 2;
    for i in 0..path_count {
        let version = empty_version(1_700_000_200 + i as i64);
        admit_change(&state, "device-a", &key, &format!("budget-{i:02}.txt"), &version);
    }

    let closed_count = || {
        (0..path_count)
            .filter(|i| {
                state
                    .replica_coordinator
                    .sqlite()
                    .dag_lookup_projection_obligation(GROUP, &format!("budget-{i:02}.txt"))
                    .unwrap()
                    .is_none()
            })
            .count()
    };

    let healthy_first = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy_first);
    assert_eq!(
        closed_count(),
        MAX_PATHS_PER_RECONCILE_ATTEMPT,
        "exactly one path-budget window's worth of paths must close on the first call"
    );

    let healthy_second = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy_second);
    assert_eq!(
        closed_count(),
        path_count,
        "the remainder must close once the path-budget cursor reaches it on a later call"
    );
}

/// `crate::obligation_tick_metrics`'s counter is a process-wide global
/// shared by the whole test binary -- serializes every test in this module
/// that reads it via `reset()`/`zero_work_attempted()` (a sibling test's own
/// obligation-engine ticks running concurrently would otherwise silently
/// inflate this one's reset-to-read window).
fn tick_metrics_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Regression (128-claim / 8-path zero-work-precheck amplification): before this fix, the zero-work pre-check loop ran
/// over every claimed path (up to the claim limit), even though at
/// most `MAX_PATHS_PER_RECONCILE_ATTEMPT` of them could ever reach a
/// real reconcile attempt the same tick -- an up-to-16x resolution
/// amplification with no throughput benefit. Seeds well more than
/// `MAX_PATHS_PER_RECONCILE_ATTEMPT` runnable obligations (comfortably
/// inside the claim limit) and asserts one scheduler tick attempts a
/// zero-work check for AT MOST `MAX_PATHS_PER_RECONCILE_ATTEMPT` of
/// them, and that repeated ticks eventually rotate through every one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
// Deliberately held across this whole async test's `.await` points: the
// point of this std `Mutex` is to serialize this test against its
// siblings for its ENTIRE body, not just a synchronous prelude (see
// `tick_metrics_test_guard`'s own doc comment). Attribute is on the function,
// not the `let`, because clippy attributes this lint to each await
// point the guard is live across, not to the guard's own binding site.
#[allow(clippy::await_holding_lock)]
async fn zero_work_precheck_examines_at_most_the_path_budget_window_per_tick() {
    let _guard = tick_metrics_test_guard();
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[97u8; 32]);
    const N: usize = MAX_PATHS_PER_RECONCILE_ATTEMPT * 3 + 1;
    for i in 0..N {
        let version = empty_version(1_700_000_500 + i as i64);
        admit_change(&state, "device-a", &key, &format!("precheck-{i:03}.txt"), &version);
    }

    // `crate::obligation_tick_metrics`'s counter is a process-wide global
    // shared by the whole test binary (see `tick_metrics_test_guard`'s own doc
    // comment) -- this file has many OTHER tests driving the
    // obligation engine that do not take that guard, so a strict
    // `<= MAX_PATHS_PER_RECONCILE_ATTEMPT` bound is not reliably
    // reproducible under full concurrent test execution even with the
    // guard held (it only serializes tests that opt in). A tolerance
    // of double the window still separates the bug this pins (the OLD
    // code attempted all N=25 paths every tick) from a HANDFUL of
    // concurrent-sibling-test contributions by a comfortable margin.
    crate::obligation_tick_metrics::reset();
    drive_obligations_once_for_test(&engine, 128, 256).await;
    let attempted_first_tick = crate::obligation_tick_metrics::zero_work_attempted();
    const TOLERANCE: u64 = (MAX_PATHS_PER_RECONCILE_ATTEMPT * 2) as u64;
    assert!(
        attempted_first_tick <= TOLERANCE,
        "one scheduler tick must not zero-work-check meaningfully more than the path-budget \
         window (MAX_PATHS_PER_RECONCILE_ATTEMPT={MAX_PATHS_PER_RECONCILE_ATTEMPT}, \
         tolerance={TOLERANCE}) out of {N} seeded/claimable paths; got {attempted_first_tick} \
         -- the pre-fix behavior attempted all {N}"
    );

    // Every path must still eventually be covered across repeated
    // ticks -- the fix must narrow PER-TICK amplification, not silently
    // drop coverage of the unwindowed remainder.
    let closed_count = |state: &Arc<DaemonState>| {
        (0..N)
            .filter(|i| {
                state
                    .replica_coordinator
                    .sqlite()
                    .dag_lookup_projection_obligation(GROUP, &format!("precheck-{i:03}.txt"))
                    .unwrap()
                    .is_none()
            })
            .count()
    };
    for _ in 0..(N / MAX_PATHS_PER_RECONCILE_ATTEMPT + 2) {
        drive_obligations_once_for_test(&engine, 128, 256).await;
    }
    assert_eq!(
        closed_count(&state),
        N,
        "every seeded path must eventually close across repeated ticks, not just the first \
         tick's windowed subset"
    );
}

/// A genuine `RetryRequired` outcome (an unfetchable block, so
/// `materialize` can never settle the path) must back the obligation
/// off -- not be reclaimed again on the very next tick, which would
/// otherwise spin retrying the identical unreachable fetch as fast as
/// the scheduler loop can tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_genuine_retry_required_outcome_backs_off_instead_of_spinning() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[97u8; 32]);
    admit_change(
        &state,
        "device-a",
        &key,
        "unfetchable.bin",
        &version_with_an_unfetchable_block(1_700_002_000),
    );

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy, "the one, unraced candidate attempt must itself be trustworthy");

    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "unfetchable.bin")
        .unwrap()
        .expect("an unfetchable path must remain outstanding, never falsely closed");
    assert_eq!(obligation.attempt_count, 1, "the failed attempt must be recorded");
    assert!(
        obligation.next_attempt_at > 1_700_002_000,
        "the backoff deadline must be pushed into the future, not left immediately claimable"
    );

    let immediate_reclaim = state
        .replica_coordinator
        .sqlite()
        .dag_claim_runnable_obligations(1_700_002_000, 128, 256)
        .unwrap();
    assert!(
        immediate_reclaim.is_empty(),
        "must not be reclaimable again before its own backoff deadline passes"
    );
}

/// No connected peer at all is a stable condition (it stays true every
/// tick until one connects), not a transient race -- it must back off
/// durably (a real, growing delay, exactly like a genuine `RetryRequired`
/// outcome), never spin at full speed re-checking `candidate_sessions`
/// every tick forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_connected_peer_backs_off_durably_instead_of_spinning() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    state.peers.remove("device-peer");
    let key = SigningKey::from_bytes(&[96u8; 32]);
    admit_change(&state, "device-a", &key, "no-peer.txt", &empty_version(1_700_004_000));

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(!healthy, "no candidate at all must never report a trustworthy audit");

    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "no-peer.txt")
        .unwrap()
        .expect("must remain outstanding with no peer to serve it");
    assert_eq!(
        obligation.attempt_count, 1,
        "no-peer-connected must count as a real failed attempt"
    );
    assert!(
        obligation.next_attempt_at > 1_700_004_000,
        "must be backed off into the future, not left immediately reclaimable"
    );
}

/// `origin_candidate_index_for_obligations` must resolve the path's
/// CURRENT desired-state winner's author, not merely echo whichever
/// device happens to be first in `candidates`. Two candidate sessions
/// are registered ("device-peer", "device-peer-2"); the admitted
/// change's own author id is "device-peer-2", so the resolved winner's
/// `device_id` must match that candidate specifically, regardless of
/// its position in the (alphabetically-sorted) candidate list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origin_first_resolves_the_current_desired_state_winners_author() {
    let (state, _root_dir, root) = build_state_with_adopted_group().await;
    register_second_candidate_session(&state, &root).await;
    for (_, session) in state.peers.all_sessions() {
        session.grant_group(GROUP);
    }

    // The admitted change's author is itself one of the two candidate
    // device ids -- realistic in that the authoring peer is exactly who
    // is most likely to actually hold this content.
    let key = SigningKey::from_bytes(&[95u8; 32]);
    admit_change(&state, "device-peer-2", &key, "origin-test.txt", &empty_version(1_700_005_000));

    let candidates = crate::hydration::candidate_sessions(&state, GROUP);
    assert_eq!(candidates.len(), 2, "sanity: both candidates must be registered");
    let budget: std::collections::BTreeSet<String> = ["origin-test.txt".to_string()].into();
    let origin_index = super::origin_candidate_index_for_obligations(
        &state.local_convergence(),
        GROUP,
        &budget,
        &candidates,
    );
    let origin_index = origin_index.expect("a resolvable winner must produce an origin preference");
    assert_eq!(
        candidates[origin_index].0, "device-peer-2",
        "the origin preference must name the path's actual current-desired-state author"
    );
}

/// Disk-pressure handling is not scheduler-specific machinery to port:
/// `process_group_via_obligations` reaches the exact same `materialize`/
/// `preflight_disk_headroom` path `process_group` does, through the
/// exact same `reconcile_paths_directly` entry point -- so a headroom
/// failure surfaces as an ordinary retriable outcome here too, with no
/// separate disk-space check needed in the scheduler itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_disk_headroom_failure_is_an_ordinary_retriable_outcome_not_a_false_close() {
    let (state, root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let convergence =
        state.peers.convergence("device-peer").expect("sanity: candidate must be registered");
    // An impossible headroom reserve guarantees `check_disk_headroom`
    // rejects every write, standing in for a genuinely full disk.
    // The two knobs the session used to forward to its executor; the
    // executor owns them now, so the test sets them where they live.
    convergence.headroom_enforced.store(true, std::sync::atomic::Ordering::Relaxed);
    *convergence.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner()) = Some(u64::MAX);

    let key = SigningKey::from_bytes(&[94u8; 32]);
    admit_change(&state, "device-a", &key, "no-space.txt", &empty_version(1_700_006_000));

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy, "the candidate attempt itself is trustworthy -- the write failing is not a raced/skipped audit");

    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "no-space.txt")
        .unwrap()
        .expect("a disk-pressure failure must never falsely close the obligation");
    assert_eq!(
        obligation.attempt_count, 1,
        "a real materialize failure must count as a failed attempt"
    );
    assert!(
        obligation.next_attempt_at > 1_700_006_000,
        "must be backed off, exactly like any other genuine RetryRequired outcome"
    );
    assert!(
        !root_dir.path().join("no-space.txt").exists(),
        "sanity: the write must have actually been blocked, not silently succeeded"
    );
}

/// The same disk-pressure block, reached only through production wiring.
///
/// The test above sets the two knobs on the executor directly, which proves
/// the preflight works but not that anything turns it on. Both halves of
/// that wiring have been broken: `147b5a4f` dropped the enforcement flag on
/// the floor, and the governance override never reached this preflight at
/// all. Either one alone silently disables the mechanism while every
/// knob-poking test stays green, so the production path needs its own
/// evidence -- an operator enabling enforcement and configuring a reserve,
/// and nothing else.
///
/// `u64::MAX` keeps this independent of the host's real free space, exactly
/// as the direct-knob test does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disk_pressure_blocks_a_write_when_configured_the_way_an_operator_configures_it() {
    let _env_guard = crate::test_support::CONFIG_ENV_MUTEX.lock().await;
    let config_dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

    let (state, root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    state.governance_config.set_headroom_override_bytes(Some(u64::MAX)).unwrap();
    state.enable_disk_headroom_enforcement();

    // The executor that runs the materialize is the one the *registered
    // session* holds, built when that session was registered -- before this
    // test configured anything. Re-registering with a freshly built executor
    // is what a reconnect does, and is the honest way to test the
    // construction-time decision without reaching into the executor's
    // fields. Production orders this correctly for enforcement (`main.rs`
    // enables it before any peer can connect), but an override changed while
    // a session is live does NOT reach that session's executor -- a narrower
    // staleness question than this test's subject, left to its own evidence.
    let session = state.peers.session("device-peer").expect("sanity: registered above");
    state.peers.register_session("device-peer".to_string(), session, state.local_convergence());

    let key = SigningKey::from_bytes(&[92u8; 32]);
    admit_change(&state, "device-a", &key, "operator-no-space.txt", &empty_version(1_700_006_500));

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy, "the attempt itself is trustworthy -- only the write is refused");

    assert!(
        !root_dir.path().join("operator-no-space.txt").exists(),
        "an operator-configured reserve larger than the disk must stop the materialize"
    );
    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "operator-no-space.txt")
        .unwrap()
        .expect("a disk-pressure refusal must leave the obligation open, not close it");
    assert_eq!(obligation.attempt_count, 1, "the refused write is a failed attempt");

    std::env::remove_var("YADORILINK_CONFIG_DIR");
}

/// A real exact-outcome obligation completion must wake the retirement
/// and hazard-recheck loops -- the SAME reasoning `process_group`'s own
/// post-`Completed` wakes already document (a copy this attempt just
/// made durable could supersede a sibling conflict copy's justification,
/// or be exactly the sibling change that clears some held path's
/// hazard), needed here too since this is the only completion path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_completion_wakes_retirement_and_hazard_recheck() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = ConvergenceEngine::new(state.clone());
    let key = SigningKey::from_bytes(&[93u8; 32]);
    admit_change(&state, "device-a", &key, "wakes-siblings.txt", &empty_version(1_700_007_000));

    assert!(!state.replica_coordinator.retirement_wake().pending().contains_key(GROUP));
    assert!(!state.replica_coordinator.hazard_recheck_wake().pending().contains_key(GROUP));

    let healthy = drive_obligations_once_for_test(&engine, 128, 256).await;
    assert!(healthy);
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "wakes-siblings.txt")
            .unwrap()
            .is_none(),
        "sanity: the obligation must have actually closed"
    );

    assert!(
        state.replica_coordinator.retirement_wake().pending().contains_key(GROUP),
        "a real completion must mark the retirement loop dirty for this group"
    );
    assert!(
        state.replica_coordinator.hazard_recheck_wake().pending().contains_key(GROUP),
        "a real completion must mark the hazard-recheck loop dirty for this group"
    );
}

/// Boundary 1 of 2: group-wide head movement during an attempt. An
/// UNRELATED path moving `dag_group_heads` between the pre-attempt
/// heads read and the post-attempt re-read must not decide whether an
/// ENTIRE `reconcile_paths_directly` attempt's settlements
/// publish/complete or are discarded whole.
///
/// x.txt's own attempt resolves (its desired state/evidence is fully
/// computed) while parked at [`BeforeHeadsAfterHook`] -- the pause
/// point strictly BETWEEN the pre-attempt `heads_before` read and the
/// post-attempt `heads_after` re-read, which [`BeforeCompletionHook`]
/// cannot reach (it only pauses once `before == after` has ALREADY
/// been checked and passed). While parked, an UNRELATED path
/// (`y-unrelated.txt`) is admitted -- a genuinely new historical
/// change, exactly like the two-arm test's own `wait_ready_first`
/// catch-up admitting new changes at ~15/s while B's per-tick
/// `reconcile_paths_directly` calls are in flight -- which moves the
/// group's heads without ever touching x.txt.
///
/// Expected: x.txt's own settlement still closes, because nothing
/// about x.txt itself changed -- the per-path
/// completion CAS (claimed generation/incarnation plus the live
/// mutation fence, exercised by `publication_succeeds_but_later_
/// mutation_before_close_prevents_completion` and `zero_work_
/// revalidation_raced_by_mutator_cannot_close` above) decides
/// currency, not a whole-group heads comparison. A group-wide
/// `before != after` check would discard the WHOLE attempt, including
/// x.txt's own already-resolved settlement, leaving its obligation
/// outstanding for no reason connected to x.txt at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_path_head_movement_must_not_discard_an_already_settled_attempt() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key = SigningKey::from_bytes(&[100u8; 32]);
    admit_change(&state, "device-a", &key, "x.txt", &empty_version(1_700_008_000));

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "x.txt")
            .unwrap()
            .is_some(),
        "sanity: admission must have created an obligation for x.txt"
    );

    let heads_hook = BeforeHeadsAfterHook::new();
    let engine2 = engine.clone();
    let heads_hook2 = heads_hook.clone();
    let handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_heads_hook(&engine2, 128, 256, &heads_hook2).await
    });

    // Parked exactly after x.txt's own attempt resolved, before the
    // group's post-attempt heads re-read.
    heads_hook.wait_parked().await;

    // A genuinely new historical change, touching ONLY an unrelated
    // path -- advances the group's heads without touching x.txt.
    let key_y = SigningKey::from_bytes(&[101u8; 32]);
    admit_change(&state, "device-a", &key_y, "y-unrelated.txt", &empty_version(1_700_008_001));

    heads_hook.resume();
    let _ = handle.await.unwrap();

    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "x.txt")
            .unwrap()
            .is_none(),
        "x.txt's own settlement must close even though an UNRELATED path's admission moved \
         the group's heads during the same reconcile attempt -- an unrelated path's DAG \
         activity must not invalidate a settlement this attempt already resolved for a \
         DIFFERENT path"
    );
}

/// Boundary 2 of 2 (the converse control): proves the per-path completion CAS alone --
/// independent of the heads-stability fence above -- already refuses
/// to close a stale attempt when the SAME path it targets is admitted
/// again while the attempt is in flight. This is the DAG-admission/`G`
/// analogue of `publication_succeeds_but_later_mutation_before_close_
/// prevents_completion` above (which races the live mutation fence
/// `E`, not a DAG admission).
///
/// x2.txt's first attempt is parked at the EXISTING
/// [`BeforeCompletionHook`] -- after publish, immediately before the
/// completion CAS, i.e. strictly AFTER the heads-stability fence
/// already passed, so this scenario cannot be explained by that fence
/// at all. While parked, a SECOND change touching x2.txt itself is
/// admitted, causally descending from the first. The completion CAS
/// must reject: its claimed generation/incarnation token no longer
/// matches x2.txt's now-current row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_path_admission_while_parked_is_independently_rejected_by_generation_cas() {
    let (state, _root_dir, _root) = build_state_with_adopted_group().await;
    let engine = Arc::new(ConvergenceEngine::new(state.clone()));
    let key = SigningKey::from_bytes(&[102u8; 32]);
    let version_x1 = empty_version(1_700_009_000);
    let change_x1 = admit_change(&state, "device-a", &key, "x2.txt", &version_x1);

    let obligation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "x2.txt")
        .unwrap()
        .expect("admission must have created an obligation for x2.txt");
    let claimed_g = obligation_before.invalidation_generation;

    let hooks = BeforeCompletionHook::new();
    let engine2 = engine.clone();
    let hooks2 = hooks.clone();
    let handle = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hooks2).await
    });

    hooks.wait_parked().await;

    // A SECOND change touching the SAME path, causally descending
    // from the first -- the in-flight attempt's own claimed
    // generation is now behind the DAG's current one.
    let version_x2 = empty_version(1_700_009_001);
    let change_x2 = create_signed_for_tests(
        vec![change_x1.change_hash()],
        change_x1.lamport,
        DeviceId("device-a".to_string()),
        FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath("x2.txt".to_string()),
            version: version_x2.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key,
    );
    state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&change_x2, std::slice::from_ref(&version_x2))
        .unwrap();

    hooks.resume();
    let _ = handle.await.unwrap();

    let obligation_after = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "x2.txt")
        .unwrap()
        .expect(
            "the stale attempt must NOT close x2.txt's obligation -- a new admission \
             touching the SAME path while it was in flight must leave it outstanding for \
             re-resolution",
        );
    assert_ne!(
        obligation_after.invalidation_generation, claimed_g,
        "x2.txt's own generation must have moved due to the second admission touching it \
         directly, proving the refusal came from the per-path generation CAS, not the \
         (in this scenario already-passed) heads-stability fence"
    );
}
