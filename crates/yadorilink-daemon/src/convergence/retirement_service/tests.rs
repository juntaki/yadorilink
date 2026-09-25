#![cfg(test)]

/// `DaemonState` holds no reference to a local executor.
///
/// The executor holds this state as its root-commit authority and its
/// pending-change flush, so caching one on the state would make the state
/// own something that owns the state. Each call therefore builds a fresh
/// executor, and this is what makes re-introducing a cache visible.
///
/// Stated as "a distinct allocation each time" rather than as "the daemon
/// is droppable", which it is not: a `DaemonState` is already retained by
/// the background tasks `new` spawns, with or without this. That is a real
/// pre-existing lifecycle issue and a separate one — this test would pass
/// vacuously if it tried to assert droppability, and fail for a reason
/// that has nothing to do with the executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_holds_no_reference_to_a_local_executor() {
    use std::sync::Arc;

    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(
        crate::replica_coordinator::ReplicaCoordinator::open(db_dir.path().join("index.db"))
            .unwrap(),
    );
    let state = crate::daemon_state::DaemonState::new("device-local".into(), coordinator, store);

    let first = state.local_convergence();
    let second = state.local_convergence();
    assert!(
        !Arc::ptr_eq(&first, &second),
        "a cached executor would be a reference cycle through this state"
    );
}

use super::*;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_root_authority::root_identity::VerifiedRoot;

const GROUP_A: &str = "group-a";
const GROUP_B: &str = "group-b";

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

/// `GROUP_A` is fully adopted (link + verified root + startup-ready),
/// with one already-live candidate `PeerSyncSession` registered for it
/// -- standing in for a real peer that connected before this tick, the
/// precondition `reconcile_group`'s guard needs in order to avoid
/// constructing anything at all.
///
/// `GROUP_B` is linked but otherwise unrelated to the call under test,
/// with its own already-live candidate session (standing in for "some
/// OTHER already-connected session") and one retained change authored
/// by a device id this process can never resolve a signing key for --
/// not the local device, no netmap pin, no `signing_keys.json` pin.
/// `NetmapChangeAuthenticator::signing_key` therefore returns `None`
/// for it, so re-validating `GROUP_B`'s retained history deterministically
/// hits `AuthenticatedHistoryError::TrustUnavailable` -- the exact
/// transient condition `reconcile_group`'s own doc comment describes,
/// forced here instead
/// of relying on a flaky real SQLite/trust-material timing window.
async fn build_state_with_two_linked_groups() -> (
    Arc<DaemonState>,
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<PeerSyncSession>,
    Arc<PeerSyncSession>,
) {
    let root_a_dir = tempfile::tempdir().unwrap();
    let root_b_dir = tempfile::tempdir().unwrap();
    let root_a = root_a_dir.path().canonicalize().unwrap();
    let root_b = root_b_dir.path().canonicalize().unwrap();
    let replica_coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let block_store =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());

    replica_coordinator.link_repository().add_link(&root_a.to_string_lossy(), GROUP_A).unwrap();
    VerifiedRoot::open(&root_a, GROUP_A, replica_coordinator.as_ref()).unwrap();
    let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP_A);
    replica_coordinator.startup_readiness().mark_group_ready(GROUP_A, generation);

    replica_coordinator.link_repository().add_link(&root_b.to_string_lossy(), GROUP_B).unwrap();

    let build = DaemonState::build("device-local".to_string(), replica_coordinator, block_store);
    let state = build.state;
    state.test_root_commit_authorities.lock().unwrap().insert(
        GROUP_A.to_string(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );

    let key = SigningKey::from_bytes(&[77u8; 32]);
    let version = empty_version(1_700_002_000);
    let bystander_change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-untrusted-for-hazard-test".to_string()),
        FolderGroupId(GROUP_B.to_string()),
        vec![Op::Put {
            path: SyncPath("bystander.txt".to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key,
    );
    state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&bystander_change, std::slice::from_ref(&version))
        .unwrap();

    let deps_a = crate::peer_orchestrator::peer_sync_session_deps(&state);
    let (transports_a, _peer_transports_a) =
        crate::test_support::session_transports_pair("device-local", "device-peer-a").await;
    let peer_store_a = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine_a = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store_a.clone(),
    );
    let session_a = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer-a".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_a,
        peer_store_a,
        vec![GROUP_A.to_string()],
        HashMap::from([(GROUP_A.to_string(), root_a.clone())]),
        transports_a,
        Some(state.forward_tx.clone()),
        deps_a,
    );
    let session_a_handle = session_a.clone();
    state.peers.register_session("device-peer-a".to_string(), session_a, state.local_convergence());

    let deps_b = crate::peer_orchestrator::peer_sync_session_deps(&state);
    let (transports_b, _peer_transports_b) =
        crate::test_support::session_transports_pair("device-local", "device-peer-b").await;
    let peer_store_b = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine_b = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store_b.clone(),
    );
    let session_b = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer-b".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_b,
        peer_store_b,
        vec![GROUP_B.to_string()],
        HashMap::from([(GROUP_B.to_string(), root_b.clone())]),
        transports_b,
        Some(state.forward_tx.clone()),
        deps_b,
    );
    let session_b_handle = session_b.clone();
    state.peers.register_session("device-peer-b".to_string(), session_b, state.local_convergence());

    // `peer_orchestrator::peer_sync_session_deps` itself constructs a
    // fresh `NetmapChangeAuthenticator` on EVERY call (see its own doc
    // comment/field) -- so
    // each of the two `peer_sync_session_deps` calls above already ran
    // a full `validate_linked_history_best_effort` sweep as an
    // ordinary, expected side effect of constructing a session at all.
    // In a real daemon that sweep's `restore_group_sessions_if_
    // currently_authorized` re-grants a session only when the current
    // netmap says it's still a writer; this bare unit-test harness
    // wires no netmap "writer" membership at all, so that re-grant
    // never fires and a session built before a LATER session merely
    // ends up revoked of its own group as an artifact of setup
    // ordering -- nothing to do with the hazard this test exercises.
    // Re-grant both sessions their own group explicitly (the same
    // stand-in `convergence::engine`'s own
    // `a_settled_path_is_never_handed_to_a_second_candidate_in_the_
    // same_tick` test uses for an identical harness gap) so the test
    // starts from "both already-connected sessions are authorized",
    // and the one assertion that matters is entirely about what
    // `reconcile_group` itself does next.
    session_a_handle.grant_group(GROUP_A);
    session_b_handle.grant_group(GROUP_B);

    (state, root_a_dir, root_b_dir, session_a_handle, session_b_handle)
}

/// The hazard this guards against: `reconcile_group`'s target
/// (`GROUP_A`) already has a live candidate session, so this call must
/// construct no session at all -- and therefore
/// must never trigger `NetmapChangeAuthenticator::new`'s linked-history
/// re-validation sweep, which would hit `GROUP_B`'s unresolvable-author
/// change and quarantine `GROUP_B`'s own already-connected session even
/// though nothing about `GROUP_B` was ever asked for.
///
/// This once happened for real: reconciling a group unconditionally
/// built a session for it, and `GROUP_B`'s live session lost its
/// authorization as a side effect of reconciling a completely different
/// group. Building a session as a side effect of local work is no longer
/// possible -- there is nothing to build one from -- so this now guards
/// against reintroducing the shape rather than against the bug itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_group_never_quarantines_an_unrelated_groups_live_session() {
    let (state, _root_a_dir, _root_b_dir, session_a, bystander_session) =
        build_state_with_two_linked_groups().await;

    assert!(
        session_a.shares_group(GROUP_A),
        "sanity: group-a's own live candidate session starts authorized"
    );
    assert!(bystander_session.shares_group(GROUP_B), "sanity: group-b's session starts authorized");

    let service = ConvergenceRetirementService::new(state.clone());
    service.reconcile_group(GROUP_A).await.expect("reconciling group-a must not itself error");

    assert!(
        bystander_session.shares_group(GROUP_B),
        "reconciling group-a must never quarantine group-b's own already-connected \
         session -- group-a already had a live candidate session, so `local_retirement_\
         session` (whose first-ever construction re-validates EVERY linked group's \
         retained history) must never have been constructed at all"
    );
}
