//! Proves the writer-freshness re-check that closes the stale-`ChangeAuth`
//! replay hole must cover orphan PROMOTION, not just the ordinary live
//! per-Change admission path (`authenticate_incoming_change` in
//! `yadorilink-peer-session`).
//!
//! A `Change` only ever buffers in the `orphan_changes` table AFTER it has
//! already passed live admission once, at RECEIPT time (see `dag_store::
//! orphan_integrity`'s own module doc comment) -- so a fix confined to that
//! one live-admission call site is not enough on its own: an attacker can
//! deliberately withhold an intermediate DAG parent so their Change buffers
//! as an orphan instead of being immediately admitted or rejected, then get
//! it durably promoted LATER -- including via `init_dag_schema`'s startup
//! self-heal sweep, which runs before any daemon-level policy/trust could
//! possibly have loaded -- on the strength of a freshness check that was
//! only ever run once, back when the row was first buffered.
//!
//! This file drives `yadorilink_sync_sqlite::dag_store`/`ChangeHistoryRepository`
//! directly rather than through a real two-daemon network session (unlike
//! `viewer_editor_authorization_end_to_end.rs`): the scenario needs precise
//! control over exactly which Change bodies land in the store and in what
//! order, which the real live-admission pipeline (whose whole job is
//! authenticating and ordering exactly this) does not let a test dictate.
//! `restart_node` (`support::topology`) is the closest existing pattern for
//! simulating a genuine daemon restart (reopening the SAME on-disk database
//! into a fresh `DaemonState`); this file inlines the same
//! `ReplicaCoordinator::open`-on-the-same-path shape directly rather than
//! pulling in the full multi-node topology harness, which this scenario
//! does not otherwise need.

mod support;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_daemon::change_policy::policy_signing::{
    grant_record_at_epoch, revoke_record_at_epoch,
};
use yadorilink_daemon::change_policy::{verify_group_policy_log, GroupPolicyLog, WriterRole};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};

const GROUP_ID: &str = "orphan-freshness-group";
const HONEST_DEVICE: &str = "device-honest";

/// Builds a real signed 3-record policy chain for `GROUP_ID`: seq 1 grants
/// `author_device_id` Editor; seq 2 (epoch 1) revokes it; seq 3 (epoch 1)
/// re-grants it at `final_role`. Returns the verified `GroupPolicyState`
/// (device is `final_role` NOW) alongside seq 1's own record hash and the
/// author's fingerprint -- the coordinates a Change pinned to the ORIGINAL
/// Editor grant needs to reference a real, correctly-bound historical
/// record, exactly the property the stale-pin exploit relies on.
fn build_downgraded_policy_chain(
    authority: &SigningKey,
    author_device_id: &str,
    author_fingerprint: [u8; 32],
    final_role: WriterRole,
) -> (yadorilink_daemon::change_policy::GroupPolicyState, ChangeAuth) {
    let grant = grant_record_at_epoch(
        authority,
        GROUP_ID,
        1,
        [0u8; 32],
        0,
        author_device_id,
        author_fingerprint,
        WriterRole::Editor,
    );
    let grant_hash: [u8; 32] = grant.record_hash.as_slice().try_into().unwrap();
    let original_auth = ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: grant_hash };

    let revoke = revoke_record_at_epoch(authority, GROUP_ID, 2, grant_hash, 1, author_device_id);
    let revoke_hash: [u8; 32] = revoke.record_hash.as_slice().try_into().unwrap();
    let regrant = grant_record_at_epoch(
        authority,
        GROUP_ID,
        3,
        revoke_hash,
        1,
        author_device_id,
        author_fingerprint,
        final_role,
    );
    let final_hash = regrant.record_hash.clone();

    let log = GroupPolicyLog {
        group_id: GROUP_ID.to_string(),
        current_seq: 3,
        current_epoch: 1,
        policy_head: final_hash,
        records: vec![grant, revoke, regrant],
    };
    let policy = verify_group_policy_log(&authority.verifying_key().to_bytes(), &log).unwrap();
    (policy, original_auth)
}

/// A single Editor-only grant chain (no downgrade) -- the control case
/// proving the resweep mechanism itself actually promotes a legitimate
/// orphan once its parent is present, not merely that it refuses one.
fn build_still_editor_policy(
    authority: &SigningKey,
    author_device_id: &str,
    author_fingerprint: [u8; 32],
) -> (yadorilink_daemon::change_policy::GroupPolicyState, ChangeAuth) {
    let grant = grant_record_at_epoch(
        authority,
        "orphan-freshness-control-group",
        1,
        [0u8; 32],
        0,
        author_device_id,
        author_fingerprint,
        WriterRole::Editor,
    );
    let grant_hash: [u8; 32] = grant.record_hash.as_slice().try_into().unwrap();
    let auth = ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: grant_hash };
    let log = GroupPolicyLog {
        group_id: "orphan-freshness-control-group".to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: grant_hash.to_vec(),
        records: vec![grant],
    };
    let policy = verify_group_policy_log(&authority.verifying_key().to_bytes(), &log).unwrap();
    (policy, auth)
}

fn new_daemon(
    device_id: &str,
    db_path: &std::path::Path,
    store_root: &std::path::Path,
) -> Arc<DaemonState> {
    let store = Arc::new(FsBlockStore::new(store_root).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(db_path).unwrap());
    DaemonState::new(device_id.to_string(), sync_state, store)
}

/// The RED-proof-shaped scenario the orphan-promotion freshness check exists
/// for: a Change from a since-downgraded author, buffered as an orphan
/// because its parent was
/// withheld, must NOT get durably promoted once the withheld parent finally
/// arrives -- neither in the live hot path, nor via `init_dag_schema`'s
/// startup self-heal sweep across a simulated restart, nor via the
/// deferred-promotion resweep that runs once real (but still-downgraded)
/// trust becomes available again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn since_downgraded_authors_withheld_parent_orphan_is_never_promoted_across_restart() {
    support::ensure_isolated_config_dir();
    let authority = SigningKey::from_bytes(&[11u8; 32]);
    let author_fingerprint = [22u8; 32];

    let (downgraded_policy, original_auth) = build_downgraded_policy_chain(
        &authority,
        "device-writer",
        author_fingerprint,
        WriterRole::Viewer,
    );

    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.sqlite3");
    let store_dir = tempfile::tempdir().unwrap();

    let state = new_daemon(HONEST_DEVICE, &db_path, store_dir.path());
    state.replace_group_policy_states(std::collections::HashMap::from([(
        GROUP_ID.to_string(),
        downgraded_policy,
    )]));

    // The withheld intermediate parent P, and the malicious/stale child X
    // that names it -- both "authored" by device-writer while it was
    // genuinely Editor (auth_seq 1), signed with an arbitrary local key
    // (dag_store::admit_change trusts the caller already authenticated the
    // Change -- see its own doc comment -- so this test constructs the
    // exact post-authentication buffered-orphan precondition directly,
    // rather than re-driving the whole live-admission pipeline).
    let local_signing = SigningKey::from_bytes(&[33u8; 32]);
    let parent = Change::create_signed(
        vec![],
        0,
        original_auth,
        DeviceId("device-writer".into()),
        FolderGroupId(GROUP_ID.into()),
        vec![Op::Delete { path: SyncPath("withheld-parent.bin".into()) }],
        &local_signing,
    );
    let child = Change::create_signed(
        vec![parent.compute_hash()],
        parent.lamport,
        original_auth,
        DeviceId("device-writer".into()),
        FolderGroupId(GROUP_ID.into()),
        vec![Op::Delete { path: SyncPath("stale-orphan-child.bin".into()) }],
        &local_signing,
    );

    let repo = state.replica_coordinator.change_history_repository();
    let child_outcome = repo.dag_admit_change_with_versions(&child, &[], false).unwrap();
    assert_eq!(
        child_outcome.outcome,
        yadorilink_sync_sqlite::dag_store::AdmitOutcome::Orphaned,
        "the child must buffer as an orphan: its parent has been deliberately withheld"
    );
    assert!(!repo.dag_has_change(&child.compute_hash()).unwrap());

    // The withheld parent finally arrives, admitted directly through the
    // SAME real production path (`ChangeHistoryRepository::
    // dag_admit_change_with_versions` -> `dag_store::
    // admit_change_with_orphan_writer_check` -> `promote_orphans`) live
    // admission uses -- this is the hot-path half of the check: no
    // restart at all yet, and the orphan must still not promote, because
    // device-writer is a Viewer at THIS device's current policy state.
    let parent_outcome = repo.dag_admit_change_with_versions(&parent, &[], false).unwrap();
    assert_eq!(parent_outcome.outcome, yadorilink_sync_sqlite::dag_store::AdmitOutcome::Applied);
    assert!(
        !repo.dag_has_change(&child.compute_hash()).unwrap(),
        "the orphan must NOT be promoted by admitting its parent while its author is a CURRENT \
         Viewer, even though the orphan's own pin (auth_seq 1) names a real, once-valid Editor \
         grant"
    );
    assert!(
        repo.dag_has_change_or_buffered_orphan(&child.compute_hash()).unwrap(),
        "the orphan must remain buffered (deferred), not be dropped outright -- a later re-grant \
         could still legitimately make it promotable"
    );

    // Simulate a restart: drop this generation's DaemonState/ReplicaCoordinator
    // entirely and reopen the SAME on-disk database -- exactly
    // `support::topology::restart_node`'s own shape. `init_dag_schema`'s
    // startup self-heal sweep runs here with ZERO trust material loaded (no
    // `DaemonState` has wired a real writer-freshness check onto this fresh
    // `ReplicaCoordinator` yet) -- it must defer, never promote.
    drop(state);
    let state = new_daemon(HONEST_DEVICE, &db_path, store_dir.path());
    let repo = state.replica_coordinator.change_history_repository();
    assert!(
        !repo.dag_has_change(&child.compute_hash()).unwrap(),
        "init_dag_schema's startup self-heal sweep must NEVER promote a buffered orphan -- it \
         runs before any policy/trust material could possibly be loaded, so it must always defer"
    );
    assert!(
        repo.dag_has_change_or_buffered_orphan(&child.compute_hash()).unwrap(),
        "the orphan must survive the restart still buffered, not be lost"
    );

    // Now simulate the coordination plane re-sending the SAME (still
    // downgraded) policy chain shortly after reconnect -- exactly what
    // `peer_orchestrator::record_group_policy_states` installs on a real
    // netmap frame -- and the resweep that call site triggers right after.
    state.replace_group_policy_states(std::collections::HashMap::from([(
        GROUP_ID.to_string(),
        build_downgraded_policy_chain(
            &authority,
            "device-writer",
            author_fingerprint,
            WriterRole::Viewer,
        )
        .0,
    )]));
    repo.resweep_deferred_orphan_promotions().unwrap();
    assert!(
        !repo.dag_has_change(&child.compute_hash()).unwrap(),
        "the deferred-promotion resweep must still refuse to promote the orphan once real trust \
         IS available, because that real trust confirms device-writer is no longer a current \
         writer -- this is the actual proof the exploit is closed even across a restart"
    );
}

/// Control proving the resweep mechanism above is not simply a permanent
/// no-op: an orphan from an author who is STILL a current writer, deferred
/// by the self-heal sweep for lack of trust at startup exactly like the
/// downgraded scenario above, DOES get promoted once the resweep runs with
/// real (permissive) trust available.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn still_current_writers_orphan_is_promoted_by_the_resweep_once_trust_is_available() {
    support::ensure_isolated_config_dir();
    let authority = SigningKey::from_bytes(&[44u8; 32]);
    let author_fingerprint = [55u8; 32];
    let control_group = "orphan-freshness-control-group";
    let (policy, auth) =
        build_still_editor_policy(&authority, "device-writer-2", author_fingerprint);

    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.sqlite3");
    let store_dir = tempfile::tempdir().unwrap();
    let state = new_daemon(HONEST_DEVICE, &db_path, store_dir.path());

    let local_signing = SigningKey::from_bytes(&[66u8; 32]);
    let parent = Change::create_signed(
        vec![],
        0,
        auth,
        DeviceId("device-writer-2".into()),
        FolderGroupId(control_group.into()),
        vec![Op::Delete { path: SyncPath("control-parent.bin".into()) }],
        &local_signing,
    );
    let child = Change::create_signed(
        vec![parent.compute_hash()],
        parent.lamport,
        auth,
        DeviceId("device-writer-2".into()),
        FolderGroupId(control_group.into()),
        vec![Op::Delete { path: SyncPath("control-child.bin".into()) }],
        &local_signing,
    );

    // Buffer the child as an orphan and land the parent BEFORE any policy
    // is installed at all (no `DaemonState` has wired the writer-check
    // yet, matching the pre-trust-loaded window a real restart leaves) via
    // a bare append, not `admit_change` -- exactly the "crash between
    // append_change and promote_orphans" self-heal seed shape
    // `already_satisfied_parents` exists for.
    let repo = state.replica_coordinator.change_history_repository();
    let child_outcome = repo.dag_admit_change_with_versions(&child, &[], false).unwrap();
    assert_eq!(child_outcome.outcome, yadorilink_sync_sqlite::dag_store::AdmitOutcome::Orphaned);
    let parent_outcome = repo.dag_admit_change_with_versions(&parent, &[], false).unwrap();
    assert_eq!(parent_outcome.outcome, yadorilink_sync_sqlite::dag_store::AdmitOutcome::Applied);
    // No policy loaded yet (Bootstrap), so the writer-check answers `None`
    // (defer) for this group too -- the orphan must still be buffered, not
    // promoted, purely for lack of trust, not because device-writer-2 is
    // unauthorized.
    assert!(!repo.dag_has_change(&child.compute_hash()).unwrap());

    // Trust becomes available: install the verified (still-Editor) policy
    // and resweep -- this must now promote the deferred orphan.
    state.replace_group_policy_states(std::collections::HashMap::from([(
        control_group.to_string(),
        policy,
    )]));
    let promoted = repo.resweep_deferred_orphan_promotions().unwrap();
    assert_eq!(
        promoted,
        vec![child.compute_hash()],
        "the resweep must promote a legitimate orphan once real trust confirms its author is \
         still a current writer -- proving the freshness gate defers rather than permanently \
         blocking, and that the resweep mechanism itself actually works"
    );
    assert!(repo.dag_has_change(&child.compute_hash()).unwrap());
}
