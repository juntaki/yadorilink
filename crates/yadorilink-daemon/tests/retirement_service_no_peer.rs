//! `ConvergenceRetirementService` regression coverage for Commit 3 of the
//! retirement-scheduler correctness effort: retirement's own decision is
//! driven entirely by this device's local DAG/file-index/disk state, never
//! by which (if any) peer session happens to be connected -- see
//! `DaemonState::local_retirement_session`'s own doc comment. Every test
//! here runs with ZERO peer sessions ever registered (no `connect_two_
//! daemons`/`connect_mesh` call anywhere), proving the property
//! structurally, not just by absence of a `candidate_sessions()` call in
//! the source.
//!
//! Conflict/history state is fabricated by admitting hand-crafted `Change`s
//! directly through `change_history_repository()`, the same technique
//! `yadorilink-peer-session`'s own
//! `audit_retires_an_ephemeral_conflict_copy_once_its_loser_window_closes`
//! test uses -- no second live device or session is needed to produce a
//! genuine DAG conflict, since concurrency is a property of the parent
//! graph, not of wall-clock timing or network delivery.

mod support;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use support::{ensure_device_signing_key, open_file_backed_replica_coordinator};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::convergence::retirement_service::ConvergenceRetirementService;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_peer_session::peer_session::RetirementAttempt;
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};

const GROUP: &str = "retirement-no-peer";

struct Device {
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

fn setup_device(device_id: &str) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    // Real root adoption (marker + persisted token) -- `retire_conflict_
    // copies_only`'s eventual `materialize` call verifies it exactly like
    // any other peer-applied mutation would (`peer_replica_state.rs`'s
    // `verify_root`), so a synthetic/skipped adoption would make every
    // scenario below fail on that check rather than the retirement
    // decision this file actually tests.
    LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string()).unwrap();
    Device { state, root, _store_dir: store_dir, _index_dir: index_dir }
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn empty_version(mtime: i64) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        },
    )
}

fn admit(
    device: &Device,
    device_id: &str,
    signing_key: &SigningKey,
    path: &str,
    version: &FileVersion,
) -> Change {
    let change = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId(device_id.into()),
        FolderGroupId(GROUP.into()),
        vec![Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        signing_key,
    );
    device
        .state
        .replica_coordinator
        .change_history_repository()
        .dag_admit_change_with_versions(&change, std::slice::from_ref(version), true)
        .unwrap();
    change
}

/// Indexes a live, empty copy-shaped file at `path` and writes the matching
/// (empty) bytes to disk -- the precondition every scenario below shares:
/// "this device already materialized a conflict copy", the state
/// `retire_unjustified_ephemeral_conflict_copies` audits. `authoring_change`
/// only needs to reference SOME change already admitted for this group --
/// the schema's `files_require_authoring_identity_on_insert` trigger only
/// checks that the hash resolves to a real row in `changes`, not that the
/// change's own ops touch `path` (that carried-by-history relationship is
/// what `dag_group_history_paths` -- derived from `Op::Put`, not this
/// column -- separately decides for retirement's own history check).
fn plant_copy(device: &Device, path: &str, authoring_change: &Change) {
    let record = FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            GROUP,
            &record,
            &device.state.device_id,
            &authoring_change.compute_hash(),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    std::fs::write(device.root.path().join(path), b"").unwrap();
}

fn is_live(device: &Device, path: &str) -> bool {
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, path)
        .unwrap()
        .is_some_and(|r| !r.deleted)
}

fn assert_no_peer_sessions(device: &Device) {
    assert!(
        device.state.peers.sessions_for_group(GROUP).is_empty(),
        "these tests must prove retirement works with zero connected peer sessions"
    );
}

/// No live loser at all (a single, uncontested winner for "shared.bin"): no
/// resolution ever lists a conflict copy for it, so a copy-shaped file
/// indexed under that base path is unjustified from the start. Never
/// carried by any admitted change either, so it must retire.
#[tokio::test]
async fn no_peer_sessions_retires_an_unjustified_ephemeral_copy() {
    support::ensure_isolated_config_dir();
    let device = setup_device("device-solo");
    let change_w = admit(&device, "device-w", &key(1), "shared.bin", &empty_version(1_000));

    let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
        "shared.bin",
        "device-l",
        1_001,
        &[9u8; 32],
    );
    plant_copy(&device, &copy_path, &change_w);
    assert_no_peer_sessions(&device);

    let outcome = ConvergenceRetirementService::new(device.state.clone())
        .reconcile_group(GROUP)
        .await
        .unwrap();
    assert_eq!(outcome, RetirementAttempt::Settled { retired: 1 });
    assert!(!is_live(&device, &copy_path), "the unjustified copy's index row must not remain live");
    assert!(
        !device.root.path().join(&copy_path).exists(),
        "the unjustified copy must be removed from disk"
    );
}

/// A genuine concurrent pair on "shared.bin": the loser is still live, so
/// its conflict copy is justified by the CURRENT frontier and must be
/// retained even though nothing carries it in history yet (matching
/// `retire_unjustified_ephemeral_conflict_copies`'s own "still-live loser"
/// case).
#[tokio::test]
async fn no_peer_sessions_retains_a_currently_justified_copy() {
    support::ensure_isolated_config_dir();
    let device = setup_device("device-solo");
    let version_w = empty_version(1_000);
    let version_l = empty_version(1_001);
    let change_w = admit(&device, "device-a", &key(1), "shared.bin", &version_w);
    let change_l = admit(&device, "device-b", &key(2), "shared.bin", &version_l);

    let (loser_device_id, loser_version) =
        if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
            change_w.lamport,
            &change_w.compute_hash().0,
            change_l.lamport,
            &change_l.compute_hash().0,
        ) {
            ("device-a", &version_w)
        } else {
            ("device-b", &version_l)
        };
    let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
        "shared.bin",
        loser_device_id,
        loser_version.meta.mtime_unix_nanos,
        &loser_version.version_hash.0,
    );
    plant_copy(&device, &copy_path, &change_w);
    assert_no_peer_sessions(&device);

    let outcome = ConvergenceRetirementService::new(device.state.clone())
        .reconcile_group(GROUP)
        .await
        .unwrap();
    assert_eq!(outcome, RetirementAttempt::Settled { retired: 0 });
    assert!(
        is_live(&device, &copy_path),
        "a copy still justified by a live loser must survive the audit"
    );
    assert!(device.root.path().join(&copy_path).exists(), "the justified copy must remain on disk");
}

/// The copy-shaped path itself is directly carried by an admitted change
/// (a user file that happens to match the copy-shaped naming convention,
/// or a durable carrier from the retroactive repair loop) -- retirement's
/// own history check must retain it regardless of whether the resolver
/// would otherwise call it unjustified.
#[tokio::test]
async fn no_peer_sessions_retains_a_dag_carried_copy_shaped_path() {
    support::ensure_isolated_config_dir();
    let device = setup_device("device-solo");
    admit(&device, "device-w", &key(1), "shared.bin", &empty_version(1_000));

    let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
        "shared.bin",
        "device-l",
        1_001,
        &[9u8; 32],
    );
    // Directly carried: an admitted change's own op targets the copy-shaped
    // path, exactly like a real user file that happens to match the naming
    // convention.
    let carrier = admit(&device, "device-w", &key(1), &copy_path, &empty_version(1_002));
    plant_copy(&device, &copy_path, &carrier);
    assert_no_peer_sessions(&device);

    let outcome = ConvergenceRetirementService::new(device.state.clone())
        .reconcile_group(GROUP)
        .await
        .unwrap();
    assert_eq!(outcome, RetirementAttempt::Settled { retired: 0 });
    assert!(is_live(&device, &copy_path), "a DAG-carried copy-shaped path must never be retired");
    assert!(
        device.root.path().join(&copy_path).exists(),
        "the DAG-carried path must remain on disk"
    );
}
