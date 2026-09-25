#![cfg(test)]
//! The Lamport clock resumes above the history an installed base absorbed.
//!
//! A base carries `L`, the greatest Lamport value its replaced history
//! reached. A change on the base is a descendant of that whole history,
//! so it is clocked from `L` as well as from its own parents: an epoch
//! root takes `L + 1`, and a change with parents takes
//! `max(L, max parent Lamport) + 1`. Heads are ranked by
//! `(lamport, change_hash)`, and a clock that restarted at the base would
//! rank a change written after the seal below history the seal absorbed.

use super::base_install_tests::open;
use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};

const GROUP: &str = "group-base-anchored-lamport";
/// Well above anything the frontier carries: the absorbed history reached
/// it through a change the base no longer keeps.
const CEILING: u64 = 40;

fn a_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

struct InstalledBase {
    epoch: HistoryEpoch,
}

fn install_base(conn: &mut Connection) -> InstalledBase {
    let group = FolderGroupId(GROUP.to_string());
    let frontier = Change::create_signed(
        Vec::new(),
        0,
        DeviceId("device-a".to_string()),
        AuthorSeq(1),
        None,
        group.clone(),
        HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath("gone.txt".to_string()) }],
        &a_key(),
    );
    assert!(frontier.lamport < CEILING);
    let frontier_hash = frontier.compute_hash();
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        vec![frontier.to_wire_bytes()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: "device-a".to_string(),
            watermark: frontier.author_seq,
            tip_change_hash: frontier_hash,
        }],
        Vec::new(),
        CEILING,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(group, vec![frontier_hash], snapshot.snapshot_hash());
    let tx = conn.transaction().unwrap();
    install_base_for_tests(&tx, &checkpoint, &snapshot).unwrap();
    tx.commit().unwrap();
    InstalledBase { epoch: HistoryEpoch::Base(HistoryBase::from_checkpoint(&checkpoint)) }
}

/// A first change by `device-b` on the base, clocked as if the greatest
/// Lamport value it had seen were `clocked_from`.
fn b_change(base: &InstalledBase, parents: Vec<ChangeHash>, clocked_from: u64) -> Change {
    Change::create_signed(
        parents,
        clocked_from,
        DeviceId("device-b".to_string()),
        AuthorSeq(1),
        None,
        FolderGroupId(GROUP.to_string()),
        base.epoch,
        vec![Op::Delete { path: SyncPath("b.txt".to_string()) }],
        &SigningKey::from_bytes(&[13u8; 32]),
    )
}

fn applied(conn: &Connection, change: &Change) -> bool {
    matches!(
        crate::dag_store::admit_change(conn, change),
        Ok(result) if result.outcome == crate::dag_store::AdmitOutcome::Applied
    )
}

#[test]
fn an_epoch_root_resumes_the_clock_above_the_base() {
    let mut conn = open();
    let base = install_base(&mut conn);

    let root = b_change(&base, Vec::new(), CEILING);
    assert_eq!(root.lamport, CEILING + 1);
    assert!(applied(&conn, &root), "an epoch root is clocked one above the base's ceiling");
}

#[test]
fn an_epoch_root_clocked_from_zero_is_not_admitted() {
    let mut conn = open();
    let base = install_base(&mut conn);

    let restarted = b_change(&base, Vec::new(), 0);
    assert!(
        !applied(&conn, &restarted),
        "a root that restarts the clock would rank below history the base absorbed"
    );
    assert!(!crate::dag_store::has_change(&conn, &restarted.compute_hash()).unwrap());
}

#[test]
fn a_local_change_on_an_installed_base_is_clocked_above_the_ceiling() {
    let mut conn = open();
    install_base(&mut conn);

    let version = FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    crate::dag_store::put_file_version(&conn, GROUP, &version).unwrap();
    let emitter = ChangeEmitter::new("device-a", a_key());
    let emitted = crate::dag_store::emit_local_change(
        &conn,
        GROUP,
        vec![Op::Put {
            path: SyncPath("local.txt".to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter,
    )
    .unwrap();
    assert_eq!(emitted.lamport, CEILING + 1);
}

/// The startup revalidation of retained history clocks a change on the
/// installed base from the same floor admission did, so a change admitted
/// above the ceiling still reads as sound when the store is reopened.
#[test]
fn a_change_clocked_above_the_ceiling_survives_the_startup_revalidation() {
    let mut conn = open();
    let base = install_base(&mut conn);
    let root = b_change(&base, Vec::new(), CEILING);
    assert!(applied(&conn, &root));

    crate::dag_store::init_dag_schema(&conn)
        .expect("retained history on the installed base revalidates against the base's floor");
    assert!(crate::dag_store::has_change(&conn, &root.compute_hash()).unwrap());
}
