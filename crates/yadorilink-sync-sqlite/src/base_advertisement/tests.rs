use rusqlite::Connection;
use yadorilink_replica_domain::base_negotiation::{AdvertisedBase, BaseAdvertisement};
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, FolderGroupId};
use yadorilink_replica_domain::rebootstrap::{Checkpoint, HistoryBase, HistoryEpoch};
use yadorilink_replica_engine::rebootstrap_snapshot::{RebootstrapSnapshot, SnapshotAuthorState};

use super::*;

const GROUP: &str = "group-base-advertisement";

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::dag_store::init_dag_schema(&conn).unwrap();
    yadorilink_sqlite_runtime::init_schema(&conn).unwrap();
    conn
}

fn author(device: &str, watermark: u64, tip: u8) -> SnapshotAuthorState {
    SnapshotAuthorState {
        device_id: device.to_owned(),
        watermark: AuthorSeq(watermark),
        tip_change_hash: ChangeHash([tip; 32]),
    }
}

/// Seals a base over an empty frontier the way a local compaction commits
/// one, carrying `author_state` as its summary.
fn seal(conn: &Connection, author_state: Vec<SnapshotAuthorState>, ceiling: u64) -> Checkpoint {
    let group = FolderGroupId(GROUP.into());
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        author_state,
        Vec::new(),
        ceiling,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(group, Vec::new(), snapshot.snapshot_hash());
    let tx = conn.unchecked_transaction().unwrap();
    crate::rebootstrap_store::commit_compaction_snapshot(&tx, &checkpoint, &snapshot, &[]).unwrap();
    tx.commit().unwrap();
    checkpoint
}

#[test]
fn a_group_with_no_base_advertises_its_original_history() {
    let conn = open();
    let advertisement = local_base_advertisement(&conn, GROUP).unwrap();
    assert_eq!(advertisement.epoch(), HistoryEpoch::Genesis);
    assert_eq!(advertisement.summary(), None);
    assert_eq!(advertisement.snapshot(), None);
    assert!(advertisement.active_heads.is_empty());
}

/// The advertisement names the installed base, carries the checkpoint it
/// derives from, and identifies the summary that base persisted -- and it
/// survives its own wire encoding, so what a peer decodes is what was
/// meant.
#[test]
fn an_installed_base_is_advertised_with_its_checkpoint_and_summary() {
    let conn = open();
    let authors = vec![author("device-b", 3, 0x22), author("device-a", 5, 0x11)];
    let checkpoint = seal(&conn, authors, 9);

    let advertisement = local_base_advertisement(&conn, GROUP).unwrap();
    assert_eq!(
        advertisement.epoch(),
        HistoryEpoch::Base(HistoryBase::from_checkpoint(&checkpoint))
    );
    match &advertisement.base {
        AdvertisedBase::Installed { checkpoint: advertised, summary } => {
            assert_eq!(**advertised, checkpoint);
            let persisted = crate::rebootstrap_store::history_base_summary(&conn, GROUP)
                .unwrap()
                .expect("the base carries a summary");
            assert_eq!(*summary, summary_identity(&persisted));
        }
        other => panic!("expected an installed base, got {other:?}"),
    }
    assert_eq!(BaseAdvertisement::decode(&advertisement.encode()).unwrap(), advertisement);
}

/// Two summaries that differ only in an author's position must not share
/// an identity -- otherwise a peer could stand on the same base with a
/// different summary and pass for agreeing.
#[test]
fn the_summary_identity_moves_with_the_summary_and_not_with_its_row_order() {
    let conn = open();
    seal(&conn, vec![author("device-a", 5, 0x11), author("device-b", 3, 0x22)], 9);
    let summary = crate::rebootstrap_store::history_base_summary(&conn, GROUP).unwrap().unwrap();

    let mut reordered = summary.clone();
    reordered.author_state.reverse();
    assert_eq!(summary_identity(&summary), summary_identity(&reordered));

    let mut advanced = summary.clone();
    advanced.author_state[0].watermark = AuthorSeq(6);
    assert_ne!(summary_identity(&summary), summary_identity(&advanced));

    let mut later = summary;
    later.lamport_ceiling += 1;
    assert_ne!(summary_identity(&later), summary_identity(&advanced));
}

/// A base whose checkpoint row is gone cannot be advertised: advertising
/// the base without the checkpoint would claim a snapshot identity this
/// device can no longer show.
#[test]
fn a_base_without_its_checkpoint_fails_closed() {
    let conn = open();
    seal(&conn, vec![author("device-a", 1, 0x11)], 1);
    conn.execute("DELETE FROM change_checkpoints WHERE group_id = ?1", [GROUP]).unwrap();
    let error = local_base_advertisement(&conn, GROUP).unwrap_err();
    assert!(matches!(error, SyncSqliteError::CorruptState(_)), "{error}");
}
