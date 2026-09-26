#![cfg(test)]
//! Sealing a group's history: the summary a seal carries, what it must
//! hold before it may happen, and where every author stands after it.

use super::base_install_tests::open;
use super::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{
    FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::{create_signed_for_tests, reset_author_sequences};
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathResolution};

pub(super) const GROUP: &str = "group-seal";

pub(super) fn version(seed: u8) -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 1_000 + seed as i64,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

pub(super) fn key(device: &str) -> SigningKey {
    SigningKey::from_bytes(&[device.as_bytes()[device.len() - 1]; 32])
}

pub(super) fn put(path: &str, version: &FileVersion) -> Op {
    Op::Put {
        path: SyncPath(path.to_string()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    }
}

pub(super) fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.to_string()) }
}

/// Admits a change on the group's original history by `device`, parented
/// on exactly `parents`.
pub(super) fn admit(conn: &Connection, device: &str, parents: &[&Change], ops: Vec<Op>) -> Change {
    let change = create_signed_for_tests(
        parents.iter().map(|parent| parent.compute_hash()).collect(),
        parents.iter().map(|parent| parent.lamport).max().unwrap_or(0),
        DeviceId(device.to_string()),
        FolderGroupId(GROUP.to_string()),
        ops,
        &key(device),
    );
    let outcome = crate::dag_store::admit_change(conn, &change).unwrap().outcome;
    assert!(
        matches!(outcome, crate::dag_store::AdmitOutcome::Applied),
        "fixture change must be admissible, got {outcome:?}"
    );
    change
}

/// Authors a change the way this device's own emission does: on the
/// group's current frontier and epoch, from the author's stored position.
pub(super) fn emit(conn: &Connection, device: &str, ops: Vec<Op>) -> Change {
    crate::dag_store::emit_local_change(conn, GROUP, ops, &ChangeEmitter::new(device, key(device)))
        .unwrap()
}

/// Publishes every retained change of the group that is not published
/// yet, under one authorization checkpoint numbered `checkpoint`.
pub(super) fn publish_everything(conn: &Connection, checkpoint: u8) {
    let unpublished: Vec<ChangeHash> = {
        let mut stmt = conn
            .prepare(
                "SELECT c.change_hash FROM changes c WHERE c.group_id = ?1 AND NOT EXISTS \
                 (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = c.change_hash)",
            )
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0)).unwrap();
        rows.map(|row| ChangeHash(row.unwrap().try_into().unwrap())).collect()
    };
    let entries: Vec<(ChangeHash, Vec<u8>)> =
        unpublished.into_iter().map(|hash| (hash, b"proof".to_vec())).collect();
    crate::dag_store::published_view::attach_authorization_evidence(
        conn,
        &[checkpoint; 32],
        GROUP,
        "device-a",
        checkpoint as u64,
        b"checkpoint",
        b"signature",
        &[7; 32],
        &entries,
    )
    .unwrap();
}

fn file_row(
    tx: &rusqlite::Transaction<'_>,
    path: &str,
    version: &FileVersion,
    author: &ChangeHash,
    deleted: bool,
) {
    crate::file_index::upsert_file_in_tx(
        tx,
        GROUP,
        &FileRecord {
            path: path.to_string(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: Vec::new(),
            deleted,
        },
        "device-a",
        Some(author),
    )
    .unwrap();
}

/// Brings the file rows up to what the live heads resolve to, conflict
/// copies included, and settles every projection obligation -- what the
/// projection engine does once it has caught up.
pub(super) fn project(conn: &Connection) {
    let paths: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT DISTINCT path FROM path_live_heads WHERE group_id = ?1").unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, String>(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    let tx = conn.unchecked_transaction().unwrap();
    for path in paths {
        let heads = crate::dag_store::live_path_heads(&tx, GROUP, &path).unwrap();
        let version_of = |index: usize| {
            let hash = heads[index].content.as_ref().unwrap().version_hash;
            crate::dag_store::get_file_version(&tx, GROUP, &VersionHash(hash)).unwrap().unwrap()
        };
        match resolve_path_heads(&path, &heads) {
            PathResolution::Present { winner, conflict_copies } => {
                file_row(
                    &tx,
                    &path,
                    &version_of(winner),
                    &ChangeHash(heads[winner].change_hash),
                    false,
                );
                for copy in conflict_copies {
                    let head = &heads[copy.head];
                    file_row(
                        &tx,
                        &copy.path,
                        &version_of(copy.head),
                        &ChangeHash(head.change_hash),
                        false,
                    );
                }
            }
            PathResolution::Absent => {
                let existing: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT size, mtime_unix_nanos FROM files \
                         WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                        [GROUP, path.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .unwrap();
                if let Some((size, mtime_unix_nanos)) = existing {
                    let removed = FileVersion::new(
                        Vec::new(),
                        size as u64,
                        FileMeta {
                            mtime_unix_nanos,
                            unix_mode: None,
                            symlink_target: None,
                            record_kind: RecordKind::File,
                            xattrs: Vec::new(),
                        },
                    );
                    file_row(&tx, &path, &removed, &ChangeHash(heads[0].change_hash), true);
                }
            }
        }
    }
    tx.execute("DELETE FROM projection_obligations WHERE group_id = ?1", [GROUP]).unwrap();
    tx.commit().unwrap();
}

/// Stores every version the fixtures write, as local capture does before
/// a change naming one is authored. A seal keeps only the versions its
/// base still needs, so this runs again before authoring above one.
pub(super) fn store_versions(conn: &Connection) {
    for seed in 1..=9 {
        crate::dag_store::put_file_version(conn, GROUP, &version(seed)).unwrap();
    }
}

pub(super) struct History {
    pub(super) a1: Change,
    pub(super) a2: Change,
    pub(super) a3: Change,
    pub(super) b1: Change,
    pub(super) b2: Change,
    pub(super) c1: Change,
}

/// A history with every shape a seal must carry exactly:
///
/// * `p`: `A1` and `B1` write identical bytes concurrently, and `A2`
///   deletes `p` descending from `A1` only. `B1` survives: the two writes
///   were two heads, not one.
/// * `r`: `A3` and `B2` write different bytes concurrently, a genuine
///   conflict with a conflict copy.
/// * `q`: `C1` descends everything, so the frontier is `C1` alone and every
///   head above is one the seal prunes.
pub(super) fn build_history(conn: &Connection) -> History {
    reset_author_sequences();
    store_versions(conn);
    let a1 = admit(conn, "device-a", &[], vec![put("p", &version(1))]);
    let b1 = admit(conn, "device-b", &[], vec![put("p", &version(1))]);
    let a2 = admit(conn, "device-a", &[&a1], vec![delete("p")]);
    let a3 = admit(conn, "device-a", &[&a2], vec![put("r", &version(2))]);
    let b2 = admit(conn, "device-b", &[&b1], vec![put("r", &version(3))]);
    let c1 = admit(conn, "device-c", &[&a3, &b2], vec![put("q", &version(4))]);
    publish_everything(conn, 1);
    project(conn);
    History { a1, a2, a3, b1, b2, c1 }
}

fn position(device: &str, change: &Change) -> SnapshotAuthorState {
    SnapshotAuthorState {
        device_id: device.to_string(),
        watermark: change.author_seq,
        tip_change_hash: change.compute_hash(),
    }
}

fn head(path: &str, change: &Change) -> SnapshotPathHead {
    let content = yadorilink_replica_engine::conflict::path_head_from_change(change, path)
        .and_then(|head| head.content)
        .expect("a content head");
    SnapshotPathHead {
        path: path.to_string(),
        change_hash: change.compute_hash(),
        device_id: change.device_id.as_str().to_string(),
        author_seq: change.author_seq,
        lamport: change.lamport,
        version_hash: VersionHash(content.version_hash),
        naming_device_id: change.device_id.as_str().to_string(),
    }
}

pub(super) fn sorted(mut summary: GroupHistorySummary) -> GroupHistorySummary {
    summary.author_state.sort();
    summary.path_heads.sort();
    summary
}

pub(super) fn seal(conn: &Connection) -> VerifiedSeal {
    let tx = conn.unchecked_transaction().unwrap();
    let seal = seal_group(&tx, GROUP).unwrap();
    tx.commit().unwrap();
    seal
}

pub(super) fn refusal(result: Result<VerifiedSeal, SyncSqliteError>) -> SealRefusal {
    match result {
        Err(SyncSqliteError::SealRefused { group_id, refusal }) => {
            assert_eq!(group_id, GROUP);
            refusal
        }
        Err(other) => panic!("expected a seal refusal, got {other}"),
        Ok(seal) => panic!("expected a seal refusal, got a seal of {:?}", seal.history_base()),
    }
}

/// Every author this replica holds is anchored on `base`, at the position
/// the base carries.
pub(super) fn assert_every_author_anchored_on(conn: &Connection, base: HistoryBase) {
    for author in crate::dag_store::author_chain::all_author_state(conn, GROUP).unwrap() {
        let state =
            crate::dag_store::author_chain::author_chain_state(conn, GROUP, &author.device_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            state.anchored_on,
            Some(base),
            "{} must resume from the sealed base, not from a tip it absorbed",
            author.device_id
        );
    }
}

/// A seal carries `Q = (W, L, Gamma)` exactly: every author's position,
/// the greatest Lamport reached, and every live content head -- two heads
/// that wrote the same bytes stay two heads. Once committed, every author
/// resumes from the new base: its next change names no predecessor, sits
/// at the next sequence, and clocks from the carried ceiling.
#[test]
fn a_seal_commits_the_exact_summary_and_anchors_every_author_on_the_new_base() {
    let conn = open();
    let h = build_history(&conn);

    let sealed = seal(&conn);

    let expected = GroupHistorySummary {
        author_state: vec![
            position("device-a", &h.a3),
            position("device-b", &h.b2),
            position("device-c", &h.c1),
        ],
        path_heads: vec![head("p", &h.b1), head("q", &h.c1), head("r", &h.a3), head("r", &h.b2)],
        lamport_ceiling: h.c1.lamport,
    };
    assert_eq!(sorted(sealed.summary()), sorted(expected.clone()));
    assert!(
        !sealed.summary().path_heads.iter().any(|head| head.change_hash == h.a1.compute_hash()),
        "A1 was superseded on p by A2's delete"
    );
    assert_eq!(sealed.frontier(), &[h.c1.compute_hash()]);
    let mut absorbed: Vec<ChangeHash> =
        [&h.a1, &h.a2, &h.a3, &h.b1, &h.b2, &h.c1].iter().map(|c| c.compute_hash()).collect();
    absorbed.sort();
    assert_eq!(sealed.absorbed(), absorbed);

    let base = sealed.history_base();
    assert_eq!(history_base(&conn, GROUP).unwrap(), Some(base));
    assert_eq!(
        sorted(history_base_summary(&conn, GROUP).unwrap().unwrap()),
        sorted(expected),
        "the installed base carries exactly the sealed summary"
    );
    assert_eq!(
        crate::base_advertisement::local_base_advertisement(&conn, GROUP).unwrap().summary(),
        Some(sealed.summary_identity()),
        "the base advertises the summary it was sealed with"
    );
    assert_every_author_anchored_on(&conn, base);

    store_versions(&conn);
    let next = emit(&conn, "device-a", vec![put("t", &version(5))]);
    assert_eq!(next.history_epoch, HistoryEpoch::Base(base));
    assert_eq!(next.author_seq.get(), h.a3.author_seq.get() + 1);
    assert_eq!(next.author_prev, None, "the first change on a base names no predecessor");
    assert_eq!(next.lamport, h.c1.lamport + 1);
}

/// A second seal describes the whole history, not only the epoch above
/// the first base. A path the first base carried and nobody touched since
/// keeps the heads that base carried; a path rewritten above it takes the
/// new head; a path deleted above it has none; and the ceiling and every
/// position continue from where the first base left them.
#[test]
fn a_second_seal_carries_the_whole_history_not_only_the_epoch_above_the_first() {
    let conn = open();
    let h = build_history(&conn);
    let first = seal(&conn);
    store_versions(&conn);

    let a4 = emit(&conn, "device-a", vec![put("p", &version(6))]);
    let b3 = emit(&conn, "device-b", vec![delete("q")]);
    publish_everything(&conn, 2);
    project(&conn);

    let second = seal(&conn);

    let expected = GroupHistorySummary {
        author_state: vec![
            position("device-a", &a4),
            position("device-b", &b3),
            position("device-c", &h.c1),
        ],
        path_heads: vec![head("p", &a4), head("r", &h.a3), head("r", &h.b2)],
        lamport_ceiling: b3.lamport,
    };
    assert_eq!(sorted(second.summary()), sorted(expected));
    assert_ne!(second.history_base(), first.history_base());
    assert_every_author_anchored_on(&conn, second.history_base());

    store_versions(&conn);
    let next = emit(&conn, "device-c", vec![put("u", &version(7))]);
    assert_eq!(next.history_epoch, HistoryEpoch::Base(second.history_base()));
    assert_eq!(next.author_seq.get(), 2);
    assert_eq!(next.author_prev, None);
    assert_eq!(next.lamport, b3.lamport + 1);
}

/// The current row a path's removal leaves behind is authored by the
/// removal, which the base absorbs without carrying it as a head: a
/// deleted path has none. The row is still one the base carries, so the
/// sealed group opens again.
#[test]
fn a_group_sealed_after_a_path_was_deleted_opens_again() {
    let conn = open();
    build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    let b3 = emit(&conn, "device-b", vec![delete("q")]);
    publish_everything(&conn, 2);
    project(&conn);
    let tombstone_author: Vec<u8> = conn
        .query_row(
            "SELECT authoring_change_hash FROM files \
             WHERE group_id = ?1 AND path = 'q' AND state = 'current' AND deleted = 1",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tombstone_author, b3.compute_hash().0.to_vec());

    let sealed = seal(&conn);

    assert!(
        !sealed.summary().path_heads.iter().any(|head| head.path == "q"),
        "a deleted path carries no head"
    );
    yadorilink_sqlite_runtime::init_schema(&conn).expect("the sealed group opens again");
}

/// A conflict copy stays a current row after the path it was copied from
/// is rewritten. The rewrite names only the version shown at the path, so
/// the losing head -- the copy's author, which the rewrite was never shown
/// there -- stays a head of the path beside it. A second seal that absorbs
/// the rewrite carries both heads and the copy, so the group opens again.
#[test]
fn a_group_sealed_after_a_conflicted_path_was_rewritten_opens_again() {
    fn copy_author(conn: &Connection) -> Vec<u8> {
        conn.query_row(
            "SELECT authoring_change_hash FROM files \
             WHERE group_id = ?1 AND path LIKE 'r %' AND state = 'current'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap()
    }

    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    let copied_by = copy_author(&conn);
    let a4 = emit(&conn, "device-a", vec![put("r", &version(6))]);
    publish_everything(&conn, 2);
    project(&conn);
    assert_eq!(copy_author(&conn), copied_by, "the copy stays current");

    let sealed = seal(&conn);

    let r_heads: BTreeSet<ChangeHash> = sealed
        .summary()
        .path_heads
        .iter()
        .filter(|head| head.path == "r")
        .map(|head| head.change_hash)
        .collect();
    assert!([h.a3.compute_hash().0.to_vec(), h.b2.compute_hash().0.to_vec()].contains(&copied_by));
    let loser = ChangeHash(copied_by.as_slice().try_into().unwrap());
    assert_eq!(r_heads, BTreeSet::from([a4.compute_hash(), loser]));
    yadorilink_sqlite_runtime::init_schema(&conn).expect("the resealed group opens again");
}

/// A seal is planned from this replica's history alone. A device that has
/// acknowledged nothing does not hold it back: that device returns with a
/// history of its own, and the two are merged by summary.
#[test]
fn a_seal_does_not_wait_for_a_device_that_has_acknowledged_nothing() {
    let conn = open();
    let h = build_history(&conn);
    let plan = plan_seal(&conn, GROUP).unwrap();
    assert!(plan.blocking_devices.is_empty());
    assert_eq!(plan.checkpoint_frontier, vec![h.c1.compute_hash()]);
    assert_eq!(plan.pruned.len(), 5, "everything below the frontier is absorbed");

    seal(&conn);
}

/// Sealing twice with nothing written in between would only restate the
/// base already installed.
#[test]
fn a_seal_with_nothing_above_the_installed_base_is_refused() {
    let conn = open();
    build_history(&conn);
    seal(&conn);

    assert_eq!(refusal(prepare_seal(&conn, GROUP)), SealRefusal::NothingToSeal);
}

#[test]
fn a_seal_waits_for_projection_to_catch_up() {
    let conn = open();
    build_history(&conn);
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &conn,
        GROUP,
        &["q"],
        1,
    )
    .unwrap();

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::ProjectionPending { path: "q".to_string() }
    );
}

/// A losing content class must be durable state -- a conflict copy the
/// snapshot carries -- before the history that holds it may be sealed.
#[test]
fn a_seal_waits_for_every_conflict_copy_to_be_durable() {
    let conn = open();
    build_history(&conn);
    let copy_path: String = conn
        .query_row(
            "SELECT path FROM files WHERE group_id = ?1 AND path LIKE 'r (%'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute("DELETE FROM files WHERE group_id = ?1 AND path = ?2", [GROUP, &copy_path])
        .unwrap();

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::ConflictCopyNotDurable { path: "r".to_string(), copy_path }
    );
}

#[test]
fn a_seal_waits_for_the_winner_to_be_materialized() {
    let conn = open();
    build_history(&conn);
    conn.execute("DELETE FROM files WHERE group_id = ?1 AND path = 'q'", [GROUP]).unwrap();

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::WinnerNotMaterialized { path: "q".to_string() }
    );
}

/// An admitted change that is not published yet has not produced its
/// files, so a snapshot taken now would disagree with the summary.
#[test]
fn a_seal_waits_for_every_admitted_change_to_be_published() {
    let conn = open();
    let h = build_history(&conn);
    let d1 = admit(&conn, "device-d", &[&h.c1], vec![put("s", &version(8))]);
    project(&conn);

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::UnpublishedChange { change: d1.compute_hash() }
    );
}

#[test]
fn a_seal_refuses_to_absorb_a_change_another_subsystem_retains() {
    let conn = open();
    let h = build_history(&conn);
    crate::dag_store::register_retention_root(
        &conn,
        "test-owner",
        "owner-1",
        GROUP,
        &h.a2.compute_hash(),
        crate::dag_store::RetentionClass::CausalStub,
    )
    .unwrap();

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::RetentionRootHeld { change: h.a2.compute_hash() }
    );
}

/// A current row the snapshot cannot carry -- its authoring change has no
/// authorization evidence here -- would silently vanish from the base.
#[test]
fn a_seal_refuses_a_current_row_it_cannot_carry() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    emit(&conn, "device-c", vec![put("s", &version(8))]);
    publish_everything(&conn, 2);
    project(&conn);
    // `p` is still the row B1 wrote; its evidence is gone.
    conn.execute(
        "DELETE FROM change_authorization WHERE change_hash = ?1",
        [&h.b1.compute_hash().0[..]],
    )
    .unwrap();

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::FileWithoutEvidence { path: "p".to_string() }
    );
}

/// The author positions the store maintains are what the base will hand
/// every author as its next position, so they must be what the retained
/// changes say, not merely what the table says.
#[test]
fn a_seal_refuses_author_positions_its_history_does_not_attain() {
    let conn = open();
    build_history(&conn);
    conn.execute(
        "UPDATE author_chain_state SET watermark = watermark + 1 \
         WHERE group_id = ?1 AND device_id = 'device-c'",
        [GROUP],
    )
    .unwrap();

    assert!(matches!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::SummaryDisagreesWithHistory { .. }
    ));
}

/// The head sets the store maintains must be the causally maximal content
/// of the retained changes themselves.
#[test]
fn a_seal_refuses_head_sets_its_history_does_not_produce() {
    let conn = open();
    build_history(&conn);
    conn.execute("DELETE FROM path_live_heads WHERE group_id = ?1 AND path = 'r'", [GROUP])
        .unwrap();

    assert!(matches!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::SummaryDisagreesWithHistory { .. }
    ));
}

/// Two live heads of one path by one author means the basis a write is
/// parented on was not the path's current one. The summary's bound on
/// concurrent heads rests on that, so such a history is not sealed.
#[test]
fn a_seal_refuses_two_live_heads_of_one_path_by_one_author() {
    let conn = open();
    let h = build_history(&conn);
    // Parented beside, not on, A3's write of r.
    admit(&conn, "device-a", &[&h.b2], vec![put("r", &version(9))]);
    publish_everything(&conn, 3);
    project(&conn);

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::TwoHeadsFromOneAuthor { path: "r".to_string(), device_id: "device-a".into() }
    );
}

/// A change retained from before the installed base, beyond the position
/// the base carried for its author, is history the base does not describe
/// and a replica installing it fresh cannot obtain.
#[test]
fn a_seal_refuses_a_retained_change_the_installed_base_does_not_carry() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    emit(&conn, "device-b", vec![put("s", &version(8))]);
    let stray = Change::create_signed(
        vec![h.c1.compute_hash()],
        h.c1.lamport,
        DeviceId("device-a".to_string()),
        yadorilink_replica_domain::ids::AuthorSeq(h.a3.author_seq.get() + 1),
        Some(h.a3.compute_hash()),
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Genesis,
        vec![put("stray", &version(9))],
        &key("device-a"),
    );
    // Retained as if kept across the install, without going through
    // admission, which would refuse it as another history.
    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, author_seq, lamport, encoded, authenticated_header) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &stray.compute_hash().0[..],
            GROUP,
            "device-a",
            stray.author_seq.get() as i64,
            stray.lamport as i64,
            stray.to_wire_bytes(),
            stray.authenticated_header_encoding(),
        ],
    )
    .unwrap();
    publish_everything(&conn, 2);
    project(&conn);

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::RetainedChangeOutsideBase { change: stray.compute_hash() }
    );
}

/// A change above a base supersedes a head the base carried only by naming
/// it among its observed base heads, whatever its DAG parents say: a base
/// head is no DAG node here. A write to a path the base carried that names
/// nothing leaves the base's head live beside it, in the path frontier as
/// in the summary; a later write that names it replaces it, and the next
/// seal carries only that write.
#[test]
fn a_write_above_a_base_replaces_the_head_the_base_carried_only_by_naming_it() {
    let conn = open();
    let h = build_history(&conn);
    let first = seal(&conn);
    store_versions(&conn);
    let live_at_q = |conn: &Connection| -> BTreeSet<ChangeHash> {
        crate::dag_store::live_path_heads(conn, GROUP, "q")
            .unwrap()
            .into_iter()
            .map(|head| ChangeHash(head.change_hash))
            .collect()
    };
    let d1 = yadorilink_replica_domain::test_authoring::create_signed_on_base_for_tests(
        Vec::new(),
        h.c1.lamport,
        DeviceId("device-d".to_string()),
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(first.history_base()),
        vec![put("q", &version(8))],
        &key("device-d"),
    );
    let outcome = crate::dag_store::admit_change(&conn, &d1).unwrap().outcome;
    assert!(matches!(outcome, crate::dag_store::AdmitOutcome::Applied), "got {outcome:?}");
    assert_eq!(
        live_at_q(&conn),
        BTreeSet::from([h.c1.compute_hash(), d1.compute_hash()]),
        "the head the base carried stands beside a write that did not name it"
    );

    let d2 = yadorilink_replica_domain::test_authoring::create_signed_observing_on_base_for_tests(
        vec![d1.compute_hash()],
        d1.lamport,
        DeviceId("device-d".to_string()),
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(first.history_base()),
        vec![h.c1.compute_hash()],
        vec![put("q", &version(9))],
        &key("device-d"),
    );
    let outcome = crate::dag_store::admit_change(&conn, &d2).unwrap().outcome;
    assert!(matches!(outcome, crate::dag_store::AdmitOutcome::Applied), "got {outcome:?}");
    assert_eq!(live_at_q(&conn), BTreeSet::from([d2.compute_hash()]));
    publish_everything(&conn, 2);
    project(&conn);

    let second = seal(&conn);

    let q_heads: Vec<ChangeHash> = second
        .summary()
        .path_heads
        .iter()
        .filter(|head| head.path == "q")
        .map(|head| head.change_hash)
        .collect();
    assert_eq!(q_heads, vec![d2.compute_hash()]);
}

/// An author with nothing written above the installed base resumes from
/// the base, and its stored anchor has to say so.
#[test]
fn a_seal_refuses_an_author_anchored_somewhere_its_history_does_not_put_it() {
    let conn = open();
    build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    emit(&conn, "device-a", vec![put("s", &version(8))]);
    publish_everything(&conn, 2);
    project(&conn);
    conn.execute(
        "UPDATE author_chain_state SET anchor_base = NULL \
         WHERE group_id = ?1 AND device_id = 'device-c'",
        [GROUP],
    )
    .unwrap();

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::AuthorAnchorInconsistent { device_id: "device-c".to_string() }
    );
}

/// The changes an author wrote above the base must continue the base's
/// position without a gap. A base sealed over a gap would hand the author
/// a watermark covering a change nobody holds.
#[test]
fn a_seal_refuses_an_author_chain_with_a_gap() {
    let conn = open();
    let h = build_history(&conn);
    let first = seal(&conn);
    store_versions(&conn);
    let a4 = emit(&conn, "device-a", vec![put("s", &version(8))]);
    let skipped = Change::create_signed(
        vec![a4.compute_hash()],
        a4.lamport,
        DeviceId("device-a".to_string()),
        yadorilink_replica_domain::ids::AuthorSeq(h.a3.author_seq.get() + 3),
        Some(a4.compute_hash()),
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(first.history_base()),
        vec![put("gap", &version(9))],
        &key("device-a"),
    );
    // Retained without going through admission, which would hold it until
    // the missing position arrived.
    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, author_seq, lamport, encoded, authenticated_header) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &skipped.compute_hash().0[..],
            GROUP,
            "device-a",
            skipped.author_seq.get() as i64,
            skipped.lamport as i64,
            skipped.to_wire_bytes(),
            skipped.authenticated_header_encoding(),
        ],
    )
    .unwrap();
    publish_everything(&conn, 2);
    project(&conn);

    assert!(matches!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::AuthorChainBroken { device_id, .. } if device_id == "device-a"
    ));
}

/// The base a seal produces derives from a checkpoint whose snapshot hash
/// covers the summary, so two seals that differ only in `W`, `L` or
/// `Gamma` are two different bases.
#[test]
fn the_sealed_base_is_bound_to_the_summary_it_carries() {
    let conn = open();
    build_history(&conn);
    let sealed = prepare_seal(&conn, GROUP).unwrap();
    let snapshot = sealed.snapshot().clone();
    let base_with = |author_state: Vec<SnapshotAuthorState>,
                     path_heads: Vec<SnapshotPathHead>,
                     lamport_ceiling: u64| {
        let altered = RebootstrapSnapshot::new(
            snapshot.group_id.clone(),
            snapshot.files.clone(),
            snapshot.frontier_changes.clone(),
            snapshot.file_versions.clone(),
            snapshot.published_change_witnesses.clone(),
            snapshot.boundary_parent_auth.clone(),
            author_state,
            path_heads,
            lamport_ceiling,
        )
        .unwrap();
        HistoryBase::from_checkpoint(&Checkpoint::new(
            snapshot.group_id.clone(),
            sealed.frontier().to_vec(),
            altered.snapshot_hash(),
        ))
    };

    assert_eq!(
        base_with(
            snapshot.author_state.clone(),
            snapshot.path_heads.clone(),
            snapshot.lamport_ceiling
        ),
        sealed.history_base()
    );
    assert_ne!(
        base_with(
            snapshot.author_state.clone(),
            snapshot.path_heads.clone(),
            snapshot.lamport_ceiling + 1
        ),
        sealed.history_base(),
        "L is bound"
    );
    let mut fewer_heads = snapshot.path_heads.clone();
    fewer_heads.retain(|head| head.path != "p");
    assert_ne!(
        base_with(snapshot.author_state.clone(), fewer_heads, snapshot.lamport_ceiling),
        sealed.history_base(),
        "Gamma is bound"
    );
    let mut advanced = snapshot.author_state.clone();
    advanced[0].watermark =
        yadorilink_replica_domain::ids::AuthorSeq(advanced[0].watermark.get() + 1);
    assert_ne!(
        base_with(advanced, snapshot.path_heads.clone(), snapshot.lamport_ceiling),
        sealed.history_base(),
        "W is bound"
    );
}

/// Outside test fixtures a seal stays off with the rest of history
/// compaction: it deletes the whole retained history and moves the group
/// onto an epoch no peer accepts yet.
#[test]
fn a_seal_is_refused_while_history_compaction_is_not_ready() {
    assert!(matches!(
        seal::require_compaction_ready(false),
        Err(SyncSqliteError::CorruptState(message)) if message.contains("disabled")
    ));
    assert!(seal::require_compaction_ready(true).is_ok());
}

/// A path the installed base carries and nothing written on the base has
/// touched resolves from the heads the base carries: they are its `Gamma`
/// heads, and its current row is theirs. Resolving it from the path
/// frontier alone -- empty after the epoch reset -- finds nothing, so a
/// projection obligation for the path (every row an install places gets
/// one when its hold is released) can never settle, and the next seal
/// waits on it forever. Once a change on the base touches the path, that
/// change is what the path resolves from.
#[test]
fn a_path_only_the_installed_base_carries_resolves_from_the_heads_it_carries() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    let heads = |path: &str| {
        let mut heads: Vec<ChangeHash> = crate::dag_store::path_gamma_heads(&conn, GROUP, path)
            .unwrap()
            .into_iter()
            .map(|head| ChangeHash(head.change_hash))
            .collect();
        heads.sort();
        heads
    };
    assert!(
        crate::dag_store::live_path_heads(&conn, GROUP, "p").unwrap().is_empty(),
        "the epoch reset leaves the path frontier empty, so this tests the base"
    );
    assert_eq!(heads("p"), vec![h.b1.compute_hash()]);
    let mut concurrent = vec![h.a3.compute_hash(), h.b2.compute_hash()];
    concurrent.sort();
    assert_eq!(heads("r"), concurrent, "concurrent heads the base carries stay two heads");

    store_versions(&conn);
    let next = emit(&conn, "device-a", vec![put("p", &version(5))]);
    assert_eq!(heads("p"), vec![next.compute_hash()]);
}

/// A seal is not observable in the desired namespace. The tree the
/// projection is driven to -- each path's own node, every level's nodes,
/// and the whole group's -- is the same the moment after a seal as the
/// moment before: after the epoch reset the path frontier is empty, and
/// the heads the base carries are what the namespace is made of. Read from
/// the frontier alone, the namespace of a sealed group is empty, and every
/// installed file whose shape depends on another path (a file relocated
/// beside a directory, a directory held for a descendant) is placed wrong.
#[test]
fn the_desired_namespace_is_the_same_after_a_seal_as_before_it() {
    use crate::desired_state::{
        desired_level_projection, desired_namespace_projection, desired_path_state,
    };

    let conn = open();
    let h = build_history(&conn);
    admit(&conn, "device-d", &[&h.c1], vec![put("d/x", &version(5))]);
    publish_everything(&conn, 2);
    project(&conn);
    let paths = ["p", "q", "r", "d", "d/x", "absent"];
    let snapshot = |conn: &Connection| {
        let whole = desired_namespace_projection(conn, GROUP).unwrap().nodes().clone();
        let levels: Vec<_> = ["", "d"]
            .iter()
            .map(|parent| desired_level_projection(conn, GROUP, parent).unwrap().nodes().clone())
            .collect();
        let own: Vec<_> =
            paths.iter().map(|path| desired_path_state(conn, GROUP, path).unwrap()).collect();
        (whole, levels, own)
    };
    let before = snapshot(&conn);
    assert!(before.0.contains_key("d/x"), "the fixture places d/x before the seal");

    seal(&conn);
    assert!(
        crate::dag_store::live_heads_by_path(&conn, GROUP).unwrap().is_empty(),
        "the epoch reset empties the path frontier, so this tests the base"
    );

    assert_eq!(snapshot(&conn), before);
}
