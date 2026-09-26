#![cfg(test)]
//! What a committed seal leaves behind.
//!
//! A seal replaces the group's history with a base. Afterwards the base is
//! the whole of that history here: no change it absorbed is retained, and
//! nothing derived from one -- parent edges, heads, path frontier, orphans
//! waiting on it, refusals measured against it -- survives it. What does
//! survive is what the base carries: every author's position, the Lamport
//! ceiling, and the files, each still authored and still servable.
//!
//! The seal is one transaction, so a crash anywhere inside it leaves the
//! group exactly as it was before it began.

use super::base_install_tests::open;
use super::seal_tests::{
    assert_every_author_anchored_on, build_history, key, put, seal, sorted, store_versions,
    version, History, GROUP,
};
use super::*;
use yadorilink_replica_domain::admission::{AdmitOutcome, AuthorChainRefusal};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};

fn group_rows(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE group_id = ?1"), [GROUP], |row| {
        row.get(0)
    })
    .unwrap()
}

fn absorbed(h: &History) -> Vec<ChangeHash> {
    [&h.a1, &h.a2, &h.a3, &h.b1, &h.b2, &h.c1].iter().map(|c| c.compute_hash()).collect()
}

/// A change by `device` on the group's current base, at exactly `seq`,
/// naming `author_prev`, parented on nothing and clocked from `clocked_from`.
fn on_base(
    base: HistoryBase,
    device: &str,
    seq: u64,
    author_prev: Option<ChangeHash>,
    clocked_from: u64,
    ops: Vec<Op>,
) -> Change {
    Change::create_signed(
        Vec::new(),
        clocked_from,
        DeviceId(device.to_string()),
        AuthorSeq(seq),
        author_prev,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(base),
        ops,
        &key(device),
    )
}

/// Every row of every table in the database, table by table, each table's
/// rows in a stable order. Two equal dumps are two databases holding the
/// same state.
fn dump(conn: &Connection) -> BTreeMap<String, Vec<String>> {
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    let mut out = BTreeMap::new();
    for table in tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = stmt.column_count();
        let mut rows: Vec<String> = stmt
            .query_map([], |row| {
                let values: Vec<rusqlite::types::Value> =
                    (0..columns).map(|i| row.get(i)).collect::<Result<_, _>>()?;
                Ok(format!("{values:?}"))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows.sort();
        out.insert(table, rows);
    }
    out
}

/// Once sealed, the group retains nothing of the history the base
/// absorbed -- not the frontier either -- and nothing derived from it,
/// while `W` and `L` stay exactly where the base put them.
#[test]
fn a_seal_retires_every_change_it_absorbs_the_frontier_included() {
    let conn = open();
    let h = build_history(&conn);
    // Derived state that names the history: a peer's acknowledged
    // frontier, an interned causal basis, and a conflict copy's
    // provenance.
    conn.execute(
        "INSERT INTO device_frontier (group_id, device_id, change_hash) VALUES (?1, 'peer', ?2)",
        rusqlite::params![GROUP, &h.c1.compute_hash().0[..]],
    )
    .unwrap();
    crate::dag_store::intern_causal_basis(&conn, GROUP, &[h.c1.compute_hash()]).unwrap();
    crate::dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO conflict_copy_provenance \
         (group_id, source_path, losing_change_hash, carrier_change_hash, target_path) \
         VALUES (?1, 'r', ?2, ?3, 'r (copy)')",
        rusqlite::params![GROUP, &h.b2.compute_hash().0[..], &h.c1.compute_hash().0[..]],
    )
    .unwrap();

    let sealed = seal(&conn);

    for table in [
        "changes",
        "group_heads",
        "path_live_heads",
        "change_path_effects",
        "change_causal_order",
        "change_file_versions",
        "orphan_changes",
        "device_frontier",
        "pruned_changes",
        "pruned_change_parents",
        "conflict_copy_provenance",
        "causal_basis_sets",
        "path_materialized_generations",
    ] {
        assert_eq!(group_rows(&conn, table), 0, "{table} still holds rows of the sealed history");
    }
    for hash in absorbed(&h) {
        let edges: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM change_parents WHERE child_hash = ?1 OR parent_hash = ?1",
                [&hash.0[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(edges, 0, "a parent edge of {} survived the seal", hash.to_hex());
    }

    let base = sealed.history_base();
    assert_eq!(
        sorted(history_base_summary(&conn, GROUP).unwrap().unwrap()),
        sorted(sealed.summary()),
        "W and L are kept, as the base carries them"
    );
    assert_eq!(lamport_floor(&conn, GROUP, HistoryEpoch::Base(base)).unwrap(), Some(h.c1.lamport));
    assert_every_author_anchored_on(&conn, base);
}

/// Every current row the base carries keeps its version bytes and a link
/// to the evidence that authorized it, so the content stays servable with
/// the change that wrote it gone.
#[test]
fn a_seal_keeps_what_every_current_row_needs_to_be_served() {
    let conn = open();
    build_history(&conn);
    let sealed = seal(&conn);

    for file in &sealed.snapshot().files {
        if file.state != SnapshotVersionState::Current || file.record.deleted {
            continue;
        }
        let version = FileVersion::from_index_row(
            file.record.blocks.clone(),
            file.record.size,
            file.record.mtime_unix_nanos,
            file.record_kind,
            file.unix_mode,
            file.symlink_target.clone(),
            file.xattrs.clone(),
        );
        let path = &file.record.path;
        assert!(
            crate::dag_store::get_file_version(&conn, GROUP, &version.version_hash)
                .unwrap()
                .is_some(),
            "{path}'s version is gone"
        );
        let evidenced: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pruned_published_change_versions w \
                 JOIN change_authorization ca ON ca.change_hash = w.authoring_change_hash \
                 WHERE w.group_id = ?1 AND w.version_hash = ?2)",
                rusqlite::params![GROUP, &version.version_hash.0[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert!(evidenced, "{path}'s version has no link to the evidence that authorized it");
    }
}

/// A change held because it waited on history the seal replaced, and a
/// refusal decided against that history, go with it: neither describes
/// anything the group is on any more.
#[test]
fn a_seal_drops_what_waited_on_the_history_it_replaced() {
    let conn = open();
    build_history(&conn);
    let waiting = create_signed_for_tests_on_genesis(
        vec![ChangeHash([0x55; 32])],
        40,
        "device-d",
        vec![put("w", &version(8))],
    );
    let outcome = crate::dag_store::admit_change(&conn, &waiting).unwrap().outcome;
    assert!(matches!(outcome, AdmitOutcome::Orphaned), "got {outcome:?}");
    let foreign = Change::create_signed(
        Vec::new(),
        0,
        DeviceId("device-e".to_string()),
        AuthorSeq(1),
        None,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(HistoryBase([0x77; 32])),
        vec![put("x", &version(9))],
        &key("device-e"),
    );
    let outcome = crate::dag_store::admit_change(&conn, &foreign).unwrap().outcome;
    assert!(matches!(outcome, AdmitOutcome::RefusedForeignHistoryBase { .. }), "got {outcome:?}");

    seal(&conn);

    assert_eq!(group_rows(&conn, "orphan_changes"), 0);
    let refusals: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_changes WHERE change_hash = ?1",
            [&foreign.compute_hash().0[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(refusals, 0, "a refusal measured against the replaced history outlived it");
}

fn create_signed_for_tests_on_genesis(
    parents: Vec<ChangeHash>,
    clocked_from: u64,
    device: &str,
    ops: Vec<Op>,
) -> Change {
    Change::create_signed(
        parents,
        clocked_from,
        DeviceId(device.to_string()),
        AuthorSeq(1),
        None,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Genesis,
        ops,
        &key(device),
    )
}

/// The first change an author writes above the seal names no predecessor,
/// sits one past the position the base carries, is signed on the base and
/// clocked from its ceiling -- and, naming the head the base carried at the
/// path it writes, it alone is the path's head.
#[test]
fn the_first_change_above_a_seal_opens_the_epoch_on_the_base() {
    let conn = open();
    let h = build_history(&conn);
    let base = seal(&conn).history_base();
    store_versions(&conn);

    let b3 = Change::create_signed_observing(
        Vec::new(),
        h.c1.lamport,
        DeviceId("device-b".to_string()),
        AuthorSeq(h.b2.author_seq.get() + 1),
        None,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(base),
        yadorilink_replica_domain::change::ChangePurpose::Ordinary,
        None,
        vec![h.c1.compute_hash()],
        vec![put("q", &version(5))],
        &key("device-b"),
    );
    assert_eq!(b3.lamport, h.c1.lamport + 1);
    let outcome = crate::dag_store::admit_change(&conn, &b3).unwrap().outcome;
    assert!(matches!(outcome, AdmitOutcome::Applied), "got {outcome:?}");

    let live: Vec<ChangeHash> = crate::dag_store::live_path_heads(&conn, GROUP, "q")
        .unwrap()
        .into_iter()
        .map(|head| ChangeHash(head.change_hash))
        .collect();
    assert_eq!(live, vec![b3.compute_hash()], "only the write above the base is a head of q");
}

/// The change that attained an author's position is absorbed by the base
/// and is not something a later change may continue from: naming it is
/// refused at the next position, and refused rather than held past it.
#[test]
fn naming_a_change_the_seal_absorbed_is_refused() {
    let conn = open();
    let h = build_history(&conn);
    let base = seal(&conn).history_base();
    store_versions(&conn);
    let tip = h.b2.compute_hash();
    let next = h.b2.author_seq.get() + 1;

    let at_next =
        on_base(base, "device-b", next, Some(tip), h.c1.lamport, vec![put("s", &version(5))]);
    let outcome = crate::dag_store::admit_change(&conn, &at_next).unwrap().outcome;
    assert!(
        matches!(
            outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
        ),
        "got {outcome:?}"
    );

    let past_next =
        on_base(base, "device-b", next + 1, Some(tip), h.c1.lamport, vec![put("s", &version(6))]);
    let outcome = crate::dag_store::admit_change(&conn, &past_next).unwrap().outcome;
    assert!(
        matches!(
            outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
        ),
        "a change naming the absorbed tip past the next position must be refused, not held: \
         got {outcome:?}"
    );
    assert_eq!(group_rows(&conn, "orphan_changes"), 0);
}

/// A change the seal absorbed, delivered again, was written on the history
/// the base replaced. It is refused as such -- neither re-admitted nor held
/// as waiting for parents that will never be retained here again.
#[test]
fn a_change_the_seal_absorbed_is_another_history_when_it_returns() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);

    let outcome = crate::dag_store::admit_change(&conn, &h.a2).unwrap().outcome;
    assert!(matches!(outcome, AdmitOutcome::RefusedForeignHistoryBase { .. }), "got {outcome:?}");
    assert!(!crate::dag_store::has_change(&conn, &h.a2.compute_hash()).unwrap());
    assert_eq!(group_rows(&conn, "orphan_changes"), 0);
}

/// A current row the base carries is part of the group's history, though
/// the change that wrote it is no longer retained: it is not an unauthored
/// row for an import to author again, and its path -- a conflict copy's
/// included -- is not missing from history for a backfill to fill in.
#[test]
fn the_rows_a_base_carries_stay_authored_and_in_history() {
    let conn = open();
    build_history(&conn);
    let copy_path: String = conn
        .query_row(
            "SELECT path FROM files WHERE group_id = ?1 AND path LIKE 'r (%'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    seal(&conn);

    assert_eq!(
        crate::file_index::unauthored_current_paths_in_tx(&conn, GROUP).unwrap(),
        HashSet::new(),
        "rows the base carries are authored"
    );
    let history = crate::dag_store::group_history_paths(&conn, GROUP).unwrap();
    for path in ["p", "q", "r", copy_path.as_str()] {
        assert!(history.contains(path), "{path} is missing from history: {history:?}");
    }
}

/// A seal interrupted after any of its steps -- the summary written, the
/// base switched, the old history retired -- is a transaction that never
/// commits, and leaves every row exactly as it was. The group can then be
/// sealed as if nothing had happened.
///
/// Inside the transaction, each step has left exactly what it promises:
/// the base is not switched to before the summary is recorded, and the
/// absorbed history is not retired before every author is anchored on the
/// new base.
#[test]
fn a_seal_interrupted_after_any_step_leaves_the_group_exactly_as_it_was() {
    for step in EpochResetStep::ALL {
        let conn = open();
        let h = build_history(&conn);
        let base = prepare_seal(&conn, GROUP).unwrap().history_base();
        let before = dump(&conn);

        {
            let tx = conn.unchecked_transaction().unwrap();
            let error = seal_group_interrupted_after(&tx, GROUP, step)
                .expect_err("the seal must stop where it was interrupted");
            assert!(
                !matches!(error, SyncSqliteError::SealRefused { .. }),
                "interrupted after {step:?}, not refused: {error}"
            );
            let retained = absorbed(&h)
                .iter()
                .filter(|hash| crate::dag_store::has_change(&tx, hash).unwrap())
                .count();
            match step {
                EpochResetStep::SummaryRecorded => {
                    assert_eq!(history_base(&tx, GROUP).unwrap(), None, "switched too early");
                    assert_eq!(retained, absorbed(&h).len(), "history retired too early");
                }
                EpochResetStep::BaseSwitched => {
                    assert_eq!(history_base(&tx, GROUP).unwrap(), Some(base));
                    assert_every_author_anchored_on(&tx, base);
                    assert_eq!(retained, absorbed(&h).len(), "history retired too early");
                }
                EpochResetStep::HistoryRetired | EpochResetStep::WitnessesCollected => {
                    assert_eq!(history_base(&tx, GROUP).unwrap(), Some(base));
                    assert_eq!(retained, 0, "absorbed history still retained");
                    assert_eq!(group_rows(&tx, "changes"), 0);
                }
            }
            // Dropped without committing: the crash.
        }

        assert_eq!(dump(&conn), before, "interrupted after {step:?}, the group changed");
        seal(&conn);
    }
}

/// A sealed group reopens exactly as it was left: the startup checks that
/// re-verify retained history, the path frontier and the author state all
/// accept a group whose history is a base and nothing else, and have
/// nothing to repair in it.
#[test]
fn a_sealed_group_reopens_exactly_as_it_was_left() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sealed.db");
    let reopen = || {
        let conn = Connection::open(&path).unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        yadorilink_sqlite_runtime::init_schema(&conn).unwrap();
        conn
    };

    let (sealed, as_left) = {
        let conn = reopen();
        build_history(&conn);
        let sealed = seal(&conn);
        (sealed, dump(&conn))
    };
    let conn = reopen();

    assert_eq!(dump(&conn), as_left, "reopening the sealed group changed it");
    assert_eq!(history_base(&conn, GROUP).unwrap(), Some(sealed.history_base()));
    assert_eq!(group_rows(&conn, "changes"), 0);
    assert_every_author_anchored_on(&conn, sealed.history_base());
}

/// A sealed group is still a group with history: the base is its history.
/// A current row claiming no authoring change, or one this device has
/// never seen, is refused both before and after the first change above the
/// base -- while a row the base carries, whose author the base absorbed,
/// stays writable throughout.
#[test]
fn a_sealed_group_still_requires_every_current_row_to_be_authored() {
    let conn = open();
    let h = build_history(&conn);
    let base = seal(&conn).history_base();
    store_versions(&conn);

    let check = |when: &str| {
        // Every carried row: the winners and the conflict copy alike.
        let touch_carried = conn.execute(
            "UPDATE files SET version_seq = version_seq \
             WHERE group_id = ?1 AND state = 'current' AND version_seq > 0 \
               AND path != 'q'",
            [GROUP],
        );
        let touched =
            touch_carried.unwrap_or_else(|e| panic!("{when}: a carried row was refused: {e}"));
        assert!(touched >= 3, "{when}: only {touched} carried rows");
        for bogus in [None, Some(vec![0x11u8; 32]), Some(vec![0x11u8; 5])] {
            let error = conn
                .execute(
                    "UPDATE files SET authoring_change_hash = ?2 \
                     WHERE group_id = ?1 AND path = 'p' AND state = 'current'",
                    rusqlite::params![GROUP, bogus],
                )
                .expect_err(&format!("{when}: a row authored by {bogus:?} was accepted"));
            assert!(error.to_string().contains("verified authoring identity"), "{when}: {error}");
            let error = conn
                .execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     version_seq, state, authoring_change_hash) \
                     VALUES (?1, 'unauthored', 0, 0, '[]', 1, 'current', ?2)",
                    rusqlite::params![GROUP, bogus],
                )
                .expect_err(&format!("{when}: a new row authored by {bogus:?} was accepted"));
            assert!(error.to_string().contains("verified authoring identity"), "{when}: {error}");
        }
    };

    check("right after the seal");

    let b3 = on_base(
        base,
        "device-b",
        h.b2.author_seq.get() + 1,
        None,
        h.c1.lamport,
        vec![put("q", &version(5))],
    );
    let outcome = crate::dag_store::admit_change(&conn, &b3).unwrap().outcome;
    assert!(matches!(outcome, AdmitOutcome::Applied), "got {outcome:?}");
    check("after the first change above the base");
    // The same rule, checked over every row when the database is opened.
    yadorilink_sqlite_runtime::init_schema(&conn).expect("the sealed group reopens");
}

/// A recursive operation's record is what a folder restore reads once the
/// changes that carried its parts are gone, so a seal must leave it alone.
#[test]
fn a_seal_keeps_the_record_of_every_recursive_operation() {
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_replica_domain::recursive_operation::{
        EffectSetHash, RecursiveOperation, RecursiveOperationId, RecursiveOperationKind,
        RecursiveOperationRef,
    };
    let conn = open();
    build_history(&conn);
    let effects = vec![Op::Delete { path: SyncPath("d/x".to_string()) }];
    let part = Change::create_recursive_part_signed(
        Vec::new(),
        0,
        DeviceId("device-r".to_string()),
        AuthorSeq(1),
        None,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Genesis,
        RecursiveOperation {
            operation_id: RecursiveOperationId([3; 16]),
            kind: RecursiveOperationKind::RmTree { root: SyncPath("d".to_string()) },
            part_index: 0,
            part_count: 1,
            effect_set_hash: EffectSetHash::of_effects(&effects),
        },
        effects,
        &key("device-r"),
    );
    crate::dag_store::record_recursive_operation_part(&conn, &part).unwrap();

    seal(&conn);

    let recorded = crate::dag_store::recursive_operation(
        &conn,
        GROUP,
        &RecursiveOperationRef {
            author: DeviceId("device-r".to_string()),
            operation_id: RecursiveOperationId([3; 16]),
        },
    )
    .unwrap()
    .expect("the seal keeps the operation's record");
    assert_eq!(recorded.completeness(), crate::dag_store::RecursiveOperationCompleteness::Complete);
}
