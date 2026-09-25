#![cfg(test)]

use super::*;
use yadorilink_replica_domain::file::FileRecord;

/// `yadorilink_sqlite_runtime::init_schema` must run AFTER
/// `init_dag_schema` (it assumes `changes`/`pruned_changes` already
/// exist, per its own doc comment), matching the real production
/// initialization order. Uses the REAL schema, not a stand-in, so
/// these tests also prove the `admitted_at_unix_nanos` migration
/// actually put the column on the table.
fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::dag_store::init_dag_schema(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    c
}

/// Inserts one `files` row with an explicit admission timestamp.
///
/// Direct SQL rather than `upsert_file_in_tx`, because the production
/// write path deliberately stamps the real wall clock and gives a
/// caller no way to choose the instant -- which is the right design
/// (see that function's doc comment) but makes it useless for building
/// a specific history. `stamps_the_local_admission_clock_at_the_write_
/// chokepoint` below covers the real path separately.
///
/// `size` is the only content knob these tests need: it feeds
/// `FileVersion::from_index_row`, so two rows with the same `size`
/// hash equal and two with different sizes do not.
#[allow(clippy::too_many_arguments)]
fn seed(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version_seq: i64,
    state: &str,
    deleted: bool,
    size: i64,
    admitted_at: Option<i64>,
) {
    conn.execute(
        "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                            mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, '[]', ?7)",
        rusqlite::params![group_id, path, version_seq, state, deleted as i64, size, admitted_at],
    )
    .unwrap();
}

/// Records the group's local history floor the way its real writers do.
/// Direct SQL for the same reason `seed` is: both of them stamp the
/// wall clock and offer no way to choose the instant. Each real writer
/// is driven end to end by its own test elsewhere --
/// `an_unmodified_file_from_before_an_install_is_unavailable_below_the_
/// floor` in `rebootstrap_store` for a base install, and
/// `local_history_floor_tests` in `enrollment` and in `link` for the two
/// link commits that can name a folder this device did not originate.
fn seed_local_history_floor(conn: &Connection, group_id: &str, floor_unix_nanos: i64) {
    conn.execute(
        "INSERT INTO group_local_history_floor (group_id, floor_unix_nanos) VALUES (?1, ?2)",
        rusqlite::params![group_id, floor_unix_nanos],
    )
    .unwrap();
}

fn action_for<'a>(plan: &'a RewindPlan, path: &str) -> Option<&'a RewindPathAction> {
    plan.entries.iter().find(|e| e.path == path).map(|e| &e.action)
}

#[test]
fn a_path_untouched_since_the_target_reports_unchanged() {
    let c = conn();
    seed(&c, "g", "steady.txt", 1, "current", false, 10, Some(100));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert_eq!(action_for(&plan, "steady.txt"), Some(&RewindPathAction::Unchanged));
    assert_eq!(plan.action_counts().unchanged, 1);
}

#[test]
fn a_path_present_at_the_target_but_deleted_since_reports_create() {
    let c = conn();
    // v1 was live at T=500; v2 (the tombstone) came after.
    seed(&c, "g", "gone.txt", 1, "trashed", false, 10, Some(100));
    seed(&c, "g", "gone.txt", 2, "current", true, 0, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    match action_for(&plan, "gone.txt") {
        Some(RewindPathAction::Create { version_seq, .. }) => assert_eq!(*version_seq, 1),
        other => panic!("expected Create, got {other:?}"),
    }
}

#[test]
fn a_path_created_after_the_target_reports_delete() {
    let c = conn();
    seed(&c, "g", "new.txt", 1, "current", false, 10, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert_eq!(action_for(&plan, "new.txt"), Some(&RewindPathAction::Delete));
}

#[test]
fn a_path_edited_after_the_target_reports_replace() {
    let c = conn();
    seed(&c, "g", "edited.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "edited.txt", 2, "current", false, 20, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    match action_for(&plan, "edited.txt") {
        Some(RewindPathAction::Replace { from_version_seq, to_version_seq, .. }) => {
            assert_eq!(*from_version_seq, 2);
            assert_eq!(*to_version_seq, 1);
        }
        other => panic!("expected Replace, got {other:?}"),
    }
}

/// Content, not `version_seq`, decides `Replace` vs `Unchanged`: a file
/// edited and then edited back has a higher `version_seq` but nothing
/// for a rewind to actually do.
#[test]
fn content_edited_back_to_its_earlier_bytes_reports_unchanged_not_replace() {
    let c = conn();
    seed(&c, "g", "roundtrip.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "roundtrip.txt", 2, "superseded", false, 20, Some(700));
    seed(&c, "g", "roundtrip.txt", 3, "current", false, 10, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert_eq!(action_for(&plan, "roundtrip.txt"), Some(&RewindPathAction::Unchanged));
}

#[test]
fn matching_content_across_a_create_and_delete_pair_is_reported_as_a_rename() {
    let c = conn();
    // At T=500 the content (size 42) lived at old/name.txt. Afterwards
    // it was moved to new/name.txt: the old path was tombstoned and the
    // new one created.
    seed(&c, "g", "old/name.txt", 1, "trashed", false, 42, Some(100));
    seed(&c, "g", "old/name.txt", 2, "current", true, 0, Some(900));
    seed(&c, "g", "new/name.txt", 1, "current", false, 42, Some(900));

    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    // The authoritative per-path entries stand on their own.
    assert!(matches!(action_for(&plan, "old/name.txt"), Some(RewindPathAction::Create { .. })));
    assert_eq!(action_for(&plan, "new/name.txt"), Some(&RewindPathAction::Delete));
    // ... and the auxiliary annotation names the pairing.
    assert_eq!(plan.rename_candidates.len(), 1);
    assert_eq!(plan.rename_candidates[0].from_path, "new/name.txt");
    assert_eq!(plan.rename_candidates[0].to_path, "old/name.txt");
}

/// A coincidental identical-content match on more than one path is
/// ambiguous. The guess is dropped; the per-path verdicts are not.
#[test]
fn ambiguous_identical_content_produces_no_rename_guess_but_keeps_per_path_verdicts() {
    let c = conn();
    seed(&c, "g", "old.txt", 1, "trashed", false, 42, Some(100));
    seed(&c, "g", "old.txt", 2, "current", true, 0, Some(900));
    seed(&c, "g", "copy-a.txt", 1, "current", false, 42, Some(900));
    seed(&c, "g", "copy-b.txt", 1, "current", false, 42, Some(900));

    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert!(plan.rename_candidates.is_empty(), "an ambiguous match must not be guessed at");
    assert!(matches!(action_for(&plan, "old.txt"), Some(RewindPathAction::Create { .. })));
    assert_eq!(action_for(&plan, "copy-a.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(action_for(&plan, "copy-b.txt"), Some(&RewindPathAction::Delete));
}

/// The retention sweep deletes expired `superseded`/`trashed` index
/// rows outright, so a path whose history at T is gone has a surviving
/// floor above `version_seq` 1. That must read as "no answer", never as
/// "nothing to do" and never as the closest version still on hand.
#[test]
fn history_expired_by_retention_reports_unavailable_rather_than_guessing() {
    let c = conn();
    // Versions 1..=4 existed; retention already deleted 1..=3. What was
    // current at T=500 was one of the deleted ones.
    seed(&c, "g", "long-lived.txt", 4, "superseded", false, 40, Some(800));
    seed(&c, "g", "long-lived.txt", 5, "current", false, 50, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    match action_for(&plan, "long-lived.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            assert!(reason.contains("retention"), "reason should say why: {reason}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    let counts = plan.action_counts();
    assert_eq!(counts.unavailable, 1);
    assert_eq!(counts.unchanged, 0, "an unanswerable path must never be tallied as unchanged");
}

/// A row carrying no admission timestamp at all (a database whose
/// first-ever schema init crashed before the column was added, the one
/// stale shape the version gate accepts) is equally unanswerable.
#[test]
fn a_row_with_no_admission_timestamp_reports_unavailable() {
    let c = conn();
    seed(&c, "g", "unstamped.txt", 1, "current", false, 10, None);
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    match action_for(&plan, "unstamped.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            assert!(reason.contains("admission timestamp"), "reason should say why: {reason}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// The `version_seq DESC` tie-break, on its own. Two rows for one path
/// sharing an `admitted_at_unix_nanos` is not a corner case: a
/// rebootstrap install writes a path's whole retained history in one
/// pass and stamps every row with that install's single instant, and a
/// coarse clock can do the same for two ordinary writes. The "at T"
/// side must resolve such a tie to the highest `version_seq` -- the
/// path's current row -- or the plan reports a rollback that is not
/// real.
#[test]
fn an_admission_timestamp_tie_resolves_to_the_highest_version_seq() {
    let c = conn();
    // Different `size`, so the two rows have different `version_hash`es
    // and a wrong pick shows up as a verdict, not just a number.
    seed(&c, "g", "tied.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "tied.txt", 2, "current", false, 20, Some(100));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert_eq!(
        action_for(&plan, "tied.txt"),
        Some(&RewindPathAction::Unchanged),
        "a tie must resolve to the current row; picking the superseded one would report a \
         rollback that never happened"
    );
}

#[test]
fn a_group_with_no_history_before_the_target_reports_every_live_path_as_delete() {
    let c = conn();
    seed(&c, "g", "a.txt", 1, "current", false, 10, Some(900));
    seed(&c, "g", "b.txt", 1, "current", false, 20, Some(901));
    // A path already tombstoned before the target existed at all is
    // absent on both sides -- nothing to do, not a delete.
    seed(&c, "g", "c.txt", 1, "trashed", false, 30, Some(902));
    seed(&c, "g", "c.txt", 2, "current", true, 0, Some(903));

    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert_eq!(action_for(&plan, "a.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(action_for(&plan, "b.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(action_for(&plan, "c.txt"), Some(&RewindPathAction::Unchanged));
    let counts = plan.action_counts();
    assert_eq!(counts.delete, 2);
    assert_eq!(counts.unavailable, 0, "'created after T' is a real answer, not a gap");
}

/// The `min_version_seq <= 1` reading -- "this path's first version was
/// admitted after T, so at T it did not exist here" -- is only sound
/// while `version_seq` is this device's own admission history. A
/// re-bootstrap install ends that: it empties `files` for the group and
/// reinstalls the SOURCE device's numbering, so a file created years ago
/// and never edited since arrives as `version_seq = 1`. Below the
/// recorded floor, that must read as "no answer here", not as "created
/// after T".
#[test]
fn below_the_local_history_floor_an_unmodified_path_is_unavailable_not_delete() {
    let c = conn();
    seed_local_history_floor(&c, "g", 1_000);
    // A never-edited file that the install carried in at version 1.
    seed(&c, "g", "unmodified.txt", 1, "current", false, 10, Some(1_000));

    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    match action_for(&plan, "unmodified.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            assert!(reason.contains("re-bootstrap"), "reason should say why: {reason}");
            assert!(
                !reason.contains("retention"),
                "retention cannot be the cause below the floor: {reason}"
            );
        }
        other => panic!("expected Unavailable below the floor, got {other:?}"),
    }
    assert_eq!(plan.action_counts().delete, 0);
}

/// The other half of the same boundary, which is what keeps the fix from
/// being a blanket "never answer after a re-bootstrap": at or above the
/// floor the group's local history IS this device's own unbroken record,
/// so the ordinary classifications still apply -- including the
/// `version_seq = 1` inference the floor suspends below it.
#[test]
fn at_or_after_the_local_history_floor_paths_are_classified_normally() {
    let c = conn();
    seed_local_history_floor(&c, "g", 1_000);
    // Carried in by the install itself.
    seed(&c, "g", "unmodified.txt", 1, "current", false, 10, Some(1_000));
    // Written locally afterwards, so its version 1 really is this
    // device's own first admission of the path.
    seed(&c, "g", "created-later.txt", 1, "current", false, 20, Some(2_000));

    let plan = compute_rewind_plan(&c, "g", 1_500).unwrap();
    assert_eq!(
        action_for(&plan, "unmodified.txt"),
        Some(&RewindPathAction::Unchanged),
        "a path whose installed row is at or before the target is ordinary evidence"
    );
    assert_eq!(
        action_for(&plan, "created-later.txt"),
        Some(&RewindPathAction::Delete),
        "inside this device's own continuous history, 'first version admitted after T' is \
         still a real answer"
    );
    assert_eq!(plan.action_counts().unavailable, 0);
}

/// The floor is per group, like the plan itself. One group's
/// re-bootstrap must not make another group's history unanswerable.
#[test]
fn the_local_history_floor_is_scoped_to_its_own_group() {
    let c = conn();
    seed_local_history_floor(&c, "rebootstrapped", 1_000);
    seed(&c, "rebootstrapped", "a.txt", 1, "current", false, 10, Some(1_000));
    seed(&c, "untouched", "b.txt", 1, "current", false, 10, Some(1_000));

    assert!(matches!(
        action_for(&compute_rewind_plan(&c, "rebootstrapped", 500).unwrap(), "a.txt"),
        Some(RewindPathAction::Unavailable { .. })
    ));
    assert_eq!(
        action_for(&compute_rewind_plan(&c, "untouched", 500).unwrap(), "b.txt"),
        Some(&RewindPathAction::Delete),
        "a group that never crossed a re-bootstrap keeps the ordinary inference"
    );
}

/// A path this device has never indexed is absent from the plan
/// entirely -- documented behavior, not a bug. Modelled here as another
/// group's path, which is the same situation from this query's point of
/// view and doubles as the group-scoping check.
#[test]
fn paths_this_device_never_indexed_for_this_group_are_absent_from_the_plan() {
    let c = conn();
    seed(&c, "g", "mine.txt", 1, "current", false, 10, Some(100));
    seed(&c, "other", "theirs.txt", 1, "current", false, 10, Some(100));
    let plan = compute_rewind_plan(&c, "g", 500).unwrap();
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(plan.entries[0].path, "mine.txt");
    assert!(action_for(&plan, "theirs.txt").is_none());
}

#[test]
fn an_empty_group_produces_an_empty_plan_rather_than_an_error() {
    let c = conn();
    let plan = compute_rewind_plan(&c, "never-seen", 500).unwrap();
    assert!(plan.entries.is_empty());
    assert!(plan.rename_candidates.is_empty());
    assert_eq!(plan.group_id, "never-seen");
    assert_eq!(plan.target_unix_nanos, 500);
}

/// The `version_seq = 0` metadata-scaffold writers are NOT
/// `upsert_file_in_tx`, and they insert a real `files` row. They have to
/// stamp it too or the whole path reads as unanswerable until the next
/// real write to it -- see `file_index::upsert_file_in_tx`'s "stamping
/// invariant" section. Both variants are checked, because they are two
/// separate copies of the same statement.
#[test]
fn the_metadata_bootstrap_scaffold_writers_stamp_too() {
    let before =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            as i64;

    // In-transaction variant, called directly.
    let mut c = conn();
    {
        let tx = c.transaction().unwrap();
        crate::file_index::ensure_bootstrap_row_for_metadata_in_tx(&tx, "g", "scaffold.txt")
            .unwrap();
        tx.commit().unwrap();
    }

    // Pooled-connection variant, through the repository.
    let db = std::sync::Arc::new(
        yadorilink_sqlite_runtime::SyncDatabase::open_in_memory(|conn| {
            crate::dag_store::init_dag_schema(conn).map_err(|error| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(error.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .unwrap(),
    );
    crate::file_index::FileIndexRepository::new(db.clone())
        .ensure_bootstrap_row_for_metadata("g", "scaffold.txt")
        .unwrap();

    let read = |conn: &Connection| -> Option<i64> {
        conn.query_row(
            "SELECT admitted_at_unix_nanos FROM files \
             WHERE group_id = 'g' AND path = 'scaffold.txt'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(
        read(&c).is_some_and(|stamp| stamp >= before),
        "the in-transaction scaffold writer must stamp the local clock"
    );
    assert!(
        db.read::<_, SyncSqliteError>(|conn| Ok(read(conn)))
            .unwrap()
            .is_some_and(|stamp| stamp >= before),
        "the pooled-connection scaffold writer must stamp the local clock"
    );

    // The consequence that actually matters: the path is answerable.
    let plan = compute_rewind_plan(&c, "g", i64::MAX).unwrap();
    assert_eq!(
        action_for(&plan, "scaffold.txt"),
        Some(&RewindPathAction::Unchanged),
        "an unstamped scaffold row would make this path unanswerable instead"
    );
}

/// The production write path stamps the column from this device's own
/// clock, on every branch, with no caller involvement -- the property
/// the whole planning layer rests on.
#[test]
fn stamps_the_local_admission_clock_at_the_write_chokepoint() {
    let mut c = conn();
    let before =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            as i64;

    let record = |path: &str, size: u64, deleted: bool| FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted,
    };
    {
        let tx = c.transaction().unwrap();
        // Branch 1: brand-new path.
        crate::file_index::upsert_file_in_tx(&tx, "g", &record("f.txt", 1, false), "", None)
            .unwrap();
        // Branch 3: version bump over an existing current row.
        crate::file_index::upsert_file_in_tx(&tx, "g", &record("f.txt", 2, false), "", None)
            .unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = c.transaction().unwrap();
        // Branch 2: promotion of a `version_seq = 0` bootstrap scaffold.
        tx.execute(
            "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                                mtime_unix_nanos, blocks_json) \
             VALUES ('g', 'scaffold.txt', 0, 'current', 0, 0, 0, '[]')",
            [],
        )
        .unwrap();
        crate::file_index::upsert_file_in_tx(&tx, "g", &record("scaffold.txt", 3, false), "", None)
            .unwrap();
        tx.commit().unwrap();
    }

    let stamped: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = 'g' \
             AND admitted_at_unix_nanos IS NOT NULL AND admitted_at_unix_nanos >= ?1",
            rusqlite::params![before],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stamped, 3, "every row all three branches wrote must carry a local stamp");
    // Never the replicated filesystem timestamp: every record above has
    // `mtime_unix_nanos = 0`, so a stamp derived from it would be 0.
    let from_mtime: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = 'g' AND admitted_at_unix_nanos = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(from_mtime, 0, "the stamp must not come from the record's own mtime");
}
