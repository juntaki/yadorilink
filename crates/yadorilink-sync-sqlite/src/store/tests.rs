#![cfg(test)]

use std::sync::Arc;

use yadorilink_sqlite_runtime::DatabaseError;

use super::*;
use crate::dag_store::ORPHAN_BOUND;

/// Minimal stand-in for the tables these reads need -- not this
/// crate's real schema (item 3 doesn't move schema ownership, only
/// reads), just enough shape for these tests to exercise real SQL.
fn test_schema(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE changes (change_hash BLOB PRIMARY KEY, group_id TEXT NOT NULL, encoded BLOB NOT NULL);
         CREATE TABLE change_parents (child_hash BLOB NOT NULL, parent_hash BLOB NOT NULL);
         CREATE TABLE group_heads (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE orphan_changes (change_hash BLOB PRIMARY KEY, author_prev_hash BLOB);
         CREATE TABLE rejected_changes (
             change_hash BLOB PRIMARY KEY, group_id TEXT NOT NULL, reason TEXT NOT NULL,
             rejected_at INTEGER NOT NULL, rejection_domain TEXT NOT NULL,
             rules_version INTEGER NOT NULL, rests_on BLOB, refused_on_epoch BLOB
         );
         CREATE TABLE file_versions (group_id TEXT NOT NULL, version_hash BLOB NOT NULL, encoded BLOB NOT NULL);
         CREATE TABLE group_block_provenance (group_id TEXT NOT NULL, block_hash BLOB NOT NULL);
         CREATE TABLE device_frontier (group_id TEXT NOT NULL, device_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE files (
             group_id TEXT NOT NULL, path TEXT NOT NULL, version_seq INTEGER NOT NULL,
             size INTEGER NOT NULL, mtime_unix_nanos INTEGER NOT NULL, blocks_json TEXT NOT NULL,
             deleted INTEGER NOT NULL, state TEXT NOT NULL, origin_device_id TEXT,
             record_kind TEXT NOT NULL, symlink_target BLOB, unix_mode INTEGER NOT NULL,
             xattrs_json TEXT NOT NULL DEFAULT '[]',
             -- Present in the real schema; the canonical current-row
             -- read returns them alongside the content columns so a
             -- guard can compare version and authoring identity from
             -- one incarnation of the row, and so a producer can take
             -- the whole payload -- origin and out-of-root flag
             -- included -- from one statement.
             authoring_change_hash BLOB, materialization_state TEXT,
             symlink_out_of_root INTEGER NOT NULL DEFAULT 0
         );",
    )?;
    Ok(())
}

fn open_test_store() -> SqliteSyncStore {
    let database = Arc::new(SyncDatabase::open_in_memory(test_schema).expect("open in-memory db"));
    SqliteSyncStore::new(database)
}

fn hash(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

fn insert_block_provenance(
    store: &SqliteSyncStore,
    group: &FolderGroupId,
    block_hashes: &[Vec<u8>],
) {
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            for h in block_hashes {
                conn.execute(
                    "INSERT INTO group_block_provenance (group_id, block_hash) VALUES (?1, ?2)",
                    rusqlite::params![group.as_str(), h],
                )?;
            }
            Ok(())
        })
        .expect("insert block provenance");
}

fn insert_change(store: &SqliteSyncStore, group: &str, h: ChangeHash, encoded: &[u8]) {
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO changes (change_hash, group_id, encoded) VALUES (?1, ?2, ?3)",
                rusqlite::params![&h.0[..], group, encoded],
            )?;
            Ok(())
        })
        .expect("insert change");
}

fn insert_parent_edge(store: &SqliteSyncStore, child: ChangeHash, parent: ChangeHash) {
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                rusqlite::params![&child.0[..], &parent.0[..]],
            )?;
            Ok(())
        })
        .expect("insert parent edge");
}

fn insert_group_head(store: &SqliteSyncStore, group: &str, h: ChangeHash) {
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO group_heads (group_id, change_hash) VALUES (?1, ?2)",
                rusqlite::params![group, &h.0[..]],
            )?;
            Ok(())
        })
        .expect("insert group head");
}

#[test]
fn group_heads_is_empty_for_an_unknown_group() {
    let store = open_test_store();
    let heads = store.group_heads(&FolderGroupId("group-1".into())).expect("group_heads");
    assert!(heads.is_empty());
}

#[test]
fn group_heads_returns_multiple_heads_in_a_stable_hash_order() {
    let store = open_test_store();
    // Inserted out of order; the query itself orders by change_hash, so
    // the result must come back sorted regardless of insertion order.
    insert_group_head(&store, "group-1", hash(3));
    insert_group_head(&store, "group-1", hash(1));
    insert_group_head(&store, "group-1", hash(2));

    let heads = store.group_heads(&FolderGroupId("group-1".into())).expect("group_heads");
    assert_eq!(heads, vec![hash(1), hash(2), hash(3)]);

    // Repeating the read must produce the identical order -- not just
    // "some" order that happens to be sorted once.
    let heads_again = store.group_heads(&FolderGroupId("group-1".into())).expect("group_heads");
    assert_eq!(heads, heads_again);
}

#[test]
fn parents_of_returns_every_recorded_parent_edge() {
    let store = open_test_store();
    insert_parent_edge(&store, hash(10), hash(1));
    insert_parent_edge(&store, hash(10), hash(2));

    let mut parents = store.parents_of(&hash(10)).expect("parents_of");
    parents.sort();
    assert_eq!(parents, vec![hash(1), hash(2)]);
    assert!(store.parents_of(&hash(1)).expect("parents_of").is_empty());
}

#[test]
fn get_encoded_round_trips_the_exact_stored_bytes() {
    let store = open_test_store();
    let encoded = b"canonical-bytes-plus-signature".to_vec();
    insert_change(&store, "group-1", hash(1), &encoded);

    let read_back = store.get_encoded(&hash(1)).expect("get_encoded").expect("present");
    assert_eq!(read_back, encoded);
    assert!(store.get_encoded(&hash(99)).expect("get_encoded").is_none());
}

#[test]
fn missing_ancestor_frontier_of_an_unknown_hash_is_itself() {
    let store = open_test_store();
    let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
    assert_eq!(missing, vec![hash(1)]);
}

#[test]
fn missing_ancestor_frontier_does_not_treat_a_rejected_change_as_missing() {
    let store = open_test_store();
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            // Recorded through the real entry point, so this test cannot
            // drift away from how a rejection is actually stamped.
            crate::dag_store::record_rejected_change(
                conn,
                &hash(1),
                "g",
                crate::dag_store::RejectionDomain::Path,
                "a settled path verdict",
                100,
            )?;
            Ok(())
        })
        .expect("insert rejected change");

    let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
    assert!(missing.is_empty(), "a permanently-rejected hash must not be reported as missing");
}

#[test]
fn missing_ancestor_frontier_walks_through_a_buffered_orphan_to_its_missing_parent() {
    let store = open_test_store();
    // hash(1) is buffered as an orphan whose recorded parent, hash(2),
    // is itself unknown -- the walk must surface hash(2), not hash(1)
    // (hash(1) is already held; re-requesting it would be a no-op).
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute("INSERT INTO orphan_changes (change_hash) VALUES (?1)", [&hash(1).0[..]])?;
            Ok(())
        })
        .expect("insert orphan");
    insert_parent_edge(&store, hash(1), hash(2));

    let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
    assert_eq!(missing, vec![hash(2)]);
}

/// The frontier this store hands the engine has to follow the author link
/// too, not only the parent edges. A change held because its author's
/// previous change has not arrived is reachable through no parent edge at
/// all -- the author link is a separate relation precisely because an
/// author's previous change is routinely not an ancestor of its next one --
/// so a parents-only walk would report nothing missing, and the one change
/// that could release the held one would never be asked for.
#[test]
fn missing_ancestor_frontier_surfaces_the_author_predecessor_a_buffered_change_waits_on() {
    let store = open_test_store();
    // hash(1) is buffered, every parent edge it has is satisfied, and the
    // only thing it waits on is its author's previous change, hash(2).
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO orphan_changes (change_hash, author_prev_hash) VALUES (?1, ?2)",
                rusqlite::params![&hash(1).0[..], &hash(2).0[..]],
            )?;
            Ok(())
        })
        .expect("insert orphan");

    let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
    assert_eq!(
        missing,
        vec![hash(2)],
        "the author predecessor a held change waits on must be re-requested"
    );
}

#[test]
fn missing_ancestor_frontier_falls_back_to_roots_when_orphan_bound_is_exceeded() {
    let store = open_test_store();
    // A chain of buffered orphans longer than ORPHAN_BOUND, each
    // pointing at the next as its sole parent (32-byte hashes distinct
    // by their first 4 bytes, a counter) -- the walk must give up and
    // return the original root unchanged, not partially-walked results
    // or an error.
    let hash_for = |i: u32| -> ChangeHash {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        ChangeHash(bytes)
    };
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            for i in 0..=(ORPHAN_BOUND as u32 + 1) {
                let child = hash_for(i);
                conn.execute(
                    "INSERT INTO orphan_changes (change_hash) VALUES (?1)",
                    [&child.0[..]],
                )?;
                let parent = hash_for(i + 1);
                conn.execute(
                    "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                    rusqlite::params![&child.0[..], &parent.0[..]],
                )?;
            }
            Ok(())
        })
        .expect("insert long orphan chain");
    let root = hash_for(0);

    let missing = store.missing_ancestor_frontier(&[root]).expect("missing_ancestor_frontier");
    assert_eq!(
        missing,
        vec![root],
        "exceeding ORPHAN_BOUND must fall back to the original roots unchanged"
    );
}

#[test]
fn list_versions_orders_newest_first_and_preserves_metadata() {
    let store = open_test_store();
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                 blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, unix_mode) \
                 VALUES ('group-1', 'a.txt', 1, 10, 100, '[]', 0, 'superseded', 'device-a', 'file', NULL, 0)",
                [],
            )?;
            conn.execute(
                "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                 blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, unix_mode) \
                 VALUES ('group-1', 'a.txt', 2, 20, 200, '[]', 0, 'current', 'device-b', 'file', NULL, 1)",
                [],
            )?;
            Ok(())
        })
        .expect("insert version rows");

    let versions =
        store.list_versions(&FolderGroupId("group-1".into()), "a.txt").expect("list_versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version_seq, 2, "newest (highest version_seq) must come first");
    assert_eq!(versions[0].state, RetainedVersionState::Current);
    assert_eq!(versions[0].origin_device_id.as_deref(), Some("device-b"));
    assert_eq!(versions[0].unix_mode, Some(1));
    assert_eq!(versions[1].version_seq, 1);
    assert_eq!(versions[1].state, RetainedVersionState::Superseded);
}

#[test]
fn get_current_version_record_distinguishes_missing_from_corrupt() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    assert!(
        store.get_current_version_record(&group, "missing.txt").expect("query").is_none(),
        "no row at all must read as None, not an error"
    );

    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                 blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, unix_mode) \
                 VALUES ('group-1', 'corrupt.txt', 1, 1, 1, 'not-json', 0, 'current', NULL, 'file', NULL, 0)",
                [],
            )?;
            Ok(())
        })
        .expect("insert corrupt row");
    let result = store.get_current_version_record(&group, "corrupt.txt");
    assert!(
        result.is_err(),
        "an unparseable blocks_json column must fail closed, not default to empty"
    );
}

#[test]
fn device_frontier_round_trips_and_replaces_wholesale() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let device = yadorilink_replica_domain::ids::DeviceId("device-a".into());

    assert!(store.get_device_frontier(&group, &device).expect("read").is_empty());

    store.set_device_frontier(&group, &device, &[hash(2), hash(1)]).expect("set frontier");
    assert_eq!(
        store.get_device_frontier(&group, &device).expect("read"),
        vec![hash(1), hash(2)],
        "read must come back ascending by hash regardless of set order"
    );

    // A second set must replace, not accumulate.
    store.set_device_frontier(&group, &device, &[hash(3)]).expect("replace frontier");
    assert_eq!(store.get_device_frontier(&group, &device).expect("read"), vec![hash(3)]);

    store.remove_device_frontier(&group, &device).expect("remove frontier");
    assert!(store.get_device_frontier(&group, &device).expect("read").is_empty());
}

/// `group_has_block_provenance_batch` must return exactly the
/// subset of queried hashes that actually have a recorded row for this
/// group -- not every hash ever recorded (would falsely dedup blocks
/// this call wasn't even asked about) and not a hash recorded under a
/// DIFFERENT group (provenance is group-scoped by design: a block
/// physically present because a different sync group already holds it
/// must not be trusted as available for THIS group without this
/// group's own independent fetch).
#[test]
fn group_has_block_provenance_batch_returns_exactly_the_recorded_subset_for_this_group() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let other_group = FolderGroupId("group-2".into());
    let h1 = vec![1u8; 32];
    let h2 = vec![2u8; 32];
    let h3 = vec![3u8; 32];

    insert_block_provenance(&store, &group, std::slice::from_ref(&h1));
    insert_block_provenance(&store, &other_group, std::slice::from_ref(&h2));
    // h3 is never recorded anywhere.

    let found = store
        .group_has_block_provenance_batch(&group, &[h1.clone(), h2.clone(), h3.clone()])
        .expect("batch query");
    assert_eq!(
        found,
        std::collections::HashSet::from([h1]),
        "only h1 (recorded under THIS group) may come back -- h2's provenance is under a \
         different group and must not leak across the group boundary, and h3 was never \
         recorded at all"
    );
}

/// An empty query must not touch the database at all (SQLite's own
/// `IN ()` is invalid syntax) and must return an empty set, not an
/// error -- the common case at the tail of a mostly-already-deduped
/// batch where every remaining hash's presence still needs checking.
#[test]
fn group_has_block_provenance_batch_with_empty_input_returns_empty_without_querying() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let found = store.group_has_block_provenance_batch(&group, &[]).expect("empty batch query");
    assert!(found.is_empty());
}

/// The batched form must agree with the single-hash form for every
/// hash it's asked about -- this is a narrow performance change, not a
/// semantic one, and this pins that equivalence directly rather than
/// trusting the two implementations to stay in sync by inspection.
#[test]
fn group_has_block_provenance_batch_agrees_with_the_single_hash_form() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let recorded = vec![9u8; 32];
    let not_recorded = vec![10u8; 32];
    insert_block_provenance(&store, &group, std::slice::from_ref(&recorded));

    let batch = store
        .group_has_block_provenance_batch(&group, &[recorded.clone(), not_recorded.clone()])
        .expect("batch query");

    assert_eq!(
        batch.contains(&recorded),
        store.group_has_block_provenance(&group, &recorded).expect("single query")
    );
    assert_eq!(
        batch.contains(&not_recorded),
        store.group_has_block_provenance(&group, &not_recorded).expect("single query")
    );
}
