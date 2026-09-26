#![cfg(test)]
//! What a group's metadata costs after many seals and merges.
//!
//! A history base replaces the history below it, so what a replica keeps
//! must depend on the files it holds and the authors that wrote them, never
//! on how many changes, seals or merges the group has been through. Each
//! test here drives the same workload round after round -- two replicas
//! writing the same paths, sealing apart and merging -- and checks that the
//! database stops growing once the retention window is full: every table,
//! the base's own summary tables and the device-local directory ledger
//! included -- the checkpoint headers too: a replica keeps the header of
//! the base it stands on, not one per base it has been through.

use std::collections::{BTreeMap, HashSet};

use super::base_install_tests::open;
use super::merge_install_tests::{as_returning, merge, publish};
use super::seal_namespace_tests::{directory, project_tree, store_directories};
use super::seal_tests::{put, seal, store_versions, version, GROUP};
use super::*;
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::test_authoring::reset_author_sequences;
use yadorilink_root_authority::fs_identity::{
    FileIdentity, ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
};

/// The row count of every table in the database.
fn census(conn: &Connection) -> BTreeMap<String, i64> {
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
    tables
        .into_iter()
        .map(|table| {
            let rows = count(conn, &format!("SELECT COUNT(*) FROM {table}"));
            (table, rows)
        })
        .collect()
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// Bytes of every stored base snapshot.
fn snapshot_bytes(conn: &Connection) -> i64 {
    count(conn, "SELECT COALESCE(SUM(LENGTH(snapshot)), 0) FROM change_checkpoint_snapshots")
}

/// Releases every install hold and brings the rows to the projection, as
/// the reconcile pass does once the disk matches the installed rows.
fn reconcile(conn: &Connection) {
    let holds: Vec<(String, i64)> = {
        let mut stmt = conn
            .prepare("SELECT path, generation FROM snapshot_install_holds WHERE group_id = ?1")
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        rows.map(Result::unwrap).collect()
    };
    for (path, generation) in holds {
        let released =
            crate::snapshot_install_hold::release_in_tx(conn, GROUP, &path, generation, 0);
        assert!(released.unwrap(), "{path} is released");
    }
    project_tree(conn);
}

pub(super) fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.to_string()) }
}

/// One round of writes by each of `authors`, the `i`-th of them on the
/// `i`-th set of paths: a file below a structural directory that flips
/// between two contents, an explicit directory that flips between two
/// modes with a file below it, a path that is written and deleted in
/// alternate rounds, and one path every author writes with the same bytes
/// -- concurrent writes of it are distinct heads, never collapsed.
///
/// Each author has been shown every version of the paths it writes -- the
/// conflict copies of the ones that lost there included -- so it names
/// every head the installed base carries at them. An author that had not
/// seen its own earlier version would leave it live beside its new one,
/// and no base can carry two heads of one author at a path.
fn write_round(conn: &Connection, round: u32, authors: &[&str]) {
    store_versions(conn);
    store_directories(conn);
    let odd = round % 2 == 1;
    for (i, author) in authors.iter().enumerate() {
        let tmp = format!("tmp{i}");
        let ops = vec![
            put("shared", &version(1)),
            put(&format!("d{i}/f"), &version(if odd { 2 } else { 3 })),
            put(&format!("dir{i}"), &directory(if odd { 0o700 } else { 0o755 })),
            put(&format!("dir{i}/x"), &version(4)),
            if odd { put(&tmp, &version(5)) } else { delete(&tmp) },
        ];
        let mut seen = crate::dag_store::SeenVersions::new();
        for op in &ops {
            let (Op::Put { path, .. } | Op::Delete { path }) = op else { continue };
            let mut stmt = conn
                .prepare(
                    "SELECT change_hash FROM history_base_path_heads \
                     WHERE group_id = ?1 AND path = ?2",
                )
                .unwrap();
            let heads = stmt
                .query_map(rusqlite::params![GROUP, path.as_str()], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|hash| ChangeHash(hash.unwrap().try_into().unwrap()));
            seen.entry(path.as_str().to_string()).or_default().extend(heads);
        }
        crate::dag_store::emit_local_change_seeing(
            conn,
            GROUP,
            ops,
            &seen,
            &ChangeEmitter::new(*author, super::seal_tests::key(author)),
        )
        .unwrap();
    }
}

/// A directory's filesystem identity; `inode` tells one object from
/// another.
fn dir_identity(inode: u64) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 7 },
        object_id: PlatformObjectId::Unix { inode },
        object_kind: ObjectKind::Directory,
        generation_or_usn: Some(1),
        birth_or_creation_time: Some(Timestamp {
            seconds_since_unix_epoch: 1_700_000_000,
            subsec_nanos: 0,
        }),
        observed_size: 64,
        metadata_fingerprint: [1; 32],
        link_count: Some(2),
        symlink_target_digest: None,
    }
}

/// What this device's materializer records about the directories it keeps
/// on disk in a round: it recreates each structural directory (a new
/// object each time, bracketed by intent and completion), leaves one
/// intent pending as a crash would, and keeps a deleted path's directory
/// that still holds something untracked.
fn record_directory_ledger(conn: &Connection, round: u32, authors: usize) {
    let now = i64::from(round) * 1_000;
    for i in 0..authors {
        let path = format!("d{i}");
        let object = u64::from(round) * 100 + i as u64;
        crate::structural_origin::record_structural_intent(conn, GROUP, &path, now).unwrap();
        crate::structural_origin::complete_structural_origin(
            conn,
            GROUP,
            &path,
            &dir_identity(object),
            now + 1,
        )
        .unwrap();
        let pending = format!("d{i}/pending");
        crate::structural_origin::record_structural_intent(conn, GROUP, &pending, now).unwrap();
        crate::structural_origin::record_retained_directory(
            conn,
            GROUP,
            &format!("tmp{i}"),
            "retained: local untracked content",
            Some(&dir_identity(object + 50)),
            now,
        )
        .unwrap();
    }
}

/// The device-local directory ledger, row by row. The per-path mutation
/// fences are not part of it: a seal or an install moves the fence of every
/// path whose rows it replaces, which is what refuses a structural
/// completion racing it, and a fence is one row per path however often it
/// moves.
fn directory_ledger(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    for table in [
        "structural_directory_intents",
        "structural_directory_origins",
        "structural_provenance_lost",
        "retained_directories",
    ] {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY path")).unwrap();
        let columns = stmt.column_count();
        let rows = stmt
            .query_map([], |row| {
                let values: Vec<rusqlite::types::Value> =
                    (0..columns).map(|i| row.get(i)).collect::<Result<_, _>>()?;
                Ok(format!("{table} {values:?}"))
            })
            .unwrap();
        out.extend(rows.map(Result::unwrap));
    }
    out
}

/// Expires what the fixed retention policy expires, as the periodic
/// retention sweep does. Every fixture version is dated at the epoch, so only the count
/// bound keeps a row.
pub(super) fn expire_retention(conn: &Connection) {
    const FORTY_DAYS: i64 = 40 * 86_400 * 1_000_000_000;
    crate::file_index::expire_superseded_and_trashed_versions_in_tx(
        conn,
        GROUP,
        FORTY_DAYS,
        &HashSet::new(),
    )
    .unwrap();
}

/// Seals `conn` over the writes of the round.
fn publish_project_and_seal(conn: &Connection, checkpoint_seq: u64) {
    publish(conn, checkpoint_seq);
    project_tree(conn);
    seal(conn);
}

/// Every stored base snapshot and checkpoint header belongs to the base the
/// group stands on.
fn assert_only_the_installed_snapshot_is_kept(conn: &Connection, context: &str) {
    let installed: Vec<u8> = conn
        .query_row(
            "SELECT checkpoint_hash FROM group_history_bases WHERE group_id = ?1",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    let stored: Vec<Vec<u8>> = {
        let mut stmt = conn
            .prepare("SELECT checkpoint_hash FROM change_checkpoint_snapshots WHERE group_id = ?1")
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    assert_eq!(
        stored,
        vec![installed],
        "{context}: a replica keeps the snapshot of the base it stands on and no other"
    );
    let headers: Vec<Vec<u8>> = {
        let mut stmt = conn
            .prepare("SELECT checkpoint_hash FROM change_checkpoints WHERE group_id = ?1")
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    assert_eq!(
        headers, stored,
        "{context}: a replica keeps the checkpoint header of the base it stands on and no other"
    );
    verify_current_base(conn, GROUP).expect("the installed base still verifies");
}

/// `left` seals a first round and `right` joins by installing its base.
fn two_replicas_on_one_base() -> (Connection, Connection) {
    let left = open();
    write_round(&left, 1, &["device-a", "device-b"]);
    publish_project_and_seal(&left, 1);
    let sealed = verify_current_base(&left, GROUP).unwrap();
    let mut right = open();
    let tx = right.transaction().unwrap();
    install_base_for_tests(&tx, sealed.checkpoint(), sealed.snapshot()).unwrap();
    tx.commit().unwrap();
    reconcile(&right);
    (left, right)
}

/// Each seal stores the snapshot and header of the base it mints. The base
/// it leaves is not served, merged or verified again -- only the installed
/// one is -- so its snapshot, a copy of every row the group held, goes with
/// it, and so does its header, which every open would otherwise re-verify.
#[test]
fn a_seal_keeps_only_the_snapshot_of_the_base_it_installs() {
    reset_author_sequences();
    let conn = open();
    for round in 1..=4u32 {
        write_round(&conn, round, &["device-a"]);
        publish_project_and_seal(&conn, u64::from(round));
        assert_only_the_installed_snapshot_is_kept(&conn, &format!("seal {round}"));
    }
}

/// The same for the base a merge installs, minted or adopted as it is.
#[test]
fn a_merge_keeps_only_the_snapshot_of_the_base_it_installs() {
    reset_author_sequences();
    let (left, right) = two_replicas_on_one_base();
    for round in 2..=4u32 {
        write_round(&left, round, &["device-a"]);
        write_round(&right, round, &["device-c"]);
        publish_project_and_seal(&left, u64::from(round) * 2);
        publish_project_and_seal(&right, u64::from(round) * 2 + 1);
        let minted = merge(&left, &as_returning(&right, "device-c"));
        assert!(matches!(minted.base, MergedBase::Minted(_)), "{:?}", minted.base);
        assert_only_the_installed_snapshot_is_kept(&left, &format!("minted merge {round}"));
        let adopted = merge(&right, &as_returning(&left, "device-a"));
        assert!(matches!(adopted.base, MergedBase::Returning(_)), "{:?}", adopted.base);
        assert_only_the_installed_snapshot_is_kept(&right, &format!("adopted merge {round}"));
        reconcile(&left);
        reconcile(&right);
    }
}

/// What one replica holds after a round.
struct Round {
    tables: BTreeMap<String, i64>,
    snapshot_bytes: i64,
    largest_checkpoint_header: i64,
    bases: i64,
}

/// Round after round, two replicas write the same paths -- three authors,
/// files, explicit and structural directories, deletes, concurrent writes
/// of identical bytes -- seal apart and merge, and the materializer
/// records its directories on disk. Once the retention window is full the
/// database stops growing: every table holds exactly what it held two
/// rounds earlier (the workload repeats every two rounds), the checkpoint
/// headers included. The authorization evidence is the one exception:
/// which change authored each retained row shifts round to round, so the
/// evidence rows, the carried authors and the checkpoints covering them
/// move, but never above the most the rounds just before the steady window
/// held. Along the way `Gamma` never holds
/// more heads for a path than there are authors, no path keeps more rows
/// than the retention policy allows, and seals and merges leave the
/// device-local directory ledger exactly as it was.
#[test]
fn metadata_stops_growing_across_repeated_seals_and_merges() {
    const ROUNDS: u32 = 30;
    const STEADY_FROM: u32 = 20;
    let authors_left = ["device-a", "device-b"];
    let authors_right = ["device-c"];
    let author_count = authors_left.len() + authors_right.len();

    reset_author_sequences();
    let (left, right) = two_replicas_on_one_base();
    let mut history: BTreeMap<(u32, &str), Round> = BTreeMap::new();
    for round in 2..=ROUNDS {
        write_round(&left, round, &authors_left);
        write_round(&right, round, &authors_right);
        record_directory_ledger(&left, round, authors_left.len());
        record_directory_ledger(&right, round, authors_right.len());
        let ledgers = (directory_ledger(&left), directory_ledger(&right));

        publish_project_and_seal(&left, u64::from(round) * 2);
        publish_project_and_seal(&right, u64::from(round) * 2 + 1);
        let minted = merge(&left, &as_returning(&right, "device-c"));
        assert!(matches!(minted.base, MergedBase::Minted(_)), "round {round}: {:?}", minted.base);
        let adopted = merge(&right, &as_returning(&left, "device-a"));
        assert!(matches!(adopted.base, MergedBase::Returning(_)), "round {round}");
        assert_eq!(
            (directory_ledger(&left), directory_ledger(&right)),
            ledgers,
            "round {round}: a seal or a merge rewrote the device-local directory ledger"
        );
        reconcile(&left);
        reconcile(&right);

        for (side, conn) in [("left", &left), ("right", &right)] {
            // The periodic sweep. The evidence behind a row it expires is
            // collected by the next seal.
            expire_retention(conn);
            assert_eq!(count(conn, "SELECT COUNT(*) FROM changes"), 0, "{side} round {round}");
            let summary = history_base_summary(conn, GROUP).unwrap().unwrap();
            assert_eq!(summary.author_state.len(), author_count, "{side} round {round}: |W|");
            let mut heads_per_path: BTreeMap<&str, usize> = BTreeMap::new();
            for head in &summary.path_heads {
                *heads_per_path.entry(head.path.as_str()).or_default() += 1;
            }
            for (path, heads) in &heads_per_path {
                assert!(
                    *heads <= author_count,
                    "{side} round {round}: {path} has {heads} heads for {author_count} authors"
                );
            }
            assert_eq!(heads_per_path["shared"], 2, "identical concurrent writes stay distinct");
            let most_rows_of_one_path = count(
                conn,
                "SELECT COALESCE(MAX(n), 0) FROM (SELECT COUNT(*) AS n FROM files GROUP BY path)",
            );
            assert!(
                most_rows_of_one_path <= crate::file_index::RETENTION_MAX_VERSIONS + 1,
                "{side} round {round}: a path keeps {most_rows_of_one_path} rows"
            );
            history.insert(
                (round, side),
                Round {
                    tables: census(conn),
                    snapshot_bytes: snapshot_bytes(conn),
                    largest_checkpoint_header: count(
                        conn,
                        "SELECT MAX(LENGTH(encoded)) FROM change_checkpoints",
                    ),
                    bases: count(conn, "SELECT COUNT(*) FROM change_checkpoints"),
                },
            );
        }
    }

    for round in STEADY_FROM..=ROUNDS {
        for side in ["left", "right"] {
            // The most the side held of a table in the eight rounds before
            // the steady window: a leak of even one row every other round
            // passes it within the window.
            let ceiling = |table: &str| {
                (STEADY_FROM - 8..STEADY_FROM)
                    .map(|r| history[&(r, side)].tables[table])
                    .max()
                    .unwrap()
            };
            let now = &history[&(round, side)];
            let before = &history[&(round - 2, side)];
            let mut grew: Vec<String> = Vec::new();
            for (table, rows) in &now.tables {
                let earlier = before.tables.get(table).copied().unwrap_or(0);
                let steady = match table.as_str() {
                    // Which change authored each retained row moves round to
                    // round -- the materializer rewrites a row whose bytes a
                    // newer head repeats -- so the evidence a base carries
                    // for them, and the checkpoints covering it, move too.
                    "change_authorization"
                    | "history_base_carried_authors"
                    | "authorization_checkpoints" => *rows <= ceiling(table),
                    _ => *rows == earlier,
                };
                if !steady {
                    grew.push(format!("{table}: {earlier} -> {rows}"));
                }
            }
            assert!(grew.is_empty(), "{side} round {round}: tables still changing: {grew:?}");
            // Exact bytes move a little as the witnesses' inclusion proofs
            // change depth; a stored copy per base would add the whole
            // snapshot every round.
            assert!(
                now.snapshot_bytes * 10 <= before.snapshot_bytes * 11,
                "{side} round {round}: stored snapshot bytes {} -> {}",
                before.snapshot_bytes,
                now.snapshot_bytes
            );
            assert!(
                now.largest_checkpoint_header <= before.largest_checkpoint_header,
                "{side} round {round}: a checkpoint header grew from {} to {} bytes",
                before.largest_checkpoint_header,
                now.largest_checkpoint_header
            );
            assert_eq!(now.bases, 1, "{side} round {round}: checkpoint headers kept");
        }
    }
    let last = &history[&(ROUNDS, "left")];
    eprintln!(
        "after {ROUNDS} rounds: {} checkpoint headers kept, largest header {} bytes, \
         {} snapshot bytes stored, tables {:?}",
        last.bases,
        last.largest_checkpoint_header,
        last.snapshot_bytes,
        last.tables.iter().filter(|(_, rows)| **rows > 0).collect::<BTreeMap<_, _>>()
    );
}
