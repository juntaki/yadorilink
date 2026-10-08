#![cfg(test)]

//! The retirement pass reads its candidate rows through an index on the
//! conflict-copy marker and asks the head table about each one, where it
//! once decoded the whole group and loaded every head path. These tests hold
//! the indexed read to the whole-group read it replaced.

use std::collections::BTreeSet;

use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};

use super::receive_cost_tests::{fixture, GROUP};
use crate::local_convergence::types::file_record_from_version;
use crate::test_support::remote_admission_fixture::{admit_remote, put};

fn version(seed: i64) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: seed + 1,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

const MARK: &str = "(conflicted copy, 2026-01-01, device-peer, ab12)";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_candidates_match_the_full_scan() {
    let f = fixture(true).await;
    let files = f.state.replica_coordinator.file_index_repository();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let write = |group: &str, path: &str, seed: i64, deleted: bool| {
        let mut record = file_record_from_version(path, &version(seed));
        record.deleted = deleted;
        files
            .upsert_files_batch(group, &[record], "device-peer", &[], &[], &permit)
            .expect("write row");
    };

    // Live rows: ordinary, carried copies, unjustified copies, a copy-shaped
    // name inside a directory component only, a marker without a filename
    // stem, a copy with no extension, and a nested copy.
    let ordinary = ["a/plain.txt", "b/other.bin", "top.md"];
    let carried = [format!("a/doc {MARK}.txt"), format!("deep/er/x {MARK}")];
    let unjustified = [format!("a/loose {MARK}.txt"), format!("b/also {MARK}.bin")];
    let directory_only = [format!("dir {MARK}/inner.txt")];
    let tombstoned = [format!("a/gone {MARK}.txt")];
    let mut seed = 0;
    let mut admitted = Vec::new();
    for path in ordinary.iter().map(|p| p.to_string()).chain(carried.iter().cloned()) {
        let v = version(seed);
        admit_remote(
            &f.state.replica_coordinator,
            GROUP,
            "device-peer",
            vec![put(&path, v.version_hash, vec![])],
            std::slice::from_ref(&v),
        );
        admitted.push(path);
        seed += 1;
    }
    for path in admitted.iter().chain(&unjustified).chain(&directory_only) {
        write(GROUP, path, seed, false);
        seed += 1;
    }
    for path in &tombstoned {
        write(GROUP, path, seed, true);
        seed += 1;
    }
    // Another group's rows never appear in this group's read.
    write("other-group", &format!("z/elsewhere {MARK}.txt"), seed, false);

    let executor = f.state.local_convergence();
    let (old_copies, old_heads) = executor.live_conflict_copy_shaped_by_full_scan(GROUP).unwrap();
    let new_copies = executor.live_conflict_copy_shaped(GROUP).unwrap();
    let names = |rows: &[yadorilink_replica_domain::file::FileRecord]| -> BTreeSet<String> {
        rows.iter().map(|r| r.path.clone()).collect()
    };
    assert_eq!(names(&new_copies), names(&old_copies));
    assert_eq!(
        names(&new_copies),
        carried.iter().chain(&unjustified).cloned().collect::<BTreeSet<_>>(),
        "carried and unjustified copies are candidates; tombstones, directory-only markers, \
         other groups and ordinary rows are not"
    );
    for record in old_copies.iter().chain(&new_copies) {
        assert_eq!(
            f.state.replica_coordinator.native_path_has_heads(GROUP, &record.path).unwrap(),
            old_heads.contains(&record.path),
            "{}",
            record.path
        );
    }
    let retained: BTreeSet<String> = new_copies
        .iter()
        .filter(|r| !f.state.replica_coordinator.native_path_has_heads(GROUP, &r.path).unwrap())
        .map(|r| r.path.clone())
        .collect();
    assert_eq!(retained, unjustified.iter().cloned().collect::<BTreeSet<_>>());
}

/// The marker index is what keeps the read off the whole group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_read_uses_the_marker_index() {
    let f = fixture(true).await;
    let plan: String = f
        .state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                yadorilink_sync_sqlite::file_index::CONFLICT_COPY_CANDIDATES_SQL
            ))?;
            let rows = stmt.query_map([GROUP], |r| r.get::<_, String>(3))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?.join(" | "))
        })
        .unwrap();
    assert!(plan.contains("files_conflict_copy_candidates"), "{plan}");
}
