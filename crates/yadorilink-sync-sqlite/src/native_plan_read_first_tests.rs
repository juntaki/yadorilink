//! A path's plan is read first and written only when it has a placement to
//! record. Pins that a plan with nothing to record opens no write
//! transaction, that one with something to record still records it, and that
//! a write transaction plans again from scratch instead of trusting what the
//! read saw.

use std::collections::BTreeSet;
use std::sync::Arc;

use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::native_plan::{NativeLevelPlan, NativePlannedNode};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::file_index::FileIndexRepository;
use crate::native_projection_binding::numbered_copy_name;
use crate::SyncSqliteError;

/// The `n`-th file version in winner order: `ranked(1)` beats `ranked(2)`.
fn ranked(n: usize) -> FileVersion {
    let mut pool: Vec<FileVersion> = (1..=4)
        .map(|mtime| {
            FileVersion::new(
                Vec::new(),
                0,
                FileMeta {
                    mtime_unix_nanos: mtime,
                    unix_mode: Some(0o644),
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: Vec::new(),
                },
            )
        })
        .collect();
    pool.sort_by_key(|v| std::cmp::Reverse(v.version_hash));
    pool.swap_remove(n - 1)
}

struct Contested {
    db: Arc<SyncDatabase>,
    repo: FileIndexRepository,
    /// The version that loses `x`, so is given a conflict copy.
    loser: FileVersion,
}

/// `x` holds two concurrent heads and nothing has recorded where the losing
/// one's copy goes yet: the state right after a peer's concurrent edit lands.
fn contested() -> Contested {
    let db = crate::replica_tables::open_for_tests();
    let (winner, loser) = (ranked(1), ranked(2));
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        for (device, seq, version) in [("a", 1, &winner), ("b", 2, &loser)] {
            crate::dag_store::put_file_version(tx, "g", version)?;
            tx.execute(
                "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
                 provenance) VALUES ('g', 'x', ?1, zeroblob(16), ?2, ?3, ?3)",
                rusqlite::params![device, seq, version.version_hash.0.as_slice()],
            )?;
        }
        Ok(())
    })
    .unwrap();
    Contested { repo: FileIndexRepository::new(db.clone()), db, loser }
}

impl Contested {
    fn placements(&self) -> Vec<String> {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT physical_path FROM native_physical_placement ORDER BY physical_path",
                )?;
                let rows = stmt.query_map([], |r| r.get(0))?;
                Ok(rows.collect::<Result<Vec<String>, _>>()?)
            })
            .unwrap()
    }

    /// What a write transaction planning `x` from scratch gives now.
    fn reference(&self) -> NativeLevelPlan {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::native_desired_state::native_plan_nodes(tx, "g", "", &names())
            })
            .unwrap()
    }
}

/// Records the head `loser` put at `x` as copied to `physical`, as another
/// planner of the same path would have.
fn record_copy_at(db: &SyncDatabase, loser: [u8; 32], physical: &str) {
    let row = crate::stable_projection_binding::NativePlacementRow {
        physical_path: physical.to_owned(),
        source_path: "x".to_owned(),
        author: "b".to_owned(),
        incarnation: [0; 16],
        seq: 2,
        provenance: loser,
        version: loser,
        origin: "conflict_copy".to_owned(),
    };
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        crate::stable_projection_binding::native_placement_put(tx, "g", &row)
    })
    .unwrap();
}

fn names() -> BTreeSet<String> {
    BTreeSet::from(["x".to_owned()])
}

fn copy_names(plan: &NativeLevelPlan) -> Vec<String> {
    plan.nodes
        .iter()
        .filter(|(physical, node)| {
            physical.as_str() != "x"
                && matches!(node, NativePlannedNode::Entry { head, .. }
                    if head.source_path.as_str() == "x")
        })
        .map(|(physical, _)| physical.as_str().to_owned())
        .collect()
}

#[test]
fn a_plan_with_nothing_to_record_opens_no_write_transaction() {
    let w = contested();
    let planned = w.repo.native_plan_nodes("g", "", &names()).unwrap();
    assert_eq!(copy_names(&planned).len(), 1, "fixture: the loser has a copy");

    let before = w.db.write_transaction_count();
    let nodes = w.repo.native_plan_nodes("g", "", &names()).unwrap();
    let node = w.repo.native_plan_node("g", "x").unwrap();
    assert_eq!(
        w.db.write_transaction_count(),
        before,
        "planning a path whose placements are all recorded must not open a write transaction"
    );
    assert_eq!(nodes, planned);
    assert_eq!(node.as_ref(), planned.nodes.get(&SyncPath("x".to_owned())));
}

#[test]
fn a_plan_that_needs_a_placement_records_it() {
    let w = contested();
    assert!(w.placements().is_empty(), "fixture: nothing is recorded yet");

    let planned = w.repo.native_plan_nodes("g", "", &names()).unwrap();

    let copy = numbered_copy_name("x", w.loser.version_hash.0, 1);
    assert_eq!(copy_names(&planned), vec![copy.clone()]);
    assert_eq!(
        w.placements(),
        vec![copy],
        "the copy's name must be recorded, or the next plan may name it differently"
    );
    assert_eq!(planned, w.reference());
}

/// Another planner records the copy under another name after this plan's
/// read found it unrecorded and before its write transaction begins. The
/// write must plan from what is recorded then: the other planner's name,
/// and no second copy of the same head.
#[test]
fn a_placement_recorded_between_the_read_and_the_write_is_planned_from() {
    let w = contested();
    let theirs = numbered_copy_name("x", w.loser.version_hash.0, 2);
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_fired = fired.clone();
    let db = w.db.clone();
    let loser = w.loser.version_hash.0;
    let hook_theirs = theirs.clone();
    crate::file_index::set_between_plan_phases_hook(Box::new(move || {
        hook_fired.store(true, std::sync::atomic::Ordering::SeqCst);
        record_copy_at(&db, loser, &hook_theirs);
    }));

    let planned = w.repo.native_plan_nodes("g", "", &names()).unwrap();

    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "the read must have asked for a write"
    );
    assert_eq!(
        copy_names(&planned),
        vec![theirs.clone()],
        "the plan must use the copy name recorded before its write, not decide from its read"
    );
    assert_eq!(w.placements(), vec![theirs], "no second copy of the same head is recorded");
    assert_eq!(planned, w.reference());
}
