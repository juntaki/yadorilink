//! Pins what planning one directory level costs once the group holds many
//! conflict copies elsewhere: the placements, stable names and index rows a
//! plan reads must be those of its own level, never the whole group's.

use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::native_state::{DeltaHash, HeadPayload, NativeState};

const FILES_PER_DIR: usize = 50;

fn group() -> FolderGroupId {
    FolderGroupId("g".to_string())
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_string()), incarnation: IncarnationId([1; 16]) }
}

fn file(mtime: i64) -> FileVersion {
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
}

fn payload(v: &FileVersion) -> HeadPayload {
    HeadPayload { version: v.version_hash, provenance: DeltaHash(v.version_hash.0) }
}

fn count_vm_work(c: &Connection) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = ticks.clone();
    c.progress_handler(
        1000,
        Some(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }),
    );
    ticks
}

/// A group of `dirs` directories with `FILES_PER_DIR` contested files each (one
/// conflict copy per file), every level planned once so the copies are named.
fn conflicted_group(dirs: usize) -> (Connection, FileVersion, FileVersion) {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    let (win, lose) = (file(1), file(2));
    for v in [&win, &lose] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let mut state = NativeState::new();
    for d in 0..dirs {
        for f in 0..FILES_PER_DIR {
            let path = SyncPath(format!("dir-{d:03}/file-{f:03}"));
            state.put(&author("a"), path.clone(), &[], payload(&win)).unwrap();
            state.put(&author("b"), path, &[], payload(&lose)).unwrap();
        }
    }
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    for d in 0..dirs {
        crate::native_desired_state::native_plan_level(&c, "g", &format!("dir-{d:03}")).unwrap();
    }
    (c, win, lose)
}

/// The SQLite work of replanning one unchanged level, and of planning the
/// level a new conflict landed in the way a delta's arrival does.
fn level_plan_costs(dirs: usize) -> (u64, u64) {
    let (c, win, lose) = conflicted_group(dirs);
    let ticks = count_vm_work(&c);
    let level = |ticks: &std::sync::atomic::AtomicU64, body: &dyn Fn()| {
        ticks.store(0, std::sync::atomic::Ordering::Relaxed);
        body();
        ticks.load(std::sync::atomic::Ordering::Relaxed)
    };
    let steady = level(&ticks, &|| {
        crate::native_desired_state::native_plan_level(&c, "g", "dir-000").unwrap();
    });
    for (i, v) in [(1i64, &win), (2, &lose)] {
        c.execute(
            "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
             provenance) VALUES ('g', 'dir-000/new', ?1, zeroblob(16), 900, ?2, ?2)",
            rusqlite::params![if i == 1 { "c" } else { "d" }, v.version_hash.0.as_slice()],
        )
        .unwrap();
    }
    let arrival = level(&ticks, &|| {
        crate::native_projection_binding::ensure_native_placements_around(&c, "g", "dir-000/new")
            .unwrap();
        crate::native_desired_state::native_plan_level(&c, "g", "dir-000").unwrap();
    });
    (steady, arrival)
}

#[test]
fn planning_a_level_costs_its_own_size_however_many_copies_the_group_holds() {
    let (small_steady, small_arrival) = level_plan_costs(50);
    let (large_steady, large_arrival) = level_plan_costs(100);
    eprintln!(
        "2500 copies: steady {small_steady}, arrival {small_arrival}; 5000 copies: steady \
         {large_steady}, arrival {large_arrival} (vm work, thousands of instructions)"
    );
    assert!(
        (large_steady as f64) <= 1.3 * small_steady as f64,
        "doubling the copies in the group grew one level's replan from {small_steady} to \
         {large_steady}"
    );
    assert!(
        (large_arrival as f64) <= 1.3 * small_arrival as f64,
        "doubling the copies in the group grew a delta's level plan from {small_arrival} to \
         {large_arrival}"
    );
}

/// What reading a level's records reads: its own placements and stable names,
/// at any group size.
#[test]
fn a_level_plan_reads_the_placements_and_names_of_its_own_level() {
    use crate::stable_projection_binding::level_row_counters;
    for dirs in [50usize, 100] {
        let (c, _, _) = conflicted_group(dirs);
        level_row_counters::reset();
        crate::native_desired_state::native_plan_level(&c, "g", "dir-000").unwrap();
        let (placements, bindings) = level_row_counters::snapshot();
        eprintln!("{dirs} dirs: {placements} placement rows, {bindings} binding rows");
        // A few reads of the level's 50 copies, none of the group's other ones.
        assert!(placements <= 4 * FILES_PER_DIR as u64, "{dirs} dirs: {placements} placements");
        assert!(bindings <= 4 * FILES_PER_DIR as u64, "{dirs} dirs: {bindings} bindings");
    }
}

/// The records a level's plan reads are enough: planning from them gives the
/// plan the whole group's records give, for levels with and without recorded
/// copies, and for a relocation.
#[test]
fn a_levels_scoped_records_plan_exactly_as_the_whole_groups_do() {
    use std::collections::BTreeSet;

    use yadorilink_replica_domain::native_resolver as resolver;

    use crate::native_projection_binding::{
        placement_records, placement_records_in_levels, OwnedLevelSnapshot,
    };

    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    let (win, lose) = (file(1), file(2));
    for v in [&win, &lose] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let mut state = NativeState::new();
    let contested = |state: &mut NativeState, path: &str| {
        let path = SyncPath(path.to_owned());
        state.put(&author("a"), path.clone(), &[], payload(&win)).unwrap();
        state.put(&author("b"), path, &[], payload(&lose)).unwrap();
    };
    for dir in ["dir-a", "dir-b", "dir-c/deep"] {
        for f in 0..4 {
            contested(&mut state, &format!("{dir}/file-{f}"));
        }
    }
    contested(&mut state, "top");
    // A file with a directory need below it is relocated.
    contested(&mut state, "moved");
    state.put(&author("a"), SyncPath("moved/child".into()), &[], payload(&win)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();

    let levels = ["", "dir-a", "dir-b", "dir-c", "dir-c/deep", "moved"];
    let compare = |when: &str| {
        let mut planned_ops = 0;
        for parent in levels {
            let (children, _) =
                crate::native_store::native_heads_at_level(&c, &group(), parent).unwrap();
            let heads: std::collections::BTreeMap<_, _> = children.into_iter().collect();
            let scope = BTreeSet::from([parent.to_owned()]);
            let scoped = OwnedLevelSnapshot::read(&c, "g", &heads).unwrap();
            let whole = OwnedLevelSnapshot::read_with(
                &c,
                "g",
                &heads,
                placement_records(&c, "g").unwrap(),
                crate::stable_projection_binding::native_bindings(&c, "g").unwrap(),
            )
            .unwrap();
            let plan = |snapshot: &OwnedLevelSnapshot| {
                resolver::plan_placements_with(&snapshot.view(&heads), &|_| false)
            };
            assert_eq!(plan(&scoped), plan(&whole), "{when}: ops of level {parent:?}");
            planned_ops += plan(&scoped).len();
            let on_level = |records: Vec<resolver::PlacementRecord>| {
                let mut on_level: Vec<_> = records
                    .into_iter()
                    .filter(|r| {
                        crate::stable_projection_binding::parent_of(&r.physical_path) == parent
                    })
                    .map(|r| r.physical_path)
                    .collect();
                on_level.sort();
                on_level
            };
            assert_eq!(
                on_level(placement_records_in_levels(&c, "g", &scope).unwrap()),
                on_level(placement_records(&c, "g").unwrap()),
                "{when}: placements on level {parent:?}"
            );
        }
        planned_ops
    };
    assert!(compare("nothing planned") > 0, "an unplanned group has copies to name");
    for parent in ["dir-a", "dir-c/deep", "moved"] {
        crate::native_desired_state::native_plan_level(&c, "g", parent).unwrap();
    }
    compare("some levels planned");
    for parent in levels {
        crate::native_desired_state::native_plan_level(&c, "g", parent).unwrap();
    }
    compare("every level planned");
    // A new conflict at an already planned level.
    c.execute(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
         provenance) VALUES ('g', 'dir-a/new', 'x', zeroblob(16), 7, ?1, ?1), \
         ('g', 'dir-a/new', 'y', zeroblob(16), 7, ?2, ?2)",
        rusqlite::params![win.version_hash.0.as_slice(), lose.version_hash.0.as_slice()],
    )
    .unwrap();
    assert!(compare("a conflict added to a planned level") > 0, "the new copy is named");
}

/// A directory of `files` plain files, one head each.
fn flat_directory(files: usize) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    let v = file(1);
    crate::dag_store::put_file_version(&c, "g", &v).unwrap();
    let mut state = NativeState::new();
    for f in 0..files {
        state.put(&author("a"), SyncPath(format!("big/file-{f:06}")), &[], payload(&v)).unwrap();
    }
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    c
}

/// Planning one level of a directory with `files` entries: its SQLite work and
/// wall time.
fn flat_level_cost(files: usize) -> (u64, std::time::Duration) {
    let c = flat_directory(files);
    let ticks = count_vm_work(&c);
    let started = std::time::Instant::now();
    crate::native_desired_state::native_plan_level(&c, "g", "big").unwrap();
    (ticks.load(std::sync::atomic::Ordering::Relaxed), started.elapsed())
}

/// One plan is linear in the entries of its level (and no more: the level is
/// what it has to describe). The reconcile pass asks for the level of every
/// path it settles, so a pass over a large directory costs entries times this.
#[test]
fn planning_a_directory_level_is_linear_in_its_entries() {
    let (small, _) = flat_level_cost(1000);
    let (large, _) = flat_level_cost(2000);
    eprintln!("plan of 1000 entries: {small} vm work; of 2000: {large}");
    assert!((large as f64) <= 2.3 * small as f64, "{small} -> {large}");
}

/// `cargo nextest run -p yadorilink-sync-sqlite --lib --run-ignored only
/// plan_of_a_10k_file_directory --no-capture`.
#[test]
#[ignore = "10k-entry measurement; run explicitly"]
fn plan_of_a_10k_file_directory() {
    let (ticks, wall) = flat_level_cost(10_000);
    eprintln!(
        "one plan of a 10000-entry level: {ticks}k vm, {wall:?}; a pass settling every entry \
         plans it once per path: {:?}",
        wall * 10_000
    );
}

/// The copies recorded for one source path are an indexed read: authoring an
/// edit and settling a path both ask for them.
#[test]
fn the_copies_of_one_source_cost_the_same_at_any_group_size() {
    let cost = |dirs: usize| {
        let (c, _, _) = conflicted_group(dirs);
        let ticks = count_vm_work(&c);
        for f in 0..FILES_PER_DIR {
            let copies = crate::stable_projection_binding::native_placements_for_source(
                &c,
                "g",
                &format!("dir-000/file-{f:03}"),
            )
            .unwrap();
            assert_eq!(copies.len(), 1);
        }
        ticks.load(std::sync::atomic::Ordering::Relaxed)
    };
    let (small, large) = (cost(50), cost(100));
    eprintln!("{FILES_PER_DIR} lookups: {small} vm work at 2500 copies, {large} at 5000");
    assert!((large as f64) <= 1.3 * small as f64, "{small} -> {large}");
}
