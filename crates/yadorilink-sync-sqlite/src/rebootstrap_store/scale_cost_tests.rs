#![cfg(test)]
//! What admission, a seal, an install and a merge cost as a group grows.
//!
//! A seal writes a snapshot of every row, and an install or a merge
//! replaces every row, so those are linear in the number of paths: the
//! claim is that the cost per path does not grow with the group, and that
//! a seal over a small amount of new history on a base of a fixed number
//! of rows costs the same however many seals came before it. Admitting or
//! authoring a change touches the paths it names -- one file, or a
//! directory and what it removes below it -- so its cost must not grow
//! with the group at all.
//!
//! The cost is counted, not timed: SQLite calls a progress handler at every
//! loop step of every statement it runs, and the number of calls is fixed
//! by the data and the queries, whatever else the machine is doing. A
//! query that walks a whole table where it should seek one row shows up as
//! a count that grows with the table. Rust-side work is not in that count;
//! the wall-clock time of each step is printed next to it for the record,
//! and never asserted.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::base_install_tests::open;
use super::bounded_metadata_tests::{delete, expire_retention};
use super::merge_install_tests::{as_returning, merge, publish, publish_leaves};
use super::seal_namespace_tests::{directory, project_tree, store_directories};
use super::seal_tests::{emit, put, seal, store_versions, version, GROUP};
use super::*;
use yadorilink_replica_domain::test_authoring::reset_author_sequences;

/// Paths written in one change while building a group.
const OPS_PER_CHANGE: usize = 5_000;
/// Changes written on top of a base before each measured seal.
const DELTA: usize = 20;
/// Rounds of rewrites before the repeated seals are measured: enough for
/// the retention bound to cap every rewritten path, so the group holds the
/// same number of rows at every measured seal.
const WARM_UP: usize = crate::file_index::RETENTION_MAX_VERSIONS as usize + 2;
/// Seals measured on that fixed number of rows.
const REPEATED_SEALS: usize = 6;

/// SQLite's loop steps while `work` runs on `conn`, and how long it took.
fn cost<T>(conn: &Connection, work: impl FnOnce() -> T) -> (T, u64, Duration) {
    let steps = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&steps);
    conn.progress_handler(
        1,
        Some(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }),
    );
    let started = Instant::now();
    let out = work();
    let elapsed = started.elapsed();
    conn.progress_handler(1, None::<fn() -> bool>);
    (out, steps.load(Ordering::Relaxed), elapsed)
}

/// The paths of a group of `files` files: a hundred files to a directory,
/// every such directory an explicit one, and ten of them to a structural
/// directory above.
fn tree(files: usize) -> Vec<(String, FileVersion)> {
    let mut entries = Vec::new();
    for i in 0..files {
        let (top, dir) = (i / 1_000, i / 100 % 10);
        if i % 100 == 0 {
            entries.push((format!("t{top}/s{dir}"), directory(0o755)));
        }
        entries.push((format!("t{top}/s{dir}/f{i}"), version((i % 9) as u8 + 1)));
    }
    entries
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
        crate::snapshot_install_hold::release_in_tx(conn, GROUP, &path, generation, 0).unwrap();
    }
    project_tree(conn);
}

/// `DELTA` single-path changes by `author`: a rewrite of an existing file,
/// or a new file, in turn. `seed` offsets the contents.
fn write_delta(conn: &Connection, author: &str, round: usize, seed: usize) -> Vec<Change> {
    store_versions(conn);
    (0..DELTA)
        .map(|i| {
            let path = if i % 2 == 0 {
                format!("t0/s0/f{i}")
            } else {
                format!("new/{author}/r{round}/f{i}")
            };
            emit(conn, author, vec![put(&path, &version(((i + round + seed) % 9) as u8 + 1))])
        })
        .collect()
}

/// `DELTA` changes by `author` that only rewrite existing files, between
/// two contents: once the retention bound caps them, the group holds as
/// many rows after a round as before it.
fn rewrite_delta(conn: &Connection, author: &str, round: usize) {
    store_versions(conn);
    for i in 0..DELTA {
        let path = format!("t0/s0/f{i}");
        emit(conn, author, vec![put(&path, &version(((i + round) % 2) as u8 + 1))]);
    }
}

/// Directory-kind changes by `author` on a tree of at least a thousand
/// files: a mode change of an explicit directory holding a hundred files,
/// a new explicit directory with a file below it, the removal of that
/// directory and its file, and the removal of another explicit directory
/// together with the hundred files below it.
fn write_directory_delta(conn: &Connection, author: &str) -> Vec<Change> {
    store_versions(conn);
    store_directories(conn);
    let mut subtree = vec![delete("t0/s9")];
    subtree.extend((900..1_000).map(|i| delete(&format!("t0/s9/f{i}"))));
    vec![
        emit(conn, author, vec![put("t0/s0", &directory(0o700))]),
        emit(conn, author, vec![put("newdir", &directory(0o755)), put("newdir/f", &version(1))]),
        emit(conn, author, vec![delete("newdir/f"), delete("newdir")]),
        emit(conn, author, subtree),
    ]
}

/// Admits every change of `changes` on `conn`, each one applied.
fn admit_all(conn: &Connection, changes: &[Change]) {
    for change in changes {
        let outcome = crate::dag_store::admit_change(conn, change).unwrap().outcome;
        assert!(matches!(outcome, crate::dag_store::AdmitOutcome::Applied), "{outcome:?}");
    }
}

fn file_rows(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM files WHERE group_id = ?1", [GROUP], |row| row.get(0))
        .unwrap()
}

/// What each step cost at one group size: SQLite loop steps, and time.
#[derive(Debug)]
struct Costs {
    entries: usize,
    first_seal: (u64, Duration),
    install: (u64, Duration),
    emit_per_change: (u64, Duration),
    admit_per_change: (u64, Duration),
    /// All the directory-kind changes of `write_directory_delta` together.
    directory_emit: (u64, Duration),
    directory_admit: (u64, Duration),
    /// Each repeated seal over `DELTA` rewrites, on the same number of
    /// rows.
    repeated_seals: Vec<(u64, Duration)>,
    merge: (u64, Duration),
}

fn per_entry(steps: u64, entries: usize) -> f64 {
    steps as f64 / entries as f64
}

/// Builds a group of `files` files, seals it, has a second replica join
/// it, and measures authoring, admission, repeated seals and a merge on
/// it.
fn measure(files: usize) -> Costs {
    reset_author_sequences();
    let left = open();
    store_versions(&left);
    store_directories(&left);
    let entries = tree(files);
    for chunk in entries.chunks(OPS_PER_CHANGE) {
        emit(&left, "device-a", chunk.iter().map(|(path, v)| put(path, v)).collect());
    }
    publish(&left, 1);
    project_tree(&left);
    let (_, steps, time) = cost(&left, || seal(&left));
    let first_seal = (steps, time);

    let right = open();
    let sealed = verify_current_base(&left, GROUP).unwrap();
    let (_, steps, time) = cost(&right, || {
        let tx = right.unchecked_transaction().unwrap();
        install_base_for_tests(&tx, sealed.checkpoint(), sealed.snapshot()).unwrap();
        tx.commit().unwrap();
    });
    let install = (steps, time);
    reconcile(&right);

    let (delta, steps, time) = cost(&left, || write_delta(&left, "device-a", 0, 0));
    let emit_per_change = (steps / DELTA as u64, time / DELTA as u32);
    store_versions(&right);
    let (_, steps, time) = cost(&right, || admit_all(&right, &delta));
    let admit_per_change = (steps / DELTA as u64, time / DELTA as u32);

    let (directory_changes, steps, time) = cost(&left, || write_directory_delta(&left, "device-a"));
    let directory_emit = (steps, time);
    store_directories(&right);
    let (_, steps, time) = cost(&right, || admit_all(&right, &directory_changes));
    let directory_admit = (steps, time);
    project_tree(&left);
    // Both replicas hold these changes, so both publish the one evidence
    // their author's checkpoint issued for them: a merge refuses two sides
    // that carry different evidence for one change.
    let shared: Vec<[u8; 32]> =
        delta.iter().chain(&directory_changes).map(|change| change.compute_hash().0).collect();
    publish_leaves(&left, 2, shared.clone());
    publish_leaves(&right, 2, shared);

    // Rewrites, each round published under its own authorization
    // checkpoint as in the measured rounds, until the retention bound caps
    // every rewritten path and the checkpoints covering what it keeps; then
    // one seal over all of it.
    let mut checkpoint = 2;
    for round in 0..WARM_UP {
        rewrite_delta(&left, "device-a", round);
        checkpoint += 1;
        publish(&left, checkpoint);
        project_tree(&left);
        expire_retention(&left);
    }
    seal(&left);
    let mut repeated_seals = Vec::new();
    let mut rows = Vec::new();
    for round in WARM_UP..WARM_UP + REPEATED_SEALS {
        rewrite_delta(&left, "device-a", round);
        checkpoint += 1;
        publish(&left, checkpoint);
        project_tree(&left);
        expire_retention(&left);
        rows.push(file_rows(&left));
        let (_, steps, time) = cost(&left, || seal(&left));
        repeated_seals.push((steps, time));
    }
    assert!(
        rows.iter().all(|n| *n == rows[0]),
        "the repeated seals run on the same number of rows: {rows:?}"
    );

    // The joiner writes apart, seals, and the sealer merges it back.
    write_delta(&right, "device-c", 0, 0);
    publish(&right, 101);
    project_tree(&right);
    seal(&right);
    let returning = as_returning(&right, "device-c");
    let (merged, steps, time) = cost(&left, || merge(&left, &returning));
    assert!(matches!(merged.base, MergedBase::Minted(_)), "{:?}", merged.base);
    let merge_cost = (steps, time);

    Costs {
        entries: entries.len(),
        first_seal,
        install,
        emit_per_change,
        admit_per_change,
        directory_emit,
        directory_admit,
        repeated_seals,
        merge: merge_cost,
    }
}

fn report(costs: &Costs) {
    let n = costs.entries;
    eprintln!(
        "{n} entries: first seal {} steps ({:.1}/entry) {:?}; install {} ({:.1}/entry) {:?}; \
         emit {} steps/change {:?}; admit {} steps/change {:?}; directory changes: emit {} \
         {:?}, admit {} {:?}; repeated seals {:?}; merge {} ({:.1}/entry) {:?}",
        costs.first_seal.0,
        per_entry(costs.first_seal.0, n),
        costs.first_seal.1,
        costs.install.0,
        per_entry(costs.install.0, n),
        costs.install.1,
        costs.emit_per_change.0,
        costs.emit_per_change.1,
        costs.admit_per_change.0,
        costs.admit_per_change.1,
        costs.directory_emit.0,
        costs.directory_emit.1,
        costs.directory_admit.0,
        costs.directory_admit.1,
        costs.repeated_seals,
        costs.merge.0,
        per_entry(costs.merge.0, n),
        costs.merge.1,
    );
}

/// `large` against `small`: per-entry costs of the linear steps within
/// `slack` of each other, per-change costs of the constant ones too, and
/// on a fixed number of rows, every repeated seal within a couple of steps
/// of the first: any work per base the group has been through -- a walk of
/// a table that gains a row per seal -- adds at least one step a seal.
fn assert_scales(small: &Costs, large: &Costs, slack: f64) {
    let linear = [
        ("first seal", small.first_seal.0, large.first_seal.0),
        ("install", small.install.0, large.install.0),
        ("merge", small.merge.0, large.merge.0),
    ];
    for (step, at_small, at_large) in linear {
        let (s, l) = (per_entry(at_small, small.entries), per_entry(at_large, large.entries));
        assert!(
            l <= s * slack,
            "{step}: {l:.1} steps per entry at {} entries against {s:.1} at {}",
            large.entries,
            small.entries
        );
    }
    let constant = [
        ("emit", small.emit_per_change.0, large.emit_per_change.0),
        ("admit", small.admit_per_change.0, large.admit_per_change.0),
        ("directory emit", small.directory_emit.0, large.directory_emit.0),
        ("directory admit", small.directory_admit.0, large.directory_admit.0),
    ];
    for (step, at_small, at_large) in constant {
        assert!(
            at_large as f64 <= at_small as f64 * slack,
            "{step}: {at_large} steps per change at {} entries against {at_small} at {}",
            large.entries,
            small.entries
        );
    }
    for costs in [small, large] {
        let steps: Vec<u64> = costs.repeated_seals.iter().map(|(steps, _)| *steps).collect();
        let (least, most) = (steps.iter().min().unwrap(), steps.iter().max().unwrap());
        assert!(
            most - least <= 2,
            "repeated seals over {} entries grow with the seals before them: {steps:?}",
            costs.entries
        );
    }
}

/// From a thousand files to ten thousand (and their directories): linear
/// steps stay linear, per-change steps stay flat.
#[test]
fn seal_install_merge_and_admission_costs_stay_in_proportion_to_ten_thousand_paths() {
    let small = measure(1_000);
    let large = measure(10_000);
    report(&small);
    report(&large);
    assert_scales(&small, &large, 1.25);
}

/// The same from ten thousand files to a hundred thousand. Ignored: it
/// builds, seals, installs and merges a group of 101,000 entries.
#[test]
#[ignore]
fn seal_install_merge_and_admission_costs_stay_in_proportion_to_a_hundred_thousand_paths() {
    let small = measure(10_000);
    let large = measure(100_000);
    report(&small);
    report(&large);
    assert_scales(&small, &large, 1.25);
}
