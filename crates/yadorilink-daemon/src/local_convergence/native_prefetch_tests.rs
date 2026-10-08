#![cfg(test)]
//! What native's plan says has to be fetched; these tests pin the
//! requirements prefetch acts on.

use super::growing_file_projection_tests::{Harness, GROUP};
use std::collections::BTreeSet;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;

fn put(path: &str, version: VersionHash) -> Op {
    Op::Put { path: SyncPath(path.into()), version }
}

fn store(h: &Harness, versions: &[&FileVersion]) {
    h.state
        .database()
        .write(|conn| {
            for version in versions {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
}

/// A peer's put that is concurrent with whatever the path holds.
fn concurrent_put(h: &Harness, device: &str, path: &str, version: &FileVersion) {
    store(h, &[version]);
    crate::test_support::remote_admission_fixture::admit_remote_ops(
        &h.state,
        GROUP,
        device,
        &[put(path, version.version_hash)],
        crate::test_support::remote_admission_fixture::Basis::Nothing,
    );
}

fn wanted(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

fn missing_version(size: u32, seed: u8) -> FileVersion {
    crate::test_support::sync_stack_fixture::file_version(size, seed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conflict_winner_and_its_copy_are_both_wanted() {
    let h = Harness::new(true);
    let (a, b) = (missing_version(10, 1), missing_version(11, 2));
    concurrent_put(&h, "device-r1", "x", &a);
    concurrent_put(&h, "device-r2", "x", &b);
    let paths = wanted(&["x"]);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &paths).unwrap();

    assert_eq!(native.len(), 2, "{native:?}");
    assert_eq!(native.iter().filter(|r| r.path == "x").count(), 1);
    let copy = native.iter().find(|r| r.path != "x").expect("a copy requirement");
    assert!(copy.path.starts_with("x"), "a sibling name of the source: {}", copy.path);
    let versions: BTreeSet<_> = native.iter().map(|r| r.version_hash).collect();
    assert_eq!(versions, BTreeSet::from([a.version_hash, b.version_hash]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_this_device_already_holds_is_not_wanted() {
    let h = Harness::new(true);
    std::fs::write(h.path("scratch"), b"already here").unwrap();
    h.capture("scratch").await;
    let held = VersionHash(h.own_head("scratch").content.unwrap().version_hash);
    let held = h.state.dag_get_file_version(GROUP, &held).unwrap().unwrap();
    concurrent_put(&h, "device-r1", "y", &held);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["y"])).unwrap();
    assert!(native.is_empty(), "{native:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_requested_sources_are_planned_even_when_a_level_holds_more() {
    let h = Harness::new(true);
    let (a, b) = (missing_version(10, 3), missing_version(11, 4));
    concurrent_put(&h, "device-r1", "p", &a);
    concurrent_put(&h, "device-r1", "q", &b);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["p"])).unwrap();
    assert_eq!(native.len(), 1);
    assert_eq!(native[0].path, "p");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_displaced_winner_is_wanted_at_its_relocated_name() {
    let h = Harness::new(true);
    let (file, child) = (missing_version(10, 5), missing_version(12, 6));
    concurrent_put(&h, "device-r1", "a", &file);
    concurrent_put(&h, "device-r1", "a/x", &child);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["a"])).unwrap();
    assert_eq!(native.len(), 1, "{native:?}");
    assert_ne!(native[0].path, "a", "a has to be a directory");
    assert_eq!(native[0].version_hash, file.version_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unresolvable_version_fails_the_prefetch_instead_of_wanting_nothing() {
    let h = Harness::new(true);
    let unknown = missing_version(10, 7);
    // Native shows a head whose version this device has never stored.
    crate::test_support::remote_admission_fixture::admit_remote(
        &h.state,
        GROUP,
        "device-r1",
        vec![crate::test_support::remote_admission_fixture::put(
            "z",
            unknown.version_hash,
            Vec::new(),
        )],
        &[],
    );

    assert!(h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["z"])).is_err());
}
