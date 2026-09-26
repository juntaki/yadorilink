#![cfg(all(test, not(turmoil)))]
//! A path an installed base leaves absent settles absent.
//!
//! A base carries only present heads. Where retained history would still
//! hold the removal that ended a path, a sealed group holds nothing at all
//! for it: no head in `Gamma`, no live row. An obligation raised for such a
//! path (releasing an install's hold raises one for every path it held)
//! used to resolve from no heads, fail closed into `retry`, and be retried
//! forever -- and every later seal was refused over the pending projection.
//! Found by the history-epoch DST scenario; pinned here without it.

use std::collections::BTreeSet;
use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_sync_sqlite::rebootstrap_store::{build_group_history_summary, seal_group};
use yadorilink_sync_sqlite::SyncSqliteError;

use super::types::{ProjectionAttempt, SettlementEvidence};
use crate::daemon_state::DaemonState;
use crate::test_support::sync_stack_fixture::{
    device, init_staging_schema, link_folder, local_capture, publish_local_pending,
    FixtureCheckpointSource, GROUP,
};

/// Hands the capture the event a watcher would have produced for `rel`.
async fn capture(state: &Arc<DaemonState>, root: &std::path::Path, rel: &str, kind: FsChangeKind) {
    local_capture(state)
        .process_event(GROUP, root, &FsChangeEvent { path: root.join(rel), kind })
        .await
        .expect("the capture must not error on an ordinary file");
}

async fn reconcile(state: &Arc<DaemonState>, path: &str) -> ProjectionAttempt {
    state
        .local_convergence()
        .reconcile_paths(GROUP, BTreeSet::from([path.to_owned()]))
        .await
        .expect("the reconcile runs")
        .expect("the reconcile attempted the path")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_an_installed_base_leaves_absent_settles_absent_and_nothing_else_does() {
    let (state, _store) = device("device-alice", 11);
    init_staging_schema(&state);
    let folder = tempfile::tempdir().expect("the linked folder");
    let root = link_folder(&state, folder.path());

    // `gone` is written and removed; `kept` keeps the group non-empty.
    std::fs::write(root.join("gone"), b"written, then removed").unwrap();
    capture(&state, &root, "gone", FsChangeKind::CreatedOrModified).await;
    std::fs::write(root.join("kept"), b"stays").unwrap();
    capture(&state, &root, "kept", FsChangeKind::CreatedOrModified).await;
    std::fs::remove_file(root.join("gone")).unwrap();
    capture(&state, &root, "gone", FsChangeKind::Removed).await;
    publish_local_pending(&state, &FixtureCheckpointSource::for_device(&state), GROUP).await;
    // The seal refuses over a pending projection. Both paths settle (the
    // reconcile says so); closing their obligations is the Convergence
    // Engine's job, which this fixture does not run, so it closes them.
    for path in ["gone", "kept"] {
        let attempt = reconcile(&state, path).await;
        assert!(attempt.retry.is_empty(), "sanity: {path} settles before the seal: {attempt:?}");
    }
    state
        .replica_coordinator
        .database()
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM projection_obligations WHERE group_id = ?1", [GROUP])?;
            Ok(())
        })
        .unwrap();

    state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| seal_group(tx, GROUP))
        .expect("the group seals");
    let summary = state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| build_group_history_summary(conn, GROUP))
        .expect("the sealed group summarizes");
    assert!(
        summary.path_heads.iter().all(|head| head.path != "gone"),
        "sanity: the base carries no head at the removed path"
    );
    assert!(
        summary.path_heads.iter().any(|head| head.path == "kept"),
        "sanity: the base carries the live path"
    );

    // Something on disk at the path: this attempt has observed no absence,
    // and may not claim one.
    std::fs::write(root.join("gone"), b"not indexed yet").unwrap();
    let attempt = reconcile(&state, "gone").await;
    assert!(
        attempt.retry.contains("gone") && !attempt.settled.contains_key("gone"),
        "a headless path with something on disk must stay owed: {attempt:?}"
    );

    // Nothing on disk, no live row, a base installed: settled absent.
    std::fs::remove_file(root.join("gone")).unwrap();
    let attempt = reconcile(&state, "gone").await;
    assert!(
        matches!(attempt.settled.get("gone"), Some(SettlementEvidence::ExactAbsent { .. })),
        "a path the installed base leaves absent, absent in the index and on disk, must settle \
         absent rather than be retried forever: {attempt:?}"
    );
}
