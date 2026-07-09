//! Tests `yadorilink gc [--dry-run]` and `status`'s block-store usage
//! fields, end-to-end against a real daemon over the actual control
//! socket — same pattern as `tests/limits.rs`/`tests/materialization.rs`
//! (a real `unix_transport::serve` daemon, no coordination-plane/auth
//! setup needed).
//!
//! Every test here writes an orphaned block (never referenced by any
//! file/link record) and then backdates its on-disk mtime past
//! `yadorilink_daemon::gc::GC_GRACE_WINDOW` via `File::set_modified` —
//! without this, a block written moments ago by `put()` would never be
//! swept by a real (non-test-injected-grace-cutoff) `run_sweep` call
//! within the lifetime of a fast-running test, since the grace window
//! exists specifically to protect a block that recently landed on disk.
#![cfg(unix)]

use std::fs::File;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{GcRequest, StatusRequest};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());

    let blocks_root = dir.path().join("blocks");
    let store = Arc::new(FsBlockStore::new(&blocks_root).unwrap());
    let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_state)
            .await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (dir, state, blocks_root)
}

/// Tests in this file share `YADORILINK_CONTROL_SOCKET`/
/// `YADORILINK_CONFIG_DIR` (process-global env vars), mirroring
/// `tests/limits.rs`'s own `TEST_MUTEX` precedent — separate integration
/// test binaries (files) don't need to coordinate with each other, but
/// tests *within this file* do.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// git-object-style sharding, mirroring `FsBlockStore`'s own private
/// `path_for_hash` (not exposed publicly) — this test needs the real
/// on-disk path to backdate a block's mtime directly.
fn block_path(blocks_root: &std::path::Path, hash: &str) -> std::path::PathBuf {
    blocks_root.join(&hash[0..2]).join(&hash[2..4]).join(hash)
}

fn backdate_past_grace_window(path: &std::path::Path) {
    let file = File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - yadorilink_daemon::gc::GC_GRACE_WINDOW * 2).unwrap();
}

/// task 4.3/5.3: a real `gc` reclaims an orphaned block and reports
/// counts matching the block store's actual before/after contents.
#[tokio::test]
async fn gc_reclaims_an_orphaned_block_and_reports_matching_counts() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state, blocks_root) = start_daemon().await;
    let hash = state.block_store.put(b"orphaned, never referenced by any file record").unwrap();
    backdate_past_grace_window(&block_path(&blocks_root, &hash));
    assert!(state.block_store.exists(&hash).unwrap(), "sanity: block exists before gc");

    let resp = yadorilink_cli::control_client::send(ReqPayload::Gc(GcRequest { dry_run: false }))
        .await
        .unwrap();
    let Some(RespPayload::Gc(report)) = resp.payload else {
        panic!("expected a Gc response, got {:?}", resp.payload);
    };

    assert_eq!(report.blocks_deleted, 1);
    assert!(!state.block_store.exists(&hash).unwrap(), "gc must actually delete the block");

    // The user-facing command itself (not just the raw IPC round-trip
    // above) also succeeds against the now-clean store.
    yadorilink_cli::commands::gc::run(false).await.unwrap();
}

/// task 4.3: `--dry-run` reports the same delete-set size a real
/// run would, but performs zero deletions.
#[tokio::test]
async fn gc_dry_run_matches_a_real_runs_estimate_without_deleting() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state, blocks_root) = start_daemon().await;
    let hash = state.block_store.put(b"orphaned block for dry-run test").unwrap();
    backdate_past_grace_window(&block_path(&blocks_root, &hash));

    let dry_run_resp =
        yadorilink_cli::control_client::send(ReqPayload::Gc(GcRequest { dry_run: true }))
            .await
            .unwrap();
    let Some(RespPayload::Gc(dry_run_report)) = dry_run_resp.payload else {
        panic!("expected a Gc response");
    };
    assert_eq!(dry_run_report.blocks_deleted, 1);
    assert!(state.block_store.exists(&hash).unwrap(), "dry-run must not delete anything");

    // An immediate real run reclaims exactly what the dry run reported.
    let real_resp =
        yadorilink_cli::control_client::send(ReqPayload::Gc(GcRequest { dry_run: false }))
            .await
            .unwrap();
    let Some(RespPayload::Gc(real_report)) = real_resp.payload else {
        panic!("expected a Gc response");
    };
    assert_eq!(real_report.blocks_deleted, dry_run_report.blocks_deleted);
    assert_eq!(real_report.bytes_reclaimed, dry_run_report.bytes_reclaimed);
    assert!(!state.block_store.exists(&hash).unwrap());

    // `commands::gc::run(true)` (the actual CLI entry point) also succeeds
    // against the now-clean store without performing a deletion.
    yadorilink_cli::commands::gc::run(true).await.unwrap();
}

/// task 4.1/4.3/5.3: `status` reports non-zero block-store usage after a
/// block is written, and lower usage (plus a recorded `last_gc_unix`)
/// after a GC run reclaims it.
#[tokio::test]
async fn status_reports_usage_and_lower_usage_after_gc() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state, blocks_root) = start_daemon().await;
    let hash = state.block_store.put(b"some content that counts toward usage").unwrap();
    backdate_past_grace_window(&block_path(&blocks_root, &hash));

    let before =
        yadorilink_cli::control_client::send(ReqPayload::Status(StatusRequest {})).await.unwrap();
    let Some(RespPayload::Status(before)) = before.payload else {
        panic!("expected a Status response");
    };
    assert_eq!(before.block_store_block_count, 1);
    assert!(before.block_store_total_bytes > 0);
    assert_eq!(before.last_gc_unix, 0, "no real sweep has run yet");

    yadorilink_cli::control_client::send(ReqPayload::Gc(GcRequest { dry_run: false }))
        .await
        .unwrap();

    let after =
        yadorilink_cli::control_client::send(ReqPayload::Status(StatusRequest {})).await.unwrap();
    let Some(RespPayload::Status(after)) = after.payload else {
        panic!("expected a Status response");
    };
    assert_eq!(after.block_store_block_count, 0);
    assert_eq!(after.block_store_total_bytes, 0);
    assert!(after.last_gc_unix > 0, "a completed real sweep must be recorded");
}

/// equivalent at the IPC layer: a `gc` request while sync
/// activity is in progress is rejected with a clear error, not silently
/// run mid-burst — see `yadorilink-daemon`'s own `gc::tests` for the
/// scheduling/concurrency unit tests this integration test complements.
#[tokio::test]
async fn gc_request_is_rejected_while_a_write_is_in_progress() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state, _blocks_root) = start_daemon().await;
    let _write_guard = state.begin_write_activity();

    let err = yadorilink_cli::control_client::send(ReqPayload::Gc(GcRequest { dry_run: false }))
        .await
        .unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("sync activity is in progress"),
        "expected a clear sync-activity-in-progress error, got: {message}"
    );
}
