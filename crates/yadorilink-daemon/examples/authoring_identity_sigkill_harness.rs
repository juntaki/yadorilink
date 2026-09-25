//! Not a test -- a small standalone harness process for the SIGKILL
//! crash-consistency proof of the authoring-identity atomicity fix
//! (`72d5608e`). Run directly (not via `cargo test`) so an external shell
//! command can send it a real `SIGKILL` while it is a real OS process with
//! work still in flight; a `#[tokio::test]` closure cannot be killed from
//! outside the test binary in a targeted way once other tests share the
//! same process.
//!
//! Usage: `authoring_identity_sigkill_harness <root_dir> <db_path> <file_count>`
//! Creates `file_count` files under `root_dir`, links a group against
//! `db_path`, waits for the group to become DAG-backed (prints
//! `DAG_BACKED_AT <unix_ms>` to stdout the instant it does, flushed
//! immediately so an external watcher can act on it), then keeps making
//! small ongoing local edits indefinitely so there is continued real work in
//! flight for an external `kill -9` to land on.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

fn group_has_any_change(conn: &rusqlite::Connection, group_id: &str) -> bool {
    let changes: i64 = conn
        .query_row("SELECT COUNT(*) FROM changes WHERE group_id = ?1", [group_id], |row| row.get(0))
        .unwrap_or(0);
    let pruned: i64 = conn
        .query_row("SELECT COUNT(*) FROM pruned_changes WHERE group_id = ?1", [group_id], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    changes + pruned > 0
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root_dir = PathBuf::from(&args[1]);
    let db_path = PathBuf::from(&args[2]);
    let file_count: usize = args[3].parse().unwrap();
    let group_id = "p0-sigkill-proof-group";

    std::fs::create_dir_all(&root_dir).unwrap();
    let store_dir = root_dir.join(".block-store");
    std::fs::create_dir_all(&store_dir).unwrap();
    let store = Arc::new(SegmentBlockStore::new(&store_dir).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new("p0-sigkill-device".to_string(), sync_state, store);
    let keypair = yadorilink_transport::DeviceSigningKeyPair::generate();
    state.set_device_signing_key(keypair.signing);

    let content_root = root_dir.join("content");
    std::fs::create_dir_all(&content_root).unwrap();
    for i in 0..file_count {
        std::fs::write(content_root.join(format!("file{i:05}.bin")), format!("v0-{i}")).unwrap();
    }

    let local_path = content_root.to_string_lossy().to_string();
    LinkRuntimeController::new(state.clone())
        .start(local_path.clone(), group_id.to_string())
        .expect("starting the link runtime");

    let poll_conn = rusqlite::Connection::open(&db_path).unwrap();
    loop {
        if group_has_any_change(&poll_conn, group_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            println!("DAG_BACKED_AT {now}");
            std::io::stdout().flush().unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(poll_conn);

    // Keep making ongoing local edits indefinitely so there is real,
    // continued write activity for an external `kill -9` to land on --
    // not just idle sleep after the first commit.
    let mut i: usize = 0;
    loop {
        let path = content_root.join(format!("file{:05}.bin", i % file_count));
        let _ = std::fs::write(&path, format!("v{}-{}", i / file_count + 1, i));
        i += 1;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
