//! Verification helper: seeds a
//! folder link + one "Synced" file directly into the daemon's SQLite
//! state, bypassing the CLI's coordination-plane-dependent `link`
//! command (which needs a logged-in, registered device) — this is only
//! for locally verifying the Windows shell-icon-overlay actually
//! renders an overlay in Explorer, not part of the shipped product.
//!
//! Usage: `cargo run --example seed_overlay_test_data -- <folder> <group_id> <relative_file>`

use std::sync::Arc;

use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::types::FileRecord;
use yadorilink_sync_core::version_vector::VersionVector;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let folder = args.get(1).expect("usage: <folder> <group_id> <relative_file>");
    let group_id = args.get(2).expect("usage: <folder> <group_id> <relative_file>");
    let relative_file = args.get(3).expect("usage: <folder> <group_id> <relative_file>");

    let config_dir =
        std::env::var("YADORILINK_CONFIG_DIR").expect("YADORILINK_CONFIG_DIR must be set");
    let config_dir = std::path::PathBuf::from(config_dir);
    std::fs::create_dir_all(&config_dir).unwrap();

    let store = Arc::new(FsBlockStore::new(config_dir.join("blocks")).unwrap());
    let sync_state = Arc::new(SyncState::open(config_dir.join("sync-state.sqlite3")).unwrap());

    sync_state.add_link(folder, group_id).unwrap();

    let path = std::path::Path::new(folder).join(relative_file);
    let content = std::fs::read(&path).unwrap();
    let blocks = yadorilink_sync_core::chunker::chunk_file(store.as_ref(), &path).unwrap();
    let mut version = VersionVector::new();
    version.increment("device-under-test");

    sync_state
        .upsert_file(
            group_id,
            &FileRecord {
                path: relative_file.clone(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks,
                deleted: false,
            },
        )
        .unwrap();

    println!("seeded: folder={folder} group={group_id} file={relative_file}");
}
