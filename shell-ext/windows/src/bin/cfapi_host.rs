//! `yadorilink-cfapi-host`: the long-lived process that owns every OnDemand
//! folder's Cloud Filter API sync-root registration/connection and serves
//! `CF_CALLBACK_TYPE_FETCH_DATA` callbacks (on-demand-sync
//! operations). See `cfapi.rs`'s module doc and `Cargo.toml`'s `[[bin]]` doc
//! comment for why this is a separate process from the
//! `yadorilink_shell_ext` COM DLL.
//!
//! Usage:
//!  yadorilink-cfapi-host run the poll loop (default)
//!  yadorilink-cfapi-host --unregister-all
//!  unregister every sync root this host
//!  has ever registered (the
//!  uninstall path), then exit; does not
//!  require the daemon to be running
//!
//! The poll loop periodically asks the daemon (over the same shell-IPC
//! named pipe the shell extension DLL uses) which folders are
//! OnDemand-linked, registers/connects a sync root for any not seen
//! before, and creates placeholders for any file the daemon reports as
//! still a placeholder that doesn't already have one on disk. This is
//! polling rather than push-driven because `ListOnDemandFolders`/
//! `ListFolderFiles` (the protocol extension) are simple
//! request/response messages on the existing shell-IPC connection, not
//! wired into the daemon's `StatusPush` broadcast — acceptable for this
//! MVP since sync-root registration only needs to happen once per folder
//! ever (already-registered roots are skipped), and new-file placeholder
//! creation lagging by up to `POLL_INTERVAL` is a modest, disclosed
//! trade-off rather than a correctness bug (the file still appears once
//! polled; it just doesn't appear at the exact instant the daemon adopted
//! it).

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Where the set of every sync root this machine has ever registered is
/// recorded, so `--unregister-all` can clean up without needing the
/// daemon reachable (the uninstaller must work even if the
/// daemon has already been stopped).
fn registry_file_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    Path::new(&base).join("yadorilink").join("cfapi_sync_roots.txt")
}

fn record_registered_root(path: &Path) {
    let file = registry_file_path();
    if let Some(parent) = file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing = std::fs::read_to_string(&file).unwrap_or_default();
    let already_recorded = existing.lines().any(|l| l == path.to_string_lossy());
    if already_recorded {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&file) {
        let _ = writeln!(f, "{}", path.to_string_lossy());
    }
}

fn unregister_all() {
    let file = registry_file_path();
    let Ok(contents) = std::fs::read_to_string(&file) else {
        println!("yadorilink-cfapi-host: no recorded sync roots at {}", file.display());
        return;
    };
    for line in contents.lines() {
        let path = Path::new(line.trim());
        if path.as_os_str().is_empty() {
            continue;
        }
        match yadorilink_shell_ext::cfapi::unregister(path) {
            Ok(()) => println!("yadorilink-cfapi-host: unregistered sync root {}", path.display()),
            Err(e) => eprintln!(
                "yadorilink-cfapi-host: failed to unregister sync root {}: {e:?}",
                path.display()
            ),
        }
    }
    let _ = std::fs::remove_file(&file);
}

fn poll_once(known_roots: &mut HashSet<PathBuf>) {
    let folders = yadorilink_shell_ext::ipc_client::list_on_demand_folders();
    for folder in folders {
        let root = PathBuf::from(&folder.local_path);
        if !known_roots.contains(&root) {
            match yadorilink_shell_ext::cfapi::register_and_connect(&root) {
                Ok(()) => {
                    println!(
                        "yadorilink-cfapi-host: registered+connected sync root {} (group {})",
                        root.display(),
                        folder.group_id
                    );
                    record_registered_root(&root);
                    known_roots.insert(root.clone());
                }
                Err(e) => {
                    eprintln!(
                        "yadorilink-cfapi-host: failed to register sync root {}: {e:?}",
                        root.display()
                    );
                    continue;
                }
            }
        }

        let entries = yadorilink_shell_ext::ipc_client::list_folder_files(&folder.local_path);
        yadorilink_shell_ext::cfapi::sync_placeholders(&root, &entries);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--unregister-all") {
        unregister_all();
        return;
    }

    println!("yadorilink-cfapi-host: starting (poll interval {POLL_INTERVAL:?})");
    let mut known_roots = HashSet::new();
    loop {
        poll_once(&mut known_roots);
        std::thread::sleep(POLL_INTERVAL);
    }
}
