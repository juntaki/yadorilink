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
//! OnDemand-linked and reconciles the CfAPI sync-root set to match --
//! registering any missing root, unregistering any no-longer-desired
//! (stale) one -- then creates placeholders for any file the daemon
//! reports as still a placeholder that doesn't already have one on disk.
//! This is polling rather than push-driven because `ListOnDemandFolders`/
//! `ListFolderFiles` (the protocol extension) are simple
//! request/response messages on the existing shell-IPC connection, not
//! wired into the daemon's `StatusPush` broadcast -- acceptable for this
//! MVP since sync-root registration only needs to happen once per folder
//! ever (already-registered roots are skipped), and new-file placeholder
//! creation / stale-root removal lagging by up to `POLL_INTERVAL` is a
//! modest, disclosed trade-off rather than a correctness bug.
//!
//! M2-1 FAIL-CLOSED RECONCILIATION: `reconcile_sync_roots` only ever runs
//! against a *confirmed* desired-state snapshot (`Some(folders)` from
//! `ipc_client::list_on_demand_folders`). A failure to confirm that
//! snapshot (unreachable daemon, timeout, malformed response) makes NO
//! change to the CfAPI sync-root set at all -- see that function's own
//! doc comment for why collapsing "cannot confirm" into "confirmed
//! empty" would be a fail-open bug (a transient daemon-unreachable
//! moment would look identical to "remove every sync root"). Mirrors
//! `shell-ext/macos/YadoriLinkFinderSync/HostApp/DomainRegistration.swift`'s
//! `registerOnDemandDomains` exactly, on the Windows side of the wire.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use yadorilink_ipc_proto::shellipc::OnDemandFolder;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Where the set of every sync root this machine has ever registered is
/// recorded, so `--unregister-all` can clean up without needing the
/// daemon reachable (the uninstaller must work even if the
/// daemon has already been stopped). Kept converged with the actually-
/// registered set by `reconcile_sync_roots`'s callers (entries are
/// removed on successful stale-root unregistration, not just appended
/// on registration) -- this is a "what should `--unregister-all` clean
/// up right now" list, not an immutable history of every root ever seen.
fn registry_file_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    Path::new(&base).join("yadorilink").join("cfapi_sync_roots.txt")
}

fn record_registered_root_at(file: &Path, path: &Path) {
    if let Some(parent) = file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    let target = path.to_string_lossy();
    if existing.lines().any(|l| l == target) {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(file) {
        let _ = writeln!(f, "{target}");
    }
}

fn record_registered_root(path: &Path) {
    record_registered_root_at(&registry_file_path(), path);
}

fn remove_registered_root_at(file: &Path, path: &Path) {
    let Ok(existing) = std::fs::read_to_string(file) else { return };
    let target = path.to_string_lossy();
    let filtered: Vec<&str> = existing.lines().filter(|l| *l != target).collect();
    let mut new_contents = filtered.join("\n");
    if !filtered.is_empty() {
        new_contents.push('\n');
    }
    if let Err(e) = std::fs::write(file, new_contents) {
        eprintln!(
            "yadorilink-cfapi-host: failed to update sync-root registry after removing {}: {e}",
            path.display()
        );
    }
}

fn remove_registered_root(path: &Path) {
    remove_registered_root_at(&registry_file_path(), path);
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

/// The two real-cfapi operations `reconcile_sync_roots` needs, factored
/// out so the reconciliation logic itself (add-missing/remove-stale set
/// arithmetic, the idempotency and fail-closed contracts) is unit-testable
/// without a real Windows machine or an installed CfAPI provider -- the
/// real implementation (`RealSyncRootBackend`) is the only thing that
/// actually calls `cfapi::register_and_connect`/`cfapi::unregister`.
trait SyncRootBackend {
    fn register_and_connect(&mut self, root: &Path) -> Result<(), String>;
    fn unregister(&mut self, root: &Path) -> Result<(), String>;
}

struct RealSyncRootBackend;

impl SyncRootBackend for RealSyncRootBackend {
    fn register_and_connect(&mut self, root: &Path) -> Result<(), String> {
        yadorilink_shell_ext::cfapi::register_and_connect(root).map_err(|e| format!("{e:?}"))
    }

    fn unregister(&mut self, root: &Path) -> Result<(), String> {
        // `cfapi::unregister` already disconnects first (documented on
        // that function) -- no separate `disconnect` call needed here.
        yadorilink_shell_ext::cfapi::unregister(root).map_err(|e| format!("{e:?}"))
    }
}

/// Converges `known_roots` (the sync roots this process believes are
/// currently registered) onto `desired` (a *confirmed* snapshot of every
/// OnDemand-linked folder) by registering whatever's missing and
/// unregistering whatever's no longer desired. Idempotent: calling this
/// again with the same `desired` set and an unchanged `known_roots` makes
/// no further backend calls (both returned `Vec`s are empty). A failed
/// individual register/unregister call is logged and left for the next
/// poll to retry -- `known_roots` only changes for operations that
/// actually succeeded, so it never drifts from backend reality.
///
/// Returns the paths successfully registered and successfully
/// unregistered this call, for the caller to keep the on-disk registry
/// file (`registry_file_path`) converged with.
fn reconcile_sync_roots<B: SyncRootBackend>(
    backend: &mut B,
    known_roots: &mut HashSet<PathBuf>,
    desired: &[OnDemandFolder],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let desired_paths: HashSet<PathBuf> =
        desired.iter().map(|f| PathBuf::from(&f.local_path)).collect();

    let mut registered = Vec::new();
    for folder in desired {
        let root = PathBuf::from(&folder.local_path);
        if known_roots.contains(&root) {
            continue;
        }
        match backend.register_and_connect(&root) {
            Ok(()) => {
                println!(
                    "yadorilink-cfapi-host: registered+connected sync root {}",
                    root.display()
                );
                known_roots.insert(root.clone());
                registered.push(root);
            }
            Err(e) => {
                eprintln!(
                    "yadorilink-cfapi-host: failed to register sync root {}: {e}",
                    root.display()
                );
            }
        }
    }

    let stale: Vec<PathBuf> =
        known_roots.iter().filter(|root| !desired_paths.contains(*root)).cloned().collect();
    let mut unregistered = Vec::new();
    for root in stale {
        match backend.unregister(&root) {
            Ok(()) => {
                println!(
                    "yadorilink-cfapi-host: unregistered stale sync root {} (no longer OnDemand-linked)",
                    root.display()
                );
                known_roots.remove(&root);
                unregistered.push(root);
            }
            Err(e) => {
                eprintln!(
                    "yadorilink-cfapi-host: failed to unregister stale sync root {}: {e}",
                    root.display()
                );
            }
        }
    }

    (registered, unregistered)
}

fn poll_once(backend: &mut impl SyncRootBackend, known_roots: &mut HashSet<PathBuf>) {
    let Some(folders) = yadorilink_shell_ext::ipc_client::list_on_demand_folders() else {
        eprintln!(
            "yadorilink-cfapi-host: could not confirm desired sync-root snapshot this poll \
             (daemon unreachable, timeout, or malformed response); leaving existing sync roots \
             untouched"
        );
        return;
    };

    let (registered, unregistered) = reconcile_sync_roots(&mut *backend, known_roots, &folders);
    for root in &registered {
        record_registered_root(root);
    }
    for root in &unregistered {
        remove_registered_root(root);
    }

    for folder in &folders {
        let root = PathBuf::from(&folder.local_path);
        if !known_roots.contains(&root) {
            // Registration failed this poll (already logged above); skip
            // placeholder sync for this folder until a future poll
            // succeeds.
            continue;
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
    let mut backend = RealSyncRootBackend;
    loop {
        poll_once(&mut backend, &mut known_roots);
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        registered: Vec<PathBuf>,
        unregistered: Vec<PathBuf>,
        fail_register: HashSet<PathBuf>,
        fail_unregister: HashSet<PathBuf>,
    }

    impl SyncRootBackend for FakeBackend {
        fn register_and_connect(&mut self, root: &Path) -> Result<(), String> {
            if self.fail_register.contains(root) {
                return Err("simulated register failure".to_string());
            }
            self.registered.push(root.to_path_buf());
            Ok(())
        }

        fn unregister(&mut self, root: &Path) -> Result<(), String> {
            if self.fail_unregister.contains(root) {
                return Err("simulated unregister failure".to_string());
            }
            self.unregistered.push(root.to_path_buf());
            Ok(())
        }
    }

    fn folder(local_path: &str) -> OnDemandFolder {
        OnDemandFolder { local_path: local_path.to_string(), group_id: "group".to_string() }
    }

    fn path_set(paths: &[&str]) -> HashSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn missing_root_is_registered() {
        let mut backend = FakeBackend::default();
        let mut known = path_set(&["A"]);
        let (registered, unregistered) =
            reconcile_sync_roots(&mut backend, &mut known, &[folder("A"), folder("B")]);
        assert_eq!(registered, vec![PathBuf::from("B")]);
        assert!(unregistered.is_empty());
        assert_eq!(known, path_set(&["A", "B"]));
    }

    #[test]
    fn stale_root_is_unregistered() {
        let mut backend = FakeBackend::default();
        let mut known = path_set(&["A", "B"]);
        let (registered, unregistered) =
            reconcile_sync_roots(&mut backend, &mut known, &[folder("A")]);
        assert!(registered.is_empty());
        assert_eq!(unregistered, vec![PathBuf::from("B")]);
        assert_eq!(known, path_set(&["A"]));
    }

    #[test]
    fn empty_desired_unregisters_everything() {
        let mut backend = FakeBackend::default();
        let mut known = path_set(&["A", "B"]);
        let (registered, unregistered) = reconcile_sync_roots(&mut backend, &mut known, &[]);
        assert!(registered.is_empty());
        let mut unregistered = unregistered;
        unregistered.sort();
        assert_eq!(unregistered, vec![PathBuf::from("A"), PathBuf::from("B")]);
        assert!(known.is_empty());
    }

    #[test]
    fn same_snapshot_twice_is_idempotent() {
        let mut backend = FakeBackend::default();
        let mut known = path_set(&["A"]);
        let desired = [folder("A"), folder("B")];
        let first = reconcile_sync_roots(&mut backend, &mut known, &desired);
        assert_eq!(first.0, vec![PathBuf::from("B")]);
        let second = reconcile_sync_roots(&mut backend, &mut known, &desired);
        assert!(second.0.is_empty());
        assert!(second.1.is_empty());
    }

    #[test]
    fn failed_register_is_retried_next_call_not_dropped() {
        let mut backend = FakeBackend::default();
        backend.fail_register.insert(PathBuf::from("B"));
        let mut known = path_set(&["A"]);
        let desired = [folder("A"), folder("B")];
        let first = reconcile_sync_roots(&mut backend, &mut known, &desired);
        assert!(first.0.is_empty());
        assert_eq!(known, path_set(&["A"]));

        backend.fail_register.clear();
        let second = reconcile_sync_roots(&mut backend, &mut known, &desired);
        assert_eq!(second.0, vec![PathBuf::from("B")]);
        assert_eq!(known, path_set(&["A", "B"]));
    }

    #[test]
    fn failed_unregister_keeps_root_known_for_retry() {
        let mut backend = FakeBackend::default();
        backend.fail_unregister.insert(PathBuf::from("B"));
        let mut known = path_set(&["A", "B"]);
        let first = reconcile_sync_roots(&mut backend, &mut known, &[folder("A")]);
        assert!(first.1.is_empty());
        assert_eq!(known, path_set(&["A", "B"]));

        backend.fail_unregister.clear();
        let second = reconcile_sync_roots(&mut backend, &mut known, &[folder("A")]);
        assert_eq!(second.1, vec![PathBuf::from("B")]);
        assert_eq!(known, path_set(&["A"]));
    }

    #[test]
    fn registry_file_records_registration_and_converges_on_stale_removal() {
        let dir = std::env::temp_dir()
            .join(format!("yadorilink-cfapi-host-test-{:?}", std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let registry = dir.join("cfapi_sync_roots.txt");

        record_registered_root_at(&registry, Path::new("A"));
        record_registered_root_at(&registry, Path::new("B"));
        let contents = std::fs::read_to_string(&registry).unwrap();
        assert_eq!(contents.lines().collect::<Vec<_>>(), vec!["A", "B"]);

        // Re-recording an already-present root is a no-op, not a duplicate.
        record_registered_root_at(&registry, Path::new("A"));
        let contents = std::fs::read_to_string(&registry).unwrap();
        assert_eq!(contents.lines().count(), 2);

        remove_registered_root_at(&registry, Path::new("A"));
        let contents = std::fs::read_to_string(&registry).unwrap();
        assert_eq!(contents.lines().collect::<Vec<_>>(), vec!["B"]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
