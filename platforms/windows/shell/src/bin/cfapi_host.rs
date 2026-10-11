//! `yadorilink-cfapi-host`: the long-lived process that owns every provider root's Cloud Filter
//! API sync-root registration and connection, shows the root's namespace as placeholders, and
//! serves `CF_CALLBACK_TYPE_FETCH_DATA` callbacks. See `cfapi.rs`'s module doc and `Cargo.toml`'s
//! `[[bin]]` doc comment for why this is a separate process from the `yadorilink_shell_ext` COM
//! DLL.
//!
//! Usage:
//!  yadorilink-cfapi-host            run the host (default)
//!  yadorilink-cfapi-host --unregister-all
//!                                   unregister every sync root this host has registered (the
//!                                   uninstall path), then exit; does not need the daemon
//!
//! The daemon declares the provider roots of this device. The host asks for them (over the same
//! shell-IPC pipe the shell extension uses), registers and connects one sync root per declared
//! root, and keeps one persistent connection to the daemon that makes it the daemon's attached
//! host: the daemon pushes "the namespace changed" and "drop the old copy of this item", and the
//! host acknowledges after it has done so.
//!
//! The host keeps a record of which sync root path serves which declared root
//! (`host_paths::roots_registry_file`), so a restarted host (or a restarted daemon) reconnects
//! the same roots at the same places.
//!
//! FAIL-CLOSED RECONCILIATION: the root set is only ever reconciled against a *confirmed*
//! snapshot (`ipc_client::list_provider_folders` returned `Some`). A failure to confirm it makes
//! NO change at all: collapsing "cannot confirm" into "confirmed empty" would be a fail-open bug.
//! A registered root the daemon neither lists nor asks to remove is an orphan: it is reported and
//! kept, never removed on that evidence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use yadorilink_fs_platform::durable_dir::{publish_durably, Replace};
use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, EvictResult, ProviderFolder, ProviderRemoval,
};
use yadorilink_shell_ext::dir_watch::{self, Signal};
use yadorilink_shell_ext::host_paths;
use yadorilink_shell_ext::provider_authoring::{self, Authoring, WindowsLocal};
use yadorilink_shell_ext::provider_namespace::{EvictOutcome, ShownItem, ShownItems};
use yadorilink_shell_ext::provider_session::{self, SessionEvent};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// How long a root must be quiet before what the user did in it is applied: an editor's save is a
/// burst of creates, renames and deletes, and it is the end state that means something.
const QUIET: Duration = Duration::from_millis(750);

/// Everything the host's loop waits for.
enum HostEvent {
    Session(SessionEvent),
    /// The watcher of the root (hex id) says something changed in its sync root.
    Local {
        root: String,
        signal: Signal,
    },
}

impl From<SessionEvent> for HostEvent {
    fn from(event: SessionEvent) -> Self {
        Self::Session(event)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

// ---- the record of registered roots -------------------------------------------------------

/// The registry's contents: root id (hex) -> sync root path. Lines of another shape (a path with
/// no root id, written by an earlier version) are not this host's roots and are ignored.
fn parse_registry(contents: &str) -> HashMap<String, PathBuf> {
    contents
        .lines()
        .filter_map(|line| {
            let (root, path) = line.split_once('\t')?;
            (unhex(root).is_some() && !path.trim().is_empty())
                .then(|| (root.to_string(), PathBuf::from(path.trim())))
        })
        .collect()
}

fn render_registry(roots: &HashMap<String, PathBuf>) -> String {
    let mut lines: Vec<String> =
        roots.iter().map(|(root, path)| format!("{root}\t{}\n", path.display())).collect();
    lines.sort();
    lines.concat()
}

fn read_registry_at(file: &Path) -> HashMap<String, PathBuf> {
    parse_registry(&std::fs::read_to_string(file).unwrap_or_default())
}

/// Writes the registry to a temporary file and renames it over the old one, so a crash cannot
/// leave every root's record half-written.
fn write_registry_at(file: &Path, roots: &HashMap<String, PathBuf>) -> std::io::Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = file.with_extension("tmp");
    let mut out = std::fs::File::create(&tmp)?;
    out.write_all(render_registry(roots).as_bytes())?;
    out.sync_all()?;
    drop(out);
    publish_durably(&tmp, file, Replace::Yes)
}

/// One shown item as a line: id, path, parent id, name, kind, size, time, version and parent
/// generation, tab separated (text fields hex encoded).
fn encode_shown(id: &[u8], item: &ShownItem) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        hex(id),
        hex(item.path.to_string_lossy().as_bytes()),
        hex(&item.parent_item_id),
        hex(item.name.as_bytes()),
        if item.directory { "d" } else { "f" },
        item.size,
        item.mtime_unix_nanos,
        hex(&item.content_version),
        item.parent_generation
    )
}

fn decode_shown(line: &str) -> Option<(Vec<u8>, ShownItem)> {
    let mut parts = line.split('\t');
    let id = unhex(parts.next()?)?;
    let path = PathBuf::from(String::from_utf8(unhex(parts.next()?)?).ok()?);
    let parent_item_id = unhex(parts.next()?)?;
    let name = String::from_utf8(unhex(parts.next()?)?).ok()?;
    let directory = parts.next()? == "d";
    let size = parts.next()?.parse().ok()?;
    let mtime_unix_nanos = parts.next()?.parse().ok()?;
    let content_version = unhex(parts.next()?)?;
    let parent_generation = parts.next()?.parse().ok()?;
    Some((
        id,
        ShownItem {
            path,
            parent_item_id,
            name,
            directory,
            size,
            mtime_unix_nanos,
            content_version,
            parent_generation,
        },
    ))
}

fn unregister_all() {
    let file = host_paths::roots_registry_file();
    let Ok(contents) = std::fs::read_to_string(&file) else {
        println!("yadorilink-cfapi-host: no recorded sync roots at {}", file.display());
        return;
    };
    // Roots recorded by this version, and (for an uninstall over an old install) the bare paths
    // an earlier version wrote.
    let mut paths: Vec<PathBuf> = parse_registry(&contents).into_values().collect();
    paths.extend(
        contents
            .lines()
            .filter(|line| !line.contains('\t') && !line.trim().is_empty())
            .map(|line| PathBuf::from(line.trim())),
    );
    for path in paths {
        match yadorilink_shell_ext::cfapi::unregister(&path) {
            Ok(()) => println!("yadorilink-cfapi-host: unregistered sync root {}", path.display()),
            Err(e) => eprintln!(
                "yadorilink-cfapi-host: failed to unregister sync root {}: {e:?}",
                path.display()
            ),
        }
    }
    let _ = std::fs::remove_file(&file);
}

// ---- the host ------------------------------------------------------------------------------

/// The operating-system side of the host: what it does to sync roots.
trait Backend {
    fn register_and_connect(&mut self, root_id: &[u8], path: &Path) -> Result<(), String>;
    fn unregister(&mut self, path: &Path) -> Result<(), String>;
    /// Makes the sync root show the root's namespace; `None` when it could not be confirmed.
    fn sync_namespace(
        &mut self,
        root_id: &[u8],
        path: &Path,
        previous: &ShownItems,
        protected: &HashSet<String>,
    ) -> Option<ShownItems>;
    fn evict(&mut self, path: &Path, item_id: &[u8]) -> Result<(), EvictOutcome>;
    /// The items an earlier run of the host showed in this root, as it showed them (`None`: it
    /// never showed the namespace completely).
    fn load_shown(&mut self, root_id: &[u8]) -> Option<ShownItems>;
    /// Records the items shown in this root now.
    fn save_shown(&mut self, root_id: &[u8], shown: &ShownItems);
    /// Whether `path` is an existing folder.
    fn is_dir(&mut self, path: &Path) -> bool;
    /// Starts signalling changes inside the sync root of `key`; dropping the guard stops it.
    fn watch(&mut self, key: &str, path: &Path) -> Option<Box<dyn std::any::Any>>;
    /// Applies what the user did at `signals` to the daemon.
    fn author(
        &mut self,
        root_id: &[u8],
        root_path: &Path,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
    ) -> provider_authoring::Report;
    /// Every path below `root_path`, for a look at everything after the watcher lost changes.
    fn listing(&mut self, root_path: &Path) -> BTreeSet<PathBuf>;
    /// Whether the user's own file or folder (not a placeholder) is at `path`.
    fn occupied_locally(&mut self, path: &Path) -> bool;
}

/// The daemon side of the host: what it tells the daemon.
trait Reports {
    fn domain_state(&self, root: &[u8], evidence: DomainEvidence, preserved_location: &str);
    fn signal_done(&self, root: &[u8], revision: u64, request_id: &[u8], error: Option<&str>);
    fn evict_done(&self, root: &[u8], request_id: &[u8], result: EvictResult, error: &str);
}

struct RealBackend {
    events: Sender<HostEvent>,
}

/// The daemon as `provider_authoring` asks it.
struct DaemonApi;

impl provider_authoring::Api for DaemonApi {
    fn apply(
        &self,
        root: &[u8],
        request: yadorilink_ipc_proto::shellipc::ProviderApplyChangeRequest,
    ) -> Option<yadorilink_ipc_proto::shellipc::ProviderApplyChangeResponse> {
        yadorilink_shell_ext::provider_client::apply(root, request)
    }
}

fn authoring_state_dir(root_id: &[u8]) -> PathBuf {
    host_paths::container().join("authoring").join(hex(root_id))
}

impl Backend for RealBackend {
    fn register_and_connect(&mut self, root_id: &[u8], path: &Path) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|e| format!("{}: {e}", path.display()))?;
        yadorilink_shell_ext::cfapi::register_and_connect_provider(root_id, path)
            .map_err(|e| format!("{e:?}"))
    }

    fn unregister(&mut self, path: &Path) -> Result<(), String> {
        // `cfapi::unregister` already disconnects first.
        yadorilink_shell_ext::cfapi::unregister(path).map_err(|e| format!("{e:?}"))
    }

    fn sync_namespace(
        &mut self,
        root_id: &[u8],
        path: &Path,
        previous: &ShownItems,
        protected: &HashSet<String>,
    ) -> Option<ShownItems> {
        yadorilink_shell_ext::provider_namespace::sync_namespace(root_id, path, previous, protected)
    }

    fn evict(&mut self, path: &Path, item_id: &[u8]) -> Result<(), EvictOutcome> {
        yadorilink_shell_ext::provider_namespace::evict(path, item_id)
    }

    fn load_shown(&mut self, root_id: &[u8]) -> Option<ShownItems> {
        let text = std::fs::read_to_string(authoring_state_dir(root_id).join("shown")).ok()?;
        text.lines().map(decode_shown).collect()
    }

    fn save_shown(&mut self, root_id: &[u8], shown: &ShownItems) {
        let dir = authoring_state_dir(root_id);
        let mut lines: Vec<String> =
            shown.iter().map(|(id, item)| encode_shown(id, item)).collect();
        lines.sort();
        let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
        let file = dir.join("shown");
        let written = std::fs::create_dir_all(&dir).and_then(|()| {
            let tmp = file.with_extension("tmp");
            let mut out = std::fs::File::create(&tmp)?;
            out.write_all(text.as_bytes())?;
            out.sync_all()?;
            drop(out);
            // On disk before the acknowledgement that depends on it: a recorded item whose
            // placeholder is gone reads as the user deleting it.
            publish_durably(&tmp, &file, Replace::Yes)
        });
        if let Err(e) = written {
            eprintln!("yadorilink-cfapi-host: could not record the shown items: {e}");
        }
    }

    fn is_dir(&mut self, path: &Path) -> bool {
        path.is_dir()
    }

    fn watch(&mut self, key: &str, path: &Path) -> Option<Box<dyn std::any::Any>> {
        let events = self.events.clone();
        let root = key.to_string();
        match dir_watch::watch(path, move |signal| {
            events.send(HostEvent::Local { root: root.clone(), signal }).is_ok()
        }) {
            Ok(watch) => Some(Box::new(watch)),
            Err(e) => {
                eprintln!("yadorilink-cfapi-host: cannot watch {}: {e}", path.display());
                None
            }
        }
    }

    fn author(
        &mut self,
        root_id: &[u8],
        root_path: &Path,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
    ) -> provider_authoring::Report {
        // A sync root folder that is gone says nothing about its files: never read it as "the
        // user deleted everything".
        if !root_path.is_dir() {
            eprintln!("yadorilink-cfapi-host: {} is not there; leaving it", root_path.display());
            return provider_authoring::Report::default();
        }
        let local = WindowsLocal { ingest_dir: host_paths::ingest_dir() };
        match Authoring::open(root_id, root_path, &authoring_state_dir(root_id)) {
            Ok(authoring) => authoring.process(signals, shown, &local, &DaemonApi),
            Err(e) => {
                eprintln!("yadorilink-cfapi-host: cannot open the authoring state: {e}");
                provider_authoring::Report {
                    retry: signals.clone(),
                    ..provider_authoring::Report::default()
                }
            }
        }
    }

    fn listing(&mut self, root_path: &Path) -> BTreeSet<PathBuf> {
        fn walk(directory: &Path, out: &mut BTreeSet<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(directory) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    out.insert(path.clone());
                    if entry.file_type().is_ok_and(|t| t.is_dir()) {
                        walk(&path, out);
                    }
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(root_path, &mut out);
        out
    }

    fn occupied_locally(&mut self, path: &Path) -> bool {
        path.symlink_metadata().is_ok()
            && yadorilink_shell_ext::provider_namespace::placeholder_info(path).is_none()
    }
}

impl Reports for provider_session::Session {
    fn domain_state(&self, root: &[u8], evidence: DomainEvidence, preserved_location: &str) {
        provider_session::Session::domain_state(self, root, evidence, preserved_location);
    }

    fn signal_done(&self, root: &[u8], revision: u64, request_id: &[u8], error: Option<&str>) {
        provider_session::Session::signal_done(self, root, revision, request_id, error);
    }

    fn evict_done(&self, root: &[u8], request_id: &[u8], result: EvictResult, error: &str) {
        provider_session::Session::evict_done(self, root, request_id, result, error);
    }
}

/// One served root.
struct Served {
    root_id: Vec<u8>,
    path: PathBuf,
    /// The namespace must be shown again (a new connection, a change, or a failed attempt).
    needs_walk: bool,
    /// The items shown by the last complete walk, with their paths.
    shown: ShownItems,
    /// What the user did in the sync root and has not been applied yet.
    pending: BTreeSet<PathBuf>,
    /// Changes were lost: look at everything.
    rescan: bool,
    /// When the last signal arrived (a root is applied once it has been quiet for [`QUIET`]).
    last_signal: Option<Instant>,
    /// Paths to look at again after this time (the daemon was busy or a file was changing).
    retry: BTreeSet<PathBuf>,
    retry_after: Option<Instant>,
    /// Keeps the watcher alive.
    _watch: Option<Box<dyn std::any::Any>>,
}

struct Host<B: Backend, R: Reports> {
    backend: B,
    reports: R,
    registry_file: PathBuf,
    sync_roots_parent: PathBuf,
    /// Everything ever registered by this host and not yet removed: root id (hex) -> path.
    registry: HashMap<String, PathBuf>,
    /// The roots connected by this process.
    served: HashMap<String, Served>,
}

impl<B: Backend, R: Reports> Host<B, R> {
    fn new(backend: B, reports: R, registry_file: PathBuf, sync_roots_parent: PathBuf) -> Self {
        let registry = read_registry_at(&registry_file);
        Self {
            backend,
            reports,
            registry_file,
            sync_roots_parent,
            registry,
            served: HashMap::new(),
        }
    }

    fn save_registry(&self) {
        if let Err(e) = write_registry_at(&self.registry_file, &self.registry) {
            eprintln!("yadorilink-cfapi-host: could not record the sync roots: {e}");
        }
    }

    /// Reconciles the served roots against the daemon's declarations. `None` snapshot (the
    /// daemon could not confirm one) changes nothing.
    fn reconcile(&mut self, snapshot: Option<(Vec<ProviderFolder>, Vec<ProviderRemoval>)>) {
        let Some((folders, removals)) = snapshot else {
            eprintln!(
                "yadorilink-cfapi-host: could not confirm the provider roots this poll (daemon \
                 unreachable, timeout, or unavailable snapshot); leaving the sync roots untouched"
            );
            return;
        };
        for removal in &removals {
            self.remove(&removal.root_id);
        }
        for folder in &folders {
            self.serve(folder);
        }
        // A recorded root the daemon neither declares nor asks to remove is an orphan: say so,
        // keep it.
        let declared: Vec<String> = folders.iter().map(|f| hex(&f.root_id)).collect();
        let removed: Vec<String> = removals.iter().map(|r| hex(&r.root_id)).collect();
        for root in self.registry.keys() {
            if !declared.contains(root) && !removed.contains(root) {
                if let Some(id) = unhex(root) {
                    self.reports.domain_state(&id, DomainEvidence::Orphan, "");
                }
            }
        }
    }

    /// Connects `folder`'s sync root if it is not connected yet, and shows its namespace when due.
    fn serve(&mut self, folder: &ProviderFolder) {
        let key = hex(&folder.root_id);
        if !self.served.contains_key(&key) {
            // A root this host registered before is reconnected where it was. A NEW root waits
            // until the daemon says its namespace is queryable: the operating system caches the
            // first listing it sees.
            let path = match self.registry.get(&key) {
                Some(path) => path.clone(),
                None if folder.registration_ready => {
                    let taken = self.registry.values().cloned().collect();
                    yadorilink_shell_ext::provider_namespace::choose_root_path(
                        &self.sync_roots_parent,
                        &folder.display_name,
                        &folder.root_id,
                        &taken,
                    )
                }
                None => return,
            };
            if self.registry.contains_key(&key) && !self.backend.is_dir(&path) {
                // A root registered before whose folder is gone (moved or removed while the host
                // was not running): it is not recreated empty, which would read as the user
                // deleting everything in it.
                eprintln!(
                    "yadorilink-cfapi-host: the sync root folder {} is missing; leaving {key} alone",
                    path.display()
                );
                return;
            }
            if let Err(e) = self.backend.register_and_connect(&folder.root_id, &path) {
                eprintln!(
                    "yadorilink-cfapi-host: failed to register sync root {}: {e}",
                    path.display()
                );
                return;
            }
            println!(
                "yadorilink-cfapi-host: registered+connected sync root {} for {key}",
                path.display()
            );
            if self.registry.insert(key.clone(), path.clone()).as_ref() != Some(&path) {
                self.save_registry();
            }
            let watch = self.backend.watch(&key, &path);
            self.served.insert(
                key.clone(),
                Served {
                    root_id: folder.root_id.clone(),
                    path,
                    needs_walk: true,
                    shown: ShownItems::new(),
                    // The first pass also sends an operation a crash left unanswered.
                    pending: BTreeSet::new(),
                    rescan: false,
                    last_signal: None,
                    retry: BTreeSet::new(),
                    retry_after: None,
                    _watch: watch,
                },
            );
            self.reports.domain_state(&folder.root_id, DomainEvidence::Registered, "");
        }
        if folder.registration_ready {
            let first = self.served.get(&key).is_some_and(|served| served.last_signal.is_none());
            let judged = first && self.judge_offline_changes(&key);
            self.walk_if_due(&key);
            // The first complete showing of a root is recorded, and whatever the user did in it
            // while the host was not running (and any operation a crash left unanswered) is applied.
            if first && self.served.get(&key).is_some_and(|served| !served.needs_walk) {
                if let Some(served) = self.served.get_mut(&key) {
                    served.last_signal = Some(Instant::now());
                }
                if !judged {
                    self.apply_local(&key, true);
                }
            }
        }
    }

    /// A restart: what the user did while the host was not running is judged against the
    /// namespace this host had SHOWN, before anything is shown, so a placeholder the user deleted
    /// is reported as deleted and not put back. An item another device created in the meantime
    /// was never shown, so it is not a deletion. False when there is nothing to judge against.
    fn judge_offline_changes(&mut self, key: &str) -> bool {
        let Some(served) = self.served.get_mut(key) else { return false };
        let Some(shown) = self.backend.load_shown(&served.root_id) else { return false };
        served.shown = shown;
        served.last_signal = Some(Instant::now());
        self.apply_local(key, true);
        true
    }

    fn walk_if_due(&mut self, key: &str) {
        if self.served.get(key).is_some_and(|served| served.needs_walk) {
            self.walk(key);
        }
    }

    /// Shows the namespace of the served root `key`. What the user did that has not been applied
    /// yet is applied first: showing the daemon's namespace would put back a placeholder the user
    /// just deleted before the delete was reported. True when the whole namespace was confirmed.
    fn walk(&mut self, key: &str) -> bool {
        let waiting = self
            .served
            .get(key)
            .is_some_and(|root| !root.pending.is_empty() || root.rescan || !root.retry.is_empty());
        if waiting {
            self.author_local(key, false);
        }
        self.walk_now(key)
    }

    fn walk_now(&mut self, key: &str) -> bool {
        let Some(served) = self.served.get_mut(key) else { return false };
        // What the user did and has not been reported yet is not touched by the walk: a
        // placeholder deleted there must not be put back before the daemon has been told.
        let protected: HashSet<String> = served
            .pending
            .iter()
            .chain(served.retry.iter())
            .map(|path| path.to_string_lossy().to_lowercase())
            .collect();
        match self.backend.sync_namespace(&served.root_id, &served.path, &served.shown, &protected)
        {
            Some(mut shown) => {
                // An item whose name the user's own file now holds (an editor's save by
                // replacing) is still that item until the change has been applied.
                for (id, old) in &served.shown {
                    if !shown.contains_key(id) && self.backend.occupied_locally(&old.path) {
                        shown.insert(id.clone(), old.clone());
                    }
                }
                println!(
                    "yadorilink-cfapi-host: showing {} item(s) of {key} in {}",
                    shown.len(),
                    served.path.display()
                );
                self.backend.save_shown(&served.root_id, &shown);
                served.shown = shown;
                served.needs_walk = false;
                true
            }
            None => {
                served.needs_walk = true;
                false
            }
        }
    }

    /// Records a signal from the watcher of root `key`.
    fn on_local(&mut self, key: &str, signal: Signal) {
        let Some(served) = self.served.get_mut(key) else { return };
        match signal {
            Signal::Paths(paths) => served.pending.extend(paths),
            Signal::Overflow => served.rescan = true,
        }
        served.last_signal = Some(Instant::now());
    }

    /// How long until some root has something to apply (`max` when nothing is waiting).
    fn next_deadline(&self, now: Instant, max: Duration) -> Duration {
        self.served
            .values()
            .flat_map(|served| {
                let changes = (!served.pending.is_empty() || served.rescan)
                    .then(|| served.last_signal.map_or(now, |at| at + QUIET));
                let retry = (!served.retry.is_empty()).then(|| served.retry_after.unwrap_or(now));
                [changes, retry]
            })
            .flatten()
            .map(|at| at.saturating_duration_since(now))
            .min()
            .map_or(max, |wait| wait.clamp(Duration::from_millis(10), max))
    }

    /// Applies what the user did in every root that has been quiet long enough.
    fn apply_due_local(&mut self, now: Instant) {
        let due: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| {
                let quiet = served.last_signal.is_none_or(|at| now.duration_since(at) >= QUIET);
                let changes = (!served.pending.is_empty() || served.rescan) && quiet;
                let retry =
                    !served.retry.is_empty() && served.retry_after.is_none_or(|at| at <= now);
                changes || retry
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in due {
            self.apply_local(&key, false);
        }
    }

    /// Applies the signalled paths (and the paths to retry) of root `key` to the daemon. With
    /// `everything`, every path of the sync root is looked at: after the watcher lost changes, and
    /// when a root starts (the user may have changed things while the host was not running).
    fn apply_local(&mut self, key: &str, everything: bool) {
        self.author_local(key, everything);
        if self.served.get(key).is_some_and(|root| root.needs_walk) {
            self.walk(key);
        }
    }

    fn author_local(&mut self, key: &str, everything: bool) {
        let Self { backend, served, .. } = self;
        let Some(root) = served.get_mut(key) else { return };
        let mut signals = std::mem::take(&mut root.pending);
        signals.append(&mut root.retry);
        root.retry_after = None;
        if everything || std::mem::take(&mut root.rescan) {
            signals.extend(backend.listing(&root.path));
            signals.extend(root.shown.values().map(|item| item.path.clone()));
        }
        let report = backend.author(&root.root_id, &root.path, &signals, &mut root.shown);
        for (path, reason) in &report.refused {
            eprintln!(
                "yadorilink-cfapi-host: the daemon refused the change at {}: {reason}",
                path.display()
            );
        }
        if !report.retry.is_empty() {
            root.retry = report.retry;
            root.retry_after = Some(Instant::now() + POLL_INTERVAL);
        }
        if report.rewalk {
            root.needs_walk = true;
        }
        backend.save_shown(&root.root_id, &root.shown);
        if report.applied > 0 {
            println!("yadorilink-cfapi-host: applied {} local change(s) in {key}", report.applied);
        }
    }

    /// The daemon asked for the root's sync root to go: unregister it (the files stay where they
    /// are) and say where they are.
    fn remove(&mut self, root_id: &[u8]) {
        let key = hex(root_id);
        let Some(path) = self.registry.get(&key).cloned() else {
            // Never registered here: the removal is already true.
            self.reports.domain_state(root_id, DomainEvidence::Removed, "");
            return;
        };
        if let Err(e) = self.backend.unregister(&path) {
            eprintln!(
                "yadorilink-cfapi-host: failed to unregister sync root {}: {e}",
                path.display()
            );
            return;
        }
        self.served.remove(&key);
        self.registry.remove(&key);
        self.save_registry();
        println!(
            "yadorilink-cfapi-host: unregistered sync root {} (removal requested)",
            path.display()
        );
        self.reports.domain_state(root_id, DomainEvidence::Removed, &path.to_string_lossy());
    }

    /// A new connection to the daemon: attach every served root again and show the namespaces
    /// again (the daemon may have restarted with a different state).
    fn on_connected(&mut self) {
        for served in self.served.values_mut() {
            self.reports.domain_state(&served.root_id, DomainEvidence::Registered, "");
            served.needs_walk = true;
        }
    }

    fn on_changed(&mut self, root: &[u8], revision: u64, request_id: &[u8]) -> bool {
        let key = hex(root);
        if !self.served.contains_key(&key) {
            // The set of provider folders changed (or an unknown root): list them again.
            return true;
        }
        let ok = self.walk(&key);
        let error = (!ok).then_some("the namespace could not be shown");
        self.reports.signal_done(root, revision, request_id, error);
        false
    }

    fn on_evict(&mut self, root: &[u8], item: &[u8], request_id: &[u8], require_shown_version: &[u8]) {
        let key = hex(root);
        let known = self.served.get(&key).and_then(|s| s.shown.get(item)).map(|s| s.path.clone());
        let mut confirmed = true;
        let path = match known {
            Some(path) => Some(path),
            None if self.served.contains_key(&key) => {
                // After a restart nothing is known yet, but a hydrated copy may be on the disk:
                // look at the namespace, and if that cannot be confirmed say so instead of
                // answering "nothing to evict".
                confirmed = self.walk(&key);
                self.served.get(&key).and_then(|s| s.shown.get(item)).map(|s| s.path.clone())
            }
            None => None,
        };
        // A request that names the version the daemon confirmed is carried out only while the item is shown at
        // that version: a late request must not drop content that arrived meanwhile.
        let shown_version_differs = !require_shown_version.is_empty()
            && !self
                .served
                .get(&key)
                .and_then(|s| s.shown.get(item))
                .is_some_and(|s| s.content_version.starts_with(require_shown_version));
        let (result, error) = match path {
            _ if shown_version_differs => (EvictResult::NotMaterialized, String::new()),
            None if !confirmed => (
                EvictResult::Error,
                "the namespace could not be confirmed, so the item could not be located"
                    .to_string(),
            ),
            None => (EvictResult::NotMaterialized, String::new()),
            Some(path) => match self.backend.evict(&path, item) {
                Ok(()) => (EvictResult::Evicted, String::new()),
                Err(EvictOutcome::NotMaterialized) => (EvictResult::NotMaterialized, String::new()),
                Err(EvictOutcome::Busy) => (EvictResult::Busy, String::new()),
                Err(EvictOutcome::Error(e)) => (EvictResult::Error, e),
                Err(EvictOutcome::Evicted) => (EvictResult::Evicted, String::new()),
            },
        };
        self.reports.evict_done(root, request_id, result, &error);
    }
}

/// Runs `dehydrate_server::serve` for the lifetime of this process on a dedicated OS thread with
/// its own single-threaded Tokio runtime. A crashed/panicked server thread does not bring down
/// the whole process; a daemon eviction attempt would simply see every `DehydrateRequest`
/// connection attempt fail closed, which `materialization_eviction.rs`'s Windows path already
/// treats as "leave the file Hydrated, retry later".
fn spawn_dehydrate_server() {
    let pipe_name = yadorilink_shell_ext::dehydrate_server::pipe_name();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the dehydrate pipe server's Tokio runtime");
        if let Err(e) = runtime.block_on(yadorilink_shell_ext::dehydrate_server::serve(&pipe_name))
        {
            eprintln!("yadorilink-cfapi-host: dehydrate pipe server exited: {e}");
        }
    });
}

fn list_snapshot() -> Option<(Vec<ProviderFolder>, Vec<ProviderRemoval>)> {
    let container = host_paths::container();
    std::fs::create_dir_all(&container).ok()?;
    yadorilink_shell_ext::ipc_client::list_provider_folders(&container.to_string_lossy())
        .map(|snapshot| (snapshot.folders, snapshot.removals))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--unregister-all") {
        unregister_all();
        return;
    }

    println!("yadorilink-cfapi-host: starting (poll interval {POLL_INTERVAL:?})");
    spawn_dehydrate_server();
    let (events, inbox) = std::sync::mpsc::channel::<HostEvent>();
    let session = provider_session::spawn(events.clone());
    let mut host = Host::new(
        RealBackend { events },
        session,
        host_paths::roots_registry_file(),
        host_paths::sync_roots_parent(),
    );
    let mut reconcile_due = true;
    let mut last_reconcile = Instant::now();
    loop {
        if reconcile_due {
            host.reconcile(list_snapshot());
            reconcile_due = false;
            last_reconcile = Instant::now();
        }
        let wait = host.next_deadline(Instant::now(), POLL_INTERVAL);
        match inbox.recv_timeout(wait) {
            Ok(HostEvent::Session(SessionEvent::Connected)) => {
                host.on_connected();
                reconcile_due = true;
            }
            Ok(HostEvent::Session(SessionEvent::Closed)) => {
                eprintln!("yadorilink-cfapi-host: daemon connection closed");
            }
            Ok(HostEvent::Session(SessionEvent::Changed { root, revision, request_id })) => {
                reconcile_due = host.on_changed(&root, revision, &request_id);
            }
            Ok(HostEvent::Session(SessionEvent::Evict {
                root,
                item,
                request_id,
                require_shown_version,
            })) => {
                host.on_evict(&root, &item, &request_id, &require_shown_version);
            }
            Ok(HostEvent::Local { root, signal }) => host.on_local(&root, signal),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_reconcile.elapsed() >= POLL_INTERVAL {
            reconcile_due = true;
        }
        host.apply_due_local(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Recorded {
        registered: Vec<(Vec<u8>, PathBuf)>,
        unregistered: Vec<PathBuf>,
        walks: Vec<Vec<u8>>,
        states: Vec<(Vec<u8>, i32, String)>,
        signals: Vec<(Vec<u8>, u64, bool)>,
        evictions: Vec<(Vec<u8>, i32)>,
        fail_walk: bool,
        evict_result: Option<EvictOutcome>,
        authored: Vec<BTreeSet<PathBuf>>,
        rewalk_next: bool,
        loaded: Option<ShownItems>,
        order: Vec<&'static str>,
        root_missing: bool,
        saved: Vec<ShownItems>,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<Recorded>>);

    impl Backend for Fake {
        fn register_and_connect(&mut self, root_id: &[u8], path: &Path) -> Result<(), String> {
            self.0.borrow_mut().registered.push((root_id.to_vec(), path.to_path_buf()));
            Ok(())
        }
        fn unregister(&mut self, path: &Path) -> Result<(), String> {
            self.0.borrow_mut().unregistered.push(path.to_path_buf());
            Ok(())
        }
        fn sync_namespace(
            &mut self,
            root_id: &[u8],
            path: &Path,
            _previous: &ShownItems,
            _protected: &HashSet<String>,
        ) -> Option<ShownItems> {
            let mut recorded = self.0.borrow_mut();
            recorded.walks.push(root_id.to_vec());
            recorded.order.push("walk");
            if recorded.fail_walk {
                return None;
            }
            Some(ShownItems::from([(
                vec![9u8; 16],
                ShownItem {
                    path: path.join("a.txt"),
                    parent_item_id: vec![],
                    name: "a.txt".into(),
                    directory: false,
                    size: 1,
                    mtime_unix_nanos: 0,
                    content_version: vec![0; 40],
                    parent_generation: 0,
                },
            )]))
        }
        fn evict(&mut self, _path: &Path, _item: &[u8]) -> Result<(), EvictOutcome> {
            match self.0.borrow_mut().evict_result.take() {
                Some(outcome) => Err(outcome),
                None => Ok(()),
            }
        }
        fn load_shown(&mut self, _root_id: &[u8]) -> Option<ShownItems> {
            self.0.borrow().loaded.clone()
        }
        fn save_shown(&mut self, _root_id: &[u8], shown: &ShownItems) {
            self.0.borrow_mut().saved.push(shown.clone());
        }
        fn is_dir(&mut self, _path: &Path) -> bool {
            !self.0.borrow().root_missing
        }
        fn watch(&mut self, _key: &str, _path: &Path) -> Option<Box<dyn std::any::Any>> {
            None
        }
        fn author(
            &mut self,
            _root_id: &[u8],
            _root_path: &Path,
            signals: &BTreeSet<PathBuf>,
            _shown: &mut ShownItems,
        ) -> provider_authoring::Report {
            let mut recorded = self.0.borrow_mut();
            recorded.authored.push(signals.clone());
            recorded.order.push("author");
            provider_authoring::Report {
                applied: signals.len(),
                rewalk: std::mem::take(&mut recorded.rewalk_next),
                ..Default::default()
            }
        }
        fn listing(&mut self, _root_path: &Path) -> BTreeSet<PathBuf> {
            BTreeSet::from([PathBuf::from("listed")])
        }
        fn occupied_locally(&mut self, _path: &Path) -> bool {
            false
        }
    }

    impl Reports for Fake {
        fn domain_state(&self, root: &[u8], evidence: DomainEvidence, location: &str) {
            self.0.borrow_mut().states.push((root.to_vec(), evidence as i32, location.to_string()));
        }
        fn signal_done(&self, root: &[u8], revision: u64, _id: &[u8], error: Option<&str>) {
            self.0.borrow_mut().signals.push((root.to_vec(), revision, error.is_none()));
        }
        fn evict_done(&self, root: &[u8], _id: &[u8], result: EvictResult, _error: &str) {
            self.0.borrow_mut().evictions.push((root.to_vec(), result as i32));
        }
    }

    fn folder(root: u8, name: &str, ready: bool) -> ProviderFolder {
        ProviderFolder {
            root_id: vec![root; 16],
            display_name: name.into(),
            registration_ready: ready,
            ..Default::default()
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yl-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    impl Fake {
        fn host_in(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
            host(fake, dir)
        }
    }

    fn host(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
        Host::new(fake.clone(), fake.clone(), dir.join("roots.txt"), dir.join("roots"))
    }

    #[test]
    fn a_new_root_is_registered_only_when_its_namespace_is_ready() {
        let dir = temp_dir("ready");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        assert!(fake.0.borrow().registered.is_empty(), "registered before the namespace was ready");
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = fake.0.borrow();
        assert_eq!(recorded.registered.len(), 1);
        assert_eq!(recorded.walks.len(), 1);
        assert_eq!(recorded.states[0].1, DomainEvidence::Registered as i32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unconfirmed_snapshot_changes_nothing() {
        let dir = temp_dir("unconfirmed");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let before = fake.0.borrow().registered.len();
        host.reconcile(None);
        let recorded = fake.0.borrow();
        assert_eq!(recorded.registered.len(), before);
        assert!(recorded.unregistered.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restarted host reconnects a root where it was, even before the daemon says its namespace
    /// is ready (it does not register anything new), and does not show a namespace it cannot
    /// confirm.
    #[test]
    fn a_restarted_host_reconnects_the_same_root_at_the_same_place() {
        let dir = temp_dir("restart");
        let first = Fake::default();
        let mut one = host(&first, &dir);
        one.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let place = first.0.borrow().registered[0].1.clone();

        let second = Fake::default();
        let mut two = host(&second, &dir);
        two.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        let recorded = second.0.borrow();
        assert_eq!(recorded.registered, vec![(vec![1u8; 16], place)]);
        assert!(recorded.walks.is_empty(), "showed a namespace that was not ready");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_orphan_is_reported_and_kept_and_a_requested_removal_unregisters() {
        let dir = temp_dir("orphan");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true), folder(2, "Docs", true)], vec![])));
        fake.0.borrow_mut().states.clear();

        host.reconcile(Some((vec![folder(2, "Docs", true)], vec![])));
        {
            let recorded = fake.0.borrow();
            assert!(recorded.unregistered.is_empty(), "removed a root on orphan evidence");
            assert!(recorded
                .states
                .iter()
                .any(|s| s.0 == vec![1u8; 16] && s.1 == DomainEvidence::Orphan as i32));
        }

        let removal = ProviderRemoval { root_id: vec![1; 16], display_name: "Photos".into() };
        host.reconcile(Some((vec![folder(2, "Docs", true)], vec![removal])));
        let recorded = fake.0.borrow();
        assert_eq!(recorded.unregistered.len(), 1);
        let removed =
            recorded.states.iter().find(|s| s.1 == DomainEvidence::Removed as i32).unwrap();
        assert!(!removed.2.is_empty(), "the preserved location was not reported");
        assert!(!read_registry_at(&dir.join("roots.txt")).contains_key(&hex(&[1u8; 16])));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_walk_is_retried_and_a_change_is_acknowledged_by_its_outcome() {
        let dir = temp_dir("walk");
        let fake = Fake::default();
        fake.0.borrow_mut().fail_walk = true;
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().walks.len(), 2, "a failed walk was not retried");

        let more = host.on_changed(&[1; 16], 7, &[3]);
        assert!(!more);
        assert_eq!(fake.0.borrow().signals, vec![(vec![1u8; 16], 7, false)]);

        fake.0.borrow_mut().fail_walk = false;
        host.on_changed(&[1; 16], 8, &[4]);
        assert_eq!(fake.0.borrow().signals[1], (vec![1u8; 16], 8, true));

        // A change naming a root this host does not serve asks for a new listing.
        assert!(host.on_changed(&[9; 16], 1, &[5]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_eviction_request_is_answered_with_what_happened() {
        let dir = temp_dir("evict");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));

        host.on_evict(&[1; 16], &[9; 16], &[1], &[]);
        fake.0.borrow_mut().evict_result = Some(EvictOutcome::Busy);
        host.on_evict(&[1; 16], &[9; 16], &[2], &[]);
        // An item the host does not show counts as not materialized ...
        host.on_evict(&[1; 16], &[8; 16], &[3], &[]);
        // ... but only when the namespace could be confirmed.
        fake.0.borrow_mut().fail_walk = true;
        host.on_evict(&[1; 16], &[7; 16], &[4], &[]);
        fake.0.borrow_mut().fail_walk = false;
        // A request that names another version than the one shown is not carried out ...
        fake.0.borrow_mut().evict_result = Some(EvictOutcome::Error("must not be reached".into()));
        host.on_evict(&[1; 16], &[9; 16], &[5], &[1; 32]);
        fake.0.borrow_mut().evict_result = None;
        // ... and one that names the shown version is.
        host.on_evict(&[1; 16], &[9; 16], &[6], &[0; 32]);
        let results: Vec<i32> = fake.0.borrow().evictions.iter().map(|e| e.1).collect();
        assert_eq!(
            results,
            vec![
                EvictResult::Evicted as i32,
                EvictResult::Busy as i32,
                EvictResult::NotMaterialized as i32,
                EvictResult::Error as i32,
                EvictResult::NotMaterialized as i32,
                EvictResult::Evicted as i32
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the user did is applied once the root has been quiet, with the paths signalled; a
    /// lost-changes signal makes the host look at everything; the first pass after a start does
    /// the same; and a request for a fresh look is honoured.
    #[test]
    fn local_changes_are_applied_after_a_quiet_moment_and_a_start_looks_at_everything() {
        let dir = temp_dir("local");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1u8; 16]);
        // The first pass after the start looked at everything (and sent nothing else).
        assert_eq!(fake.0.borrow().authored.len(), 1);
        assert!(fake.0.borrow().authored[0].contains(Path::new("listed")));

        host.on_local(&key, Signal::Paths(vec![PathBuf::from("a"), PathBuf::from("b")]));
        let now = Instant::now();
        host.apply_due_local(now);
        assert_eq!(fake.0.borrow().authored.len(), 1, "applied before the root was quiet");
        assert!(host.next_deadline(now, Duration::from_secs(60)) <= QUIET);
        host.apply_due_local(now + QUIET + Duration::from_millis(5));
        assert_eq!(
            fake.0.borrow().authored[1],
            BTreeSet::from([PathBuf::from("a"), PathBuf::from("b")])
        );

        host.on_local(&key, Signal::Overflow);
        fake.0.borrow_mut().rewalk_next = true;
        let walks = fake.0.borrow().walks.len();
        host.apply_due_local(Instant::now() + QUIET + Duration::from_millis(5));
        assert!(fake.0.borrow().authored[2].contains(Path::new("listed")));
        assert_eq!(fake.0.borrow().walks.len(), walks + 1, "a fresh look was not taken");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restart judges the user's offline changes against the daemon's namespace BEFORE showing
    /// it (so a deleted placeholder is reported, not put back); the very first showing of a root
    /// has nothing to judge against and shows first.
    #[test]
    fn a_restart_judges_offline_changes_before_showing_and_a_first_run_shows_first() {
        let dir = temp_dir("offline");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        // First run: nothing recorded before, so the namespace is shown before the local pass,
        // and what was shown is recorded.
        assert_eq!(fake.0.borrow().order, vec!["walk", "author"]);
        assert!(!fake.0.borrow().saved.is_empty());

        // A restart with a record of what was shown: the local pass comes first.
        let again = Fake::default();
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        let mut restarted = Fake::host_in(&again, &dir);
        restarted.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(again.0.borrow().order, vec!["author", "walk"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A namespace pushed by the daemon never overtakes what the user just did: the pending local
    /// changes are applied before the placeholders are shown again.
    /// A recorded root whose folder is gone is not recreated empty (that would read as the user
    /// deleting everything); a root never seen before is created.
    #[test]
    fn a_missing_registered_root_folder_is_not_recreated() {
        let dir = temp_dir("missing");
        let first = Fake::default();
        host(&first, &dir).reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let again = Fake::default();
        again.0.borrow_mut().root_missing = true;
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        host(&again, &dir).reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(again.0.borrow().registered.is_empty());
        assert!(again.0.borrow().authored.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pushed_namespace_is_shown_only_after_pending_local_changes_are_applied() {
        let dir = temp_dir("pushed");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        fake.0.borrow_mut().order.clear();
        host.on_local(&hex(&[1u8; 16]), Signal::Paths(vec![PathBuf::from("deleted-by-the-user")]));
        host.on_changed(&[1; 16], 5, &[1]);
        assert_eq!(fake.0.borrow().order, vec!["author", "walk"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shown_item_survives_the_journal_unchanged() {
        let item = ShownItem {
            path: PathBuf::from(r"C:\Users\a\YadoriLink\Photos\日本語 file.txt"),
            parent_item_id: vec![4; 16],
            name: "日本語 file.txt".into(),
            directory: false,
            size: 12,
            mtime_unix_nanos: -5,
            content_version: vec![9; 40],
            parent_generation: 3,
        };
        let line = encode_shown(&[7; 16], &item);
        assert_eq!(decode_shown(&line), Some((vec![7; 16], item)));
        assert_eq!(decode_shown("not\ta line"), None);
    }

    #[test]
    fn the_registry_round_trips_and_ignores_lines_of_another_shape() {
        let mut roots = HashMap::new();
        roots.insert(hex(&[1u8; 16]), PathBuf::from(r"C:\Users\a\YadoriLink\Photos"));
        let text = render_registry(&roots);
        let mut with_legacy = text.clone();
        with_legacy.push_str("C:\\old\\plain\\folder\nnot-hex\tC:\\x\n");
        assert_eq!(parse_registry(&with_legacy), roots);
        let seen: HashSet<_> = parse_registry(&text).into_keys().collect();
        assert_eq!(seen.len(), 1);
    }
}
