//! Turning what the user does in a sync root into `ProviderApplyChange` requests.
//!
//! The host does not decide what a change MEANS. A directory watcher only says "something
//! happened at this path"; this module looks at that path and at what the daemon last showed
//! there (the [`ShownItems`]) and derives the one operation that makes the daemon's namespace
//! match what the user did:
//!
//! * a name with no item behind it is a CREATE (a file's bytes first go to a private copy in the
//!   daemon's `ingest` directory, which the daemon then reads under its own checks);
//! * the placeholder of a known item that is no longer where it was, or is no longer called what
//!   it was, is a MODIFY that renames or moves it;
//! * a placeholder the user wrote to (no longer in sync, with a different size or time), or a plain
//!   file that took the place of a known item (an editor's save-by-replacing), is a MODIFY with
//!   the new bytes;
//! * a known item whose name is gone, and which is nowhere else in the sync root either, is a
//!   DELETE.
//!
//! Every request carries the version the user saw as its base, so the daemon, not the host, finds
//! a conflict. The answer is adopted the way the daemon issued it: a created file becomes the
//! placeholder of the item the daemon made, and an accepted edit is marked in sync.
//!
//! One operation is journaled before it is sent and cleared after its answer was adopted, with the
//! (session, sequence) pair the daemon uses to recognize a repeat: after a crash the same request
//! is sent again and the daemon answers it from its record instead of applying it twice.

use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_root_authority::durable_dir::{
    move_durably, publish_durably, remove_file_durably, Replace,
};
use yadorilink_ipc_proto::shellipc::{
    EntryKind, ProviderAppliedItem, ProviderApplyChangeRequest, ProviderApplyChangeResponse,
    ProviderApplyFailure, ProviderApplyOutcome, ProviderChangeKind, ProviderContentSource,
    ProviderItemMetadata,
};

use crate::provider_namespace::{PlaceholderInfo, ShownItem, ShownItems};

/// What the file system says about a path.
#[derive(Clone, Debug)]
pub struct LocalStat {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    /// The Cloud Files placeholder state, when the entry is a placeholder.
    pub placeholder: Option<PlaceholderInfo>,
}

/// A finished private copy of a file's bytes in the daemon's ingest directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestCopy {
    pub name: String,
    pub size: u64,
    pub sha256: Vec<u8>,
}

#[derive(Debug)]
pub enum CopyError {
    /// The file changed while it was copied, or could not be read right now: copy again later.
    Unstable(String),
    Failed(String),
}

/// The file system side of the host.
pub trait Local {
    fn stat(&self, path: &Path) -> Option<LocalStat>;
    fn children(&self, directory: &Path) -> Vec<PathBuf>;
    fn copy_to_ingest(&self, path: &Path) -> Result<IngestCopy, CopyError>;
    /// Binds `path` to the daemon's item: converts a plain file or folder into a placeholder
    /// carrying the item id, or marks an existing placeholder in sync.
    fn adopt(&self, path: &Path, item_id: &[u8]) -> Result<(), String>;
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()>;
    /// Makes the placeholder at `path` an ordinary file again: its bytes stay, its item identity
    /// goes.
    fn unbind(&self, path: &Path) -> Result<(), String>;
    /// Removes the file at `path` (its bytes are kept elsewhere by the daemon).
    fn discard(&self, path: &Path) -> std::io::Result<()>;
    /// The path of the placeholder of `item_id` anywhere below `root`.
    fn locate(&self, root: &Path, item_id: &[u8]) -> Located;
    /// Whether `path` is confirmed not to exist (`NotFound`). A path that cannot be inspected
    /// (access denied, a sharing violation) is not missing.
    fn confirmed_missing(&self, path: &Path) -> bool;
}

/// The answer to "where is the placeholder of this item".
#[derive(Debug, PartialEq, Eq)]
pub enum Located {
    Found(PathBuf),
    /// The whole sync root was searched and it is nowhere.
    Absent,
    /// Some part of the sync root could not be searched.
    Unknown,
}

/// The daemon side of the host.
pub trait Api {
    /// `None`: the daemon could not be asked or did not answer.
    fn apply(
        &self,
        root: &[u8],
        request: ProviderApplyChangeRequest,
    ) -> Option<ProviderApplyChangeResponse>;
}

/// What a batch of signals led to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Operations the daemon accepted.
    pub applied: usize,
    /// Paths to look at again later: the daemon was busy, or a file was still changing.
    pub retry: BTreeSet<PathBuf>,
    /// The namespace changed in a way only a fresh look shows (a concurrent edit, a conflict).
    pub rewalk: bool,
    /// Operations the daemon refused for good, with its reason.
    pub refused: Vec<(PathBuf, String)>,
}

/// What an edit of an existing item changes.
#[derive(Default)]
struct Edit {
    /// The folder the item moved to.
    new_parent: Option<Vec<u8>>,
    /// The name the item was given.
    new_name: Option<String>,
    /// New bytes, copied for the daemon to ingest.
    content: bool,
}

/// What one pass works with: the items shown, the file system, the daemon, and the report being
/// built.
struct Ctx<'a> {
    shown: &'a mut ShownItems,
    local: &'a dyn Local,
    api: &'a dyn Api,
    report: Report,
    /// An operation went unanswered and is still journaled: nothing new may start over it.
    blocked: bool,
}

impl Ctx<'_> {
    /// Whether a new operation must wait (an earlier one is unanswered); the path is looked at
    /// again later.
    fn hold(&mut self, path: &Path) -> bool {
        if self.blocked {
            self.report.retry.insert(path.to_path_buf());
        }
        self.blocked
    }
}

/// The authoring state of one served root.
pub struct Authoring {
    root_id: Vec<u8>,
    root_path: PathBuf,
    state_dir: PathBuf,
    session: [u8; 16],
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        // `RandomState` is seeded from the operating system's generator for each instance.
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        let bytes = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
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

fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // A durable publish: the journal or sequence file is on disk before the request that
    // depends on it is sent.
    publish_durably(&tmp, path, Replace::Yes)
}

/// The request of the journaled operation and where its answer lands.
struct Pending {
    request: ProviderApplyChangeRequest,
    path: PathBuf,
    /// The size and modification time (unix nanoseconds) of the file the request describes. The
    /// answer is adopted only if the file still looks like that: a later write is not covered by
    /// what the daemon accepted.
    expect: Option<(u64, i64)>,
}

impl Pending {
    fn encode(&self) -> String {
        let r = &self.request;
        let mut lines = vec![
            format!("path={}", hex(self.path.to_string_lossy().as_bytes())),
            format!("request_id={}", hex(&r.request_id)),
            format!("session={}", hex(&r.session_id)),
            format!("seq={}", r.operation_seq),
            format!("kind={}", r.kind),
            format!("item={}", hex(&r.item_id)),
            format!("entry_kind={}", r.entry_kind),
            format!("base={}", hex(&r.base_version_hash)),
            format!("recursive={}", r.recursive),
        ];
        if let Some(parent) = &r.parent_item_id {
            lines.push(format!("parent={}", hex(parent)));
        }
        if let Some(name) = &r.name {
            lines.push(format!("name={}", hex(name.as_bytes())));
        }
        if let Some(generation) = r.parent_generation {
            lines.push(format!("parent_generation={generation}"));
        }
        if let Some(content) = &r.content {
            lines.push(format!(
                "content={} {} {}",
                content.ingest_name,
                content.size,
                hex(&content.sha256)
            ));
        }
        if let Some(mtime) = r.metadata.as_ref().and_then(|m| m.mtime_unix_nanos) {
            lines.push(format!("mtime={mtime}"));
        }
        if let Some((size, mtime)) = self.expect {
            lines.push(format!("expect={size},{mtime}"));
        }
        lines.push(String::new());
        lines.join("\n")
    }

    fn decode(text: &str, root_id: &[u8]) -> Option<Self> {
        let get = |key: &str| {
            text.lines().find_map(|line| line.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        };
        let path = PathBuf::from(String::from_utf8(unhex(get("path")?)?).ok()?);
        let content = get("content").and_then(|value| {
            let mut parts = value.split(' ');
            Some(ProviderContentSource {
                ingest_name: parts.next()?.to_string(),
                size: parts.next()?.parse().ok()?,
                sha256: unhex(parts.next()?)?,
            })
        });
        let request = ProviderApplyChangeRequest {
            request_id: unhex(get("request_id")?)?,
            session_id: unhex(get("session")?)?,
            operation_seq: get("seq")?.parse().ok()?,
            root_id: root_id.to_vec(),
            kind: get("kind")?.parse().ok()?,
            item_id: unhex(get("item")?)?,
            parent_item_id: match get("parent") {
                Some(v) => Some(unhex(v)?),
                None => None,
            },
            name: match get("name") {
                Some(v) => Some(String::from_utf8(unhex(v)?).ok()?),
                None => None,
            },
            entry_kind: get("entry_kind")?.parse().ok()?,
            base_version_hash: unhex(get("base")?)?,
            content,
            recursive: get("recursive")? == "true",
            parent_generation: get("parent_generation").and_then(|v| v.parse().ok()),
            metadata: Some(ProviderItemMetadata {
                mtime_unix_nanos: get("mtime").and_then(|v| v.parse().ok()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let expect = get("expect").and_then(|v| {
            let (size, mtime) = v.split_once(',')?;
            Some((size.parse().ok()?, mtime.parse().ok()?))
        });
        Some(Self { request, path, expect })
    }
}

/// How an answer is acted on.
enum Verdict {
    Accepted(Option<ProviderAppliedItem>, bool),
    /// Ask again later, with the same request.
    Retry,
    /// Nothing there to apply it to (the item is gone): look again.
    Gone,
    /// The daemon wants these bytes kept under another name.
    KeepLocal(String),
    Refused(String),
}

fn verdict(response: &ProviderApplyChangeResponse) -> Verdict {
    if response.ok {
        let concurrent = response.outcome() != ProviderApplyOutcome::Applied;
        return Verdict::Accepted(response.item.clone(), concurrent);
    }
    match response.failure() {
        ProviderApplyFailure::NotReady
        | ProviderApplyFailure::Retry
        | ProviderApplyFailure::StaleView
        | ProviderApplyFailure::StaleOperation
        | ProviderApplyFailure::IngestUnstable
        | ProviderApplyFailure::LowDisk
        | ProviderApplyFailure::Cancelled => Verdict::Retry,
        ProviderApplyFailure::NotFound | ProviderApplyFailure::InvalidBase => Verdict::Gone,
        ProviderApplyFailure::KeepLocal => Verdict::KeepLocal(response.suggested_name.clone()),
        other => Verdict::Refused(format!("{other:?}: {}", response.error)),
    }
}

impl Authoring {
    /// Opens (creating on first use) the authoring state of a root under `state_dir`.
    pub fn open(root_id: &[u8], root_path: &Path, state_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let session_file = state_dir.join("session");
        let session =
            match std::fs::read_to_string(&session_file).ok().and_then(|t| unhex(t.trim())) {
                Some(bytes) if bytes.len() == 16 => bytes.try_into().expect("16 bytes"),
                _ => {
                    let fresh = random_bytes::<16>();
                    write_atomically(&session_file, &hex(&fresh))?;
                    fresh
                }
            };
        Ok(Self {
            root_id: root_id.to_vec(),
            root_path: root_path.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            session,
        })
    }

    fn pending_file(&self) -> PathBuf {
        self.state_dir.join("pending")
    }

    /// The next sequence number, recorded before it is used so a crash never reuses one.
    fn next_seq(&self) -> std::io::Result<u64> {
        let file = self.state_dir.join("seq");
        let last =
            std::fs::read_to_string(&file).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0u64);
        let next = last + 1;
        write_atomically(&file, &next.to_string())?;
        Ok(next)
    }

    fn request(&self, kind: ProviderChangeKind) -> std::io::Result<ProviderApplyChangeRequest> {
        Ok(ProviderApplyChangeRequest {
            request_id: random_bytes::<16>().to_vec(),
            session_id: self.session.to_vec(),
            operation_seq: self.next_seq()?,
            root_id: self.root_id.clone(),
            kind: kind as i32,
            ..Default::default()
        })
    }

    /// Sends the operation left by a crash, if any, and adopts its answer.
    pub fn resume(&self, shown: &mut ShownItems, local: &dyn Local, api: &dyn Api) -> Report {
        let mut cx = Ctx { shown, local, api, report: Report::default(), blocked: false };
        self.resume_in(&mut cx);
        cx.report
    }

    fn resume_in(&self, cx: &mut Ctx<'_>) {
        let Ok(text) = std::fs::read_to_string(self.pending_file()) else { return };
        match Pending::decode(&text, &self.root_id) {
            Some(pending) => {
                self.send(pending, cx);
            }
            None => {
                eprintln!("yadorilink-cfapi-host: dropping an unreadable journal entry");
                let _ = std::fs::remove_file(self.pending_file());
            }
        }
    }

    /// Looks at the paths a watcher signalled and applies what the user did to the daemon.
    pub fn process(
        &self,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
        local: &dyn Local,
        api: &dyn Api,
    ) -> Report {
        let mut cx = Ctx { shown, local, api, report: Report::default(), blocked: false };
        let cx = &mut cx;
        self.resume_in(cx);
        if self.pending_file().exists() {
            // The earlier operation is still unanswered. It is sent again before anything new,
            // so nothing else is started now and nothing is lost: look at these paths later.
            cx.report.retry.extend(signals.iter().cloned());
            return std::mem::take(&mut cx.report);
        }
        // Parents before children: a new folder must have its item before what is inside it.
        let mut paths: Vec<&PathBuf> = signals
            .iter()
            .filter(|p| p.starts_with(&self.root_path) && **p != self.root_path)
            .collect();
        paths.sort_by_key(|p| p.components().count());

        let mut vanished: Vec<(Vec<u8>, ShownItem)> = Vec::new();
        let mut done: HashSet<PathBuf> = HashSet::new();
        for path in paths {
            if !done.insert(path.clone()) {
                continue;
            }
            match cx.local.stat(path) {
                Some(stat) => self.on_present(path, &stat, cx, &mut done),
                None if !cx.local.confirmed_missing(path) => {
                    // Could not be inspected right now (in use, access denied): not a delete.
                    cx.report.retry.insert(path.clone());
                }
                None => {
                    if let Some((id, item)) = cx.shown.iter().find(|(_, item)| item.path == *path) {
                        vanished.push((id.clone(), item.clone()));
                    }
                }
            }
        }
        // Deletes last, shallowest first, once the items that merely moved have been seen where
        // they went.
        vanished.sort_by_key(|(_, item)| item.path.components().count());
        let mut deleted: Vec<PathBuf> = Vec::new();
        for (id, item) in vanished {
            // Skip what an earlier step already settled (an item that moved is shown at its new
            // path by now) and what lies below a folder deleted in this pass.
            let still_there = cx.shown.get(&id).is_some_and(|current| current.path == item.path);
            if !still_there || deleted.iter().any(|dir| item.path.starts_with(dir)) {
                continue;
            }
            match cx.local.locate(&self.root_path, &id) {
                Located::Found(moved_to) => {
                    // It is still in the sync root, under another path: the move is what happened.
                    if let Some(stat) = cx.local.stat(&moved_to) {
                        done.insert(moved_to.clone());
                        self.on_present(&moved_to, &stat, cx, &mut done);
                    }
                    continue;
                }
                Located::Unknown => {
                    // Only a complete search that finds nothing authorizes a delete.
                    cx.report.retry.insert(item.path.clone());
                    continue;
                }
                Located::Absent => {}
            }
            self.delete(&id, &item, cx);
            deleted.push(item.path.clone());
        }
        std::mem::take(&mut cx.report)
    }

    fn on_present(
        &self,
        path: &Path,
        stat: &LocalStat,
        cx: &mut Ctx<'_>,
        done: &mut HashSet<PathBuf>,
    ) {
        if stat.is_symlink {
            eprintln!(
                "yadorilink-cfapi-host: {} is a symbolic link; it is not synchronized",
                path.display()
            );
            return;
        }
        let Some(parent) = path.parent() else { return };
        let Some(parent_item) = self.item_of_directory(parent, cx.shown, cx.local) else {
            // The folder above has no item yet (it is signalled too and comes first), or is not
            // this root's: nothing to place this under right now.
            cx.report.retry.insert(path.to_path_buf());
            return;
        };
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let known_id = stat.placeholder.as_ref().and_then(|p| p.item_id.clone());
        match known_id {
            Some(id) if cx.shown.contains_key(&id) => {
                self.on_known(path, stat, &id, &parent_item, &name, cx);
            }
            // The placeholder of an item shown after the last look: look again.
            Some(_) => cx.report.rewalk = true,
            None => {
                // A plain file or folder. If an item was shown at exactly this path, the plain
                // entry replaced it (an editor saving by writing a new file over the old one).
                let replaced = cx
                    .shown
                    .iter()
                    .find(|(_, item)| item.path == path && !item.directory && !stat.is_dir)
                    .map(|(id, _)| id.clone());
                match replaced {
                    Some(id) => self.on_replaced(path, stat, &id, cx),
                    None => self.create(path, stat, &parent_item, &name, cx, done),
                }
            }
        }
    }

    /// The item of a folder inside the sync root: empty for the root itself.
    fn item_of_directory(
        &self,
        directory: &Path,
        shown: &ShownItems,
        local: &dyn Local,
    ) -> Option<Vec<u8>> {
        if directory == self.root_path {
            return Some(Vec::new());
        }
        let from_state = shown.iter().find(|(_, item)| item.directory && item.path == directory);
        if let Some((id, _)) = from_state {
            return Some(id.clone());
        }
        local.stat(directory)?.placeholder?.item_id.filter(|id| shown.contains_key(id))
    }
    fn create(
        &self,
        path: &Path,
        stat: &LocalStat,
        parent_item: &[u8],
        name: &str,
        cx: &mut Ctx<'_>,
        done: &mut HashSet<PathBuf>,
    ) {
        if cx.hold(path) {
            return;
        }
        let Ok(mut request) = self.request(ProviderChangeKind::Create) else { return };
        request.parent_item_id = Some(parent_item.to_vec());
        request.name = Some(name.to_string());
        request.entry_kind =
            if stat.is_dir { EntryKind::Directory as i32 } else { EntryKind::File as i32 };
        request.metadata = Some(ProviderItemMetadata {
            mtime_unix_nanos: Some(stat.mtime_unix_nanos),
            ..Default::default()
        });
        if !stat.is_dir {
            match cx.local.copy_to_ingest(path) {
                Ok(copy) => request.content = Some(content_of(&copy)),
                Err(CopyError::Unstable(why)) => {
                    eprintln!(
                        "yadorilink-cfapi-host: {} is still changing ({why})",
                        path.display()
                    );
                    cx.report.retry.insert(path.to_path_buf());
                    return;
                }
                Err(CopyError::Failed(why)) => {
                    cx.report.refused.push((path.to_path_buf(), why));
                    return;
                }
            }
        }
        let expect = (!stat.is_dir).then_some((stat.size, stat.mtime_unix_nanos));
        if self.send(Pending { request, path: path.to_path_buf(), expect }, cx) && stat.is_dir {
            // What was inside a folder that arrived whole (moved in) never got its own signal.
            for child in cx.local.children(path) {
                if done.insert(child.clone()) {
                    if let Some(child_stat) = cx.local.stat(&child) {
                        self.on_present(&child, &child_stat, cx, done);
                    }
                }
            }
        }
    }

    fn on_replaced(&self, path: &Path, stat: &LocalStat, id: &[u8], cx: &mut Ctx<'_>) {
        let Some(item) = cx.shown.get(id).cloned() else { return };
        self.edit(path, stat, id, &item, Edit { content: true, ..Edit::default() }, cx);
    }
    fn on_known(
        &self,
        path: &Path,
        stat: &LocalStat,
        id: &[u8],
        parent_item: &[u8],
        name: &str,
        cx: &mut Ctx<'_>,
    ) {
        let Some(item) = cx.shown.get(id).cloned() else { return };
        let moved = parent_item != item.parent_item_id.as_slice();
        let renamed = name != item.name;
        let in_sync = stat.placeholder.as_ref().is_none_or(|p| p.in_sync);
        let content_changed = !item.directory
            && !in_sync
            && (stat.size != item.size
                || (stat.mtime_unix_nanos - item.mtime_unix_nanos).abs() > 200);
        if !moved && !renamed && !content_changed {
            return;
        }
        // The name may be held by another item that this file replaced (an editor saving
        // through a temporary file that is renamed over the original): that item goes first.
        let displaced = cx
            .shown
            .iter()
            .find(|(other, shown)| other.as_slice() != id && shown.path == path)
            .map(|(other, shown)| (other.clone(), shown.clone()));
        if let Some((other, shown)) = displaced {
            self.delete(&other, &shown, cx);
            if cx.shown.contains_key(&other) {
                // Not deleted (the daemon was busy): do this again from the start later.
                cx.report.retry.insert(path.to_path_buf());
                return;
            }
        }
        let edit = Edit {
            new_parent: moved.then(|| parent_item.to_vec()),
            new_name: renamed.then(|| name.to_string()),
            content: content_changed,
        };
        self.edit(path, stat, id, &item, edit, cx);
    }
    fn edit(
        &self,
        path: &Path,
        stat: &LocalStat,
        id: &[u8],
        item: &ShownItem,
        edit: Edit,
        cx: &mut Ctx<'_>,
    ) {
        let Edit { new_parent, new_name, content } = edit;
        if cx.hold(path) {
            return;
        }
        let Ok(mut request) = self.request(ProviderChangeKind::Modify) else { return };
        request.item_id = id.to_vec();
        request.base_version_hash = item.content_version.clone();
        if new_parent.is_some() || new_name.is_some() {
            // The folder the item leaves is the one the user saw it in.
            request.parent_generation = Some(item.parent_generation);
        }
        request.parent_item_id = new_parent;
        request.name = new_name;
        request.entry_kind =
            if item.directory { EntryKind::Directory as i32 } else { EntryKind::File as i32 };
        request.metadata = Some(ProviderItemMetadata {
            mtime_unix_nanos: Some(stat.mtime_unix_nanos),
            ..Default::default()
        });
        if content {
            match cx.local.copy_to_ingest(path) {
                Ok(copy) => request.content = Some(content_of(&copy)),
                Err(CopyError::Unstable(why)) => {
                    eprintln!(
                        "yadorilink-cfapi-host: {} is still changing ({why})",
                        path.display()
                    );
                    cx.report.retry.insert(path.to_path_buf());
                    return;
                }
                Err(CopyError::Failed(why)) => {
                    cx.report.refused.push((path.to_path_buf(), why));
                    return;
                }
            }
        }
        let expect = (!item.directory).then_some((stat.size, stat.mtime_unix_nanos));
        self.send(Pending { request, path: path.to_path_buf(), expect }, cx);
    }

    fn delete(&self, id: &[u8], item: &ShownItem, cx: &mut Ctx<'_>) {
        if cx.hold(&item.path) {
            return;
        }
        let Ok(mut request) = self.request(ProviderChangeKind::Delete) else { return };
        request.item_id = id.to_vec();
        request.base_version_hash = item.content_version.clone();
        request.entry_kind =
            if item.directory { EntryKind::Directory as i32 } else { EntryKind::File as i32 };
        request.recursive =
            item.directory && cx.shown.values().any(|other| other.parent_item_id == id);
        self.send(Pending { request, path: item.path.clone(), expect: None }, cx);
    }

    /// Journals `pending`, sends it, and acts on the answer. True when the daemon accepted it.
    fn send(&self, pending: Pending, cx: &mut Ctx<'_>) -> bool {
        if let Err(error) = write_atomically(&self.pending_file(), &pending.encode()) {
            cx.report
                .refused
                .push((pending.path.clone(), format!("could not journal the change: {error}")));
            return false;
        }
        let Some(response) = cx.api.apply(&self.root_id, pending.request.clone()) else {
            // Unanswered: the journal keeps the operation, a later pass sends it again, and
            // nothing else is started over it.
            cx.blocked = true;
            cx.report.retry.insert(pending.path.clone());
            return false;
        };
        let accepted = self.settle(&pending, &response, cx);
        let _ = std::fs::remove_file(self.pending_file());
        accepted
    }

    fn settle(
        &self,
        pending: &Pending,
        response: &ProviderApplyChangeResponse,
        cx: &mut Ctx<'_>,
    ) -> bool {
        let request = &pending.request;
        match verdict(response) {
            Verdict::Accepted(item, concurrent) => {
                cx.report.applied += 1;
                cx.report.rewalk |= concurrent;
                // What is inside a folder that moved or was renamed is at new paths now.
                cx.report.rewalk |= request.entry_kind == EntryKind::Directory as i32
                    && request.kind == ProviderChangeKind::Modify as i32
                    && (request.name.is_some() || request.parent_item_id.is_some());
                if request.kind == ProviderChangeKind::Delete as i32 {
                    forget(cx.shown, &request.item_id);
                } else if let Some(item) = item {
                    let unchanged = pending.expect.is_none_or(|(size, mtime)| {
                        cx.local.stat(&pending.path).is_some_and(|now| {
                            now.size == size && (now.mtime_unix_nanos - mtime).abs() <= 200
                        })
                    });
                    if !unchanged {
                        // Written to again while the daemon was answering: what it accepted is
                        // not what is on the disk. The file stays as it is (not in sync) and
                        // is looked at again; the item is shown as the daemon now has it, so
                        // the difference is what the next pass sends.
                        cx.report.retry.insert(pending.path.clone());
                    } else if concurrent && request.content.is_some() {
                        // The item moved on since the version the user edited: the daemon kept
                        // the user's bytes beside it as a conflict copy and answered with the
                        // current item. The file is not that item's content, so it is not bound
                        // to it; it is removed (the bytes are the conflict copy's) and the fresh
                        // look shows the current content and the copy.
                        if let Err(error) = cx.local.discard(&pending.path) {
                            eprintln!(
                                "yadorilink-cfapi-host: could not replace {} with the current version: {error}",
                                pending.path.display()
                            );
                        }
                        // Not shown until the fresh look puts it back: the missing path must
                        // not read as the user deleting the current item.
                        cx.shown.remove(&item.item_id);
                        return true;
                    } else if let Err(error) = cx.local.adopt(&pending.path, &item.item_id) {
                        eprintln!(
                            "yadorilink-cfapi-host: could not bind {} to its item: {error}",
                            pending.path.display()
                        );
                        cx.report.rewalk = true;
                    }
                    cx.shown.insert(item.item_id.clone(), shown_of(&pending.path, &item));
                }
                true
            }
            Verdict::Retry => {
                cx.report.retry.insert(pending.path.clone());
                false
            }
            Verdict::Gone => {
                if request.kind == ProviderChangeKind::Delete as i32 {
                    forget(cx.shown, &request.item_id);
                } else {
                    // The version the user saw is gone: look again, then judge the file again.
                    cx.report.rewalk = true;
                    cx.report.retry.insert(pending.path.clone());
                }
                false
            }
            Verdict::KeepLocal(suggested) => {
                // Keep the bytes under the name the daemon proposed and send them as a new item.
                let target = pending.path.with_file_name(&suggested);
                if suggested.is_empty()
                    || !crate::provider_namespace::valid_component(&suggested)
                    || target.exists()
                    || cx.local.rename(&pending.path, &target).is_err()
                    // The kept bytes are the user's own file now, not that item's.
                    || (cx.local.stat(&target).is_some_and(|s| s.placeholder.is_some())
                        && cx.local.unbind(&target).is_err())
                {
                    cx.report
                        .refused
                        .push((pending.path.clone(), "kept local; no usable name".into()));
                    return false;
                }
                cx.report.rewalk = true;
                cx.report.retry.insert(target);
                false
            }
            Verdict::Refused(reason) => {
                cx.report.refused.push((pending.path.clone(), reason));
                // A repeat of the same request would be refused the same way; look again instead.
                cx.report.rewalk = true;
                false
            }
        }
    }
}

fn content_of(copy: &IngestCopy) -> ProviderContentSource {
    ProviderContentSource {
        ingest_name: copy.name.clone(),
        size: copy.size,
        sha256: copy.sha256.clone(),
    }
}

fn shown_of(path: &Path, item: &ProviderAppliedItem) -> ShownItem {
    ShownItem {
        path: path.to_path_buf(),
        parent_item_id: item.parent_item_id.clone(),
        name: item.name.clone(),
        directory: item.entry_kind == EntryKind::Directory as i32,
        size: item.size,
        mtime_unix_nanos: item.mtime_unix_nanos,
        content_version: item.content_version.clone(),
        parent_generation: item.parent_generation,
    }
}

/// Removes `id` and everything below it from the shown items.
fn forget(shown: &mut ShownItems, id: &[u8]) {
    let mut gone = vec![id.to_vec()];
    while let Some(next) = gone.pop() {
        shown.remove(&next);
        gone.extend(shown.iter().filter(|(_, i)| i.parent_item_id == next).map(|(k, _)| k.clone()));
    }
}

// ---- the real file system ----------------------------------------------------------------

/// The Windows implementation of [`Local`].
pub struct WindowsLocal {
    pub ingest_dir: PathBuf,
}

impl Local for WindowsLocal {
    fn stat(&self, path: &Path) -> Option<LocalStat> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        let placeholder = crate::provider_namespace::placeholder_info(path);
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as i64);
        // A placeholder is a reparse point too, but not a link the user made.
        let is_symlink = placeholder.is_none() && metadata.file_type().is_symlink();
        Some(LocalStat {
            is_dir: metadata.is_dir(),
            is_symlink,
            size: metadata.len(),
            mtime_unix_nanos: mtime,
            placeholder,
        })
    }

    fn children(&self, directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory)
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    }

    fn copy_to_ingest(&self, path: &Path) -> Result<IngestCopy, CopyError> {
        use std::os::windows::fs::OpenOptionsExt;
        // Readers, writers and deleters of the user's file are all allowed: the copy is verified
        // by looking at the file again afterwards, not by locking the user out.
        const SHARE_ALL: u32 = 7;
        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_ALL)
            .open(path)
            .map_err(|e| CopyError::Unstable(e.to_string()))?;
        let before = source.metadata().map_err(|e| CopyError::Unstable(e.to_string()))?;
        let name = format!("c{}", hex(&random_bytes::<16>()));
        let partial = self.ingest_dir.join(format!(".{name}.partial"));
        let finished = self.ingest_dir.join(&name);
        let copy = (|| -> Result<(u64, Vec<u8>), CopyError> {
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)
                .map_err(|e| CopyError::Failed(format!("{}: {e}", partial.display())))?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; 1 << 20];
            let mut size = 0u64;
            loop {
                let n = source.read(&mut buffer).map_err(|e| CopyError::Unstable(e.to_string()))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                target.write_all(&buffer[..n]).map_err(|e| CopyError::Failed(e.to_string()))?;
                size += n as u64;
            }
            target.sync_all().map_err(|e| CopyError::Failed(e.to_string()))?;
            Ok((size, hasher.finalize().to_vec()))
        })();
        let (size, sha256) = match copy {
            Ok(done) => done,
            Err(error) => {
                let _ = std::fs::remove_file(&partial);
                return Err(error);
            }
        };
        let after = source.metadata().map_err(|e| CopyError::Unstable(e.to_string()))?;
        if before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
            || after.len() != size
        {
            let _ = std::fs::remove_file(&partial);
            return Err(CopyError::Unstable("the file changed while it was copied".into()));
        }
        // The copy is on disk under its name before the request that names it is journaled.
        publish_durably(&partial, &finished, Replace::No).map_err(|e| {
            let _ = std::fs::remove_file(&partial);
            CopyError::Failed(e.to_string())
        })?;
        Ok(IngestCopy { name, size, sha256 })
    }

    fn adopt(&self, path: &Path, item_id: &[u8]) -> Result<(), String> {
        crate::provider_namespace::bind_to_item(path, item_id)
    }

    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        // Never replacing, and durable: the kept bytes are the user's only copy under this name.
        move_durably(from, to, Replace::No)
    }

    fn unbind(&self, path: &Path) -> Result<(), String> {
        crate::provider_namespace::revert_to_plain(path)
    }

    fn discard(&self, path: &Path) -> std::io::Result<()> {
        remove_file_durably(path)
    }

    fn locate(&self, root: &Path, item_id: &[u8]) -> Located {
        fn scan(directory: &Path, item_id: &[u8], complete: &mut bool) -> Option<PathBuf> {
            let Ok(entries) = std::fs::read_dir(directory) else {
                *complete = false;
                return None;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    *complete = false;
                    continue;
                };
                let path = entry.path();
                let info = crate::provider_namespace::placeholder_info(&path);
                if info.as_ref().and_then(|i| i.item_id.as_deref()) == Some(item_id) {
                    return Some(path);
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    if let Some(found) = scan(&path, item_id, complete) {
                        return Some(found);
                    }
                }
            }
            None
        }
        let mut complete = true;
        match scan(root, item_id, &mut complete) {
            Some(found) => Located::Found(found),
            None if complete => Located::Absent,
            None => Located::Unknown,
        }
    }

    fn confirmed_missing(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const ROOT: &str = r"C:\sync";

    fn p(rel: &str) -> PathBuf {
        PathBuf::from(ROOT).join(rel)
    }

    fn item(rel: &str, id: u8, parent: u8, directory: bool, size: u64) -> (Vec<u8>, ShownItem) {
        (
            vec![id; 16],
            ShownItem {
                path: p(rel),
                parent_item_id: if parent == 0 { vec![] } else { vec![parent; 16] },
                name: rel.rsplit('\\').next().unwrap().to_string(),
                directory,
                size,
                mtime_unix_nanos: 1_000,
                content_version: vec![id; 40],
                parent_generation: 5,
            },
        )
    }

    #[derive(Default)]
    struct FakeLocal {
        entries: RefCell<HashMap<PathBuf, LocalStat>>,
        children: RefCell<HashMap<PathBuf, Vec<PathBuf>>>,
        adopted: RefCell<Vec<(PathBuf, Vec<u8>)>>,
        copies: RefCell<u32>,
        unstable: RefCell<bool>,
        located: RefCell<HashMap<Vec<u8>, PathBuf>>,
        discarded: RefCell<Vec<PathBuf>>,
        unbound: RefCell<Vec<PathBuf>>,
        unsearchable: RefCell<bool>,
        unreadable: RefCell<HashSet<PathBuf>>,
    }

    impl FakeLocal {
        fn file(&self, rel: &str, size: u64, placeholder: Option<(u8, bool)>) {
            self.entries.borrow_mut().insert(
                p(rel),
                LocalStat {
                    is_dir: false,
                    is_symlink: false,
                    size,
                    mtime_unix_nanos: 9_999,
                    placeholder: placeholder.map(|(id, in_sync)| PlaceholderInfo {
                        item_id: Some(vec![id; 16]),
                        in_sync,
                        is_dir: false,
                        size,
                        mtime_ticks: 0,
                        dehydrated: false,
                    }),
                },
            );
        }
        fn dir(&self, rel: &str, placeholder: Option<u8>) {
            self.entries.borrow_mut().insert(
                p(rel),
                LocalStat {
                    is_dir: true,
                    is_symlink: false,
                    size: 0,
                    mtime_unix_nanos: 9_999,
                    placeholder: placeholder.map(|id| PlaceholderInfo {
                        item_id: Some(vec![id; 16]),
                        in_sync: true,
                        is_dir: true,
                        size: 0,
                        mtime_ticks: 0,
                        dehydrated: false,
                    }),
                },
            );
        }
    }

    impl Local for FakeLocal {
        fn stat(&self, path: &Path) -> Option<LocalStat> {
            self.entries.borrow().get(path).cloned()
        }
        fn children(&self, directory: &Path) -> Vec<PathBuf> {
            self.children.borrow().get(directory).cloned().unwrap_or_default()
        }
        fn copy_to_ingest(&self, _path: &Path) -> Result<IngestCopy, CopyError> {
            if *self.unstable.borrow() {
                return Err(CopyError::Unstable("busy".into()));
            }
            *self.copies.borrow_mut() += 1;
            Ok(IngestCopy {
                name: format!("copy{}", self.copies.borrow()),
                size: 3,
                sha256: vec![1; 32],
            })
        }
        fn adopt(&self, path: &Path, item_id: &[u8]) -> Result<(), String> {
            self.adopted.borrow_mut().push((path.to_path_buf(), item_id.to_vec()));
            Ok(())
        }
        fn rename(&self, _from: &Path, _to: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn unbind(&self, path: &Path) -> Result<(), String> {
            self.unbound.borrow_mut().push(path.to_path_buf());
            Ok(())
        }
        fn discard(&self, path: &Path) -> std::io::Result<()> {
            self.discarded.borrow_mut().push(path.to_path_buf());
            Ok(())
        }
        fn locate(&self, _root: &Path, item_id: &[u8]) -> Located {
            if *self.unsearchable.borrow() {
                return Located::Unknown;
            }
            match self.located.borrow().get(item_id) {
                Some(path) => Located::Found(path.clone()),
                None => Located::Absent,
            }
        }
        fn confirmed_missing(&self, path: &Path) -> bool {
            !self.unreadable.borrow().contains(path)
        }
    }

    #[derive(Default)]
    struct FakeApi {
        requests: RefCell<Vec<ProviderApplyChangeRequest>>,
        answers: RefCell<Vec<Option<ProviderApplyChangeResponse>>>,
        /// Runs after a request arrives and before its answer, like the user writing meanwhile.
        before_answer: RefCell<Option<Box<dyn Fn()>>>,
    }

    impl FakeApi {
        fn accept(&self, item: ProviderAppliedItem) {
            self.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
                ok: true,
                outcome: ProviderApplyOutcome::Applied as i32,
                item: Some(item),
                ..Default::default()
            }));
        }
        fn accept_delete(&self) {
            self.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
                ok: true,
                outcome: ProviderApplyOutcome::Applied as i32,
                ..Default::default()
            }));
        }
        fn fail(&self, failure: ProviderApplyFailure) {
            self.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
                ok: false,
                failure: failure as i32,
                ..Default::default()
            }));
        }
    }

    impl Api for FakeApi {
        fn apply(
            &self,
            _root: &[u8],
            request: ProviderApplyChangeRequest,
        ) -> Option<ProviderApplyChangeResponse> {
            self.requests.borrow_mut().push(request);
            if let Some(hook) = self.before_answer.borrow_mut().take() {
                hook();
            }
            if self.answers.borrow().is_empty() {
                None
            } else {
                self.answers.borrow_mut().remove(0)
            }
        }
    }

    fn applied(id: u8, parent: u8, name: &str, directory: bool) -> ProviderAppliedItem {
        ProviderAppliedItem {
            item_id: vec![id; 16],
            parent_item_id: if parent == 0 { vec![] } else { vec![parent; 16] },
            name: name.into(),
            entry_kind: if directory {
                EntryKind::Directory as i32
            } else {
                EntryKind::File as i32
            },
            content_version: vec![id; 40],
            size: 3,
            mtime_unix_nanos: 9_999,
            parent_generation: 7,
            ..Default::default()
        }
    }

    fn setup(tag: &str) -> (Authoring, PathBuf) {
        let dir = std::env::temp_dir().join(format!("yl-auth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap(), dir)
    }

    fn signals(paths: &[PathBuf]) -> BTreeSet<PathBuf> {
        paths.iter().cloned().collect()
    }

    #[test]
    fn a_new_file_is_created_under_its_folder_and_becomes_the_daemons_item() {
        let (auth, dir) = setup("create");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("new.txt", 3, None);
        api.accept(applied(7, 0, "new.txt", false));
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Create as i32);
        assert_eq!(request.name.as_deref(), Some("new.txt"));
        assert_eq!(request.parent_item_id, Some(vec![]));
        assert_eq!(request.content.as_ref().unwrap().ingest_name, "copy1");
        assert_eq!(report.applied, 1);
        assert_eq!(local.adopted.borrow()[0], (p("new.txt"), vec![7; 16]));
        assert!(shown.contains_key(&vec![7; 16]));
        assert!(!auth.pending_file().exists(), "the journal outlived the answer");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_folder_is_created_before_what_is_inside_it_and_what_moved_in_whole_is_found() {
        let (auth, dir) = setup("folder");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.file("album\\a.jpg", 3, None);
        local.children.borrow_mut().insert(p("album"), vec![p("album\\a.jpg")]);
        api.accept(applied(8, 0, "album", true));
        api.accept(applied(9, 8, "a.jpg", false));
        let mut shown = ShownItems::new();
        // Only the folder is signalled; its child arrived inside it.
        auth.process(&signals(&[p("album")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].entry_kind, EntryKind::Directory as i32);
        assert_eq!(requests[1].parent_item_id, Some(vec![8; 16]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_edited_placeholder_is_a_modify_based_on_the_version_the_user_saw() {
        let (auth, dir) = setup("edit");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.accept(applied(3, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Modify as i32);
        assert_eq!(request.item_id, vec![3; 16]);
        assert_eq!(request.base_version_hash, vec![3; 40]);
        assert!(request.content.is_some());
        assert!(request.name.is_none() && request.parent_item_id.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A file written to after its bytes were copied and before the daemon answered is not marked
    /// in sync: what the daemon accepted is not what is on the disk.
    #[test]
    fn a_file_written_to_while_the_daemon_answers_is_not_adopted_as_in_sync() {
        let (auth, dir) = setup("raced");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        local.file("a.txt", 3, None);
        api.accept(applied(7, 0, "a.txt", false));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || {
            racing.file("a.txt", 99, None); // written to again
        }));
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &*local, &api);
        assert!(local.adopted.borrow().is_empty(), "adopted a file that changed after the copy");
        assert!(report.retry.contains(&p("a.txt")));
        assert!(shown.contains_key(&vec![7; 16]), "the accepted item must be known");
        // The next look sees the plain file at the item's path and sends its new bytes.
        api.accept(applied(7, 0, "a.txt", false));
        auth.process(&signals(&[p("a.txt")]), &mut shown, &*local, &api);
        assert_eq!(api.requests.borrow()[1].kind, ProviderChangeKind::Modify as i32);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stale edit is answered with the current item and a conflict copy of the user's bytes:
    /// the file must not be bound to the current item as if it held its content.
    #[test]
    fn a_concurrent_answer_replaces_the_file_with_the_current_version_instead_of_adopting_it() {
        let (auth, dir) = setup("concurrent");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: true,
            outcome: ProviderApplyOutcome::Concurrent as i32,
            item: Some(applied(3, 0, "doc.txt", false)),
            ..Default::default()
        }));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(local.adopted.borrow().is_empty(), "the edit was bound to the canonical item");
        assert_eq!(*local.discarded.borrow(), vec![p("doc.txt")]);
        assert!(report.rewalk, "the current version and the conflict copy must be shown");
        assert!(!shown.contains_key(&vec![3; 16]), "a missing path must not read as a delete");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_placeholder_that_is_in_sync_causes_no_request() {
        let (auth, dir) = setup("quiet");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 10, Some((3, true)));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty());
        assert_eq!(report, Report::default());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_rename_and_a_move_are_one_modify_that_names_what_changed() {
        let (auth, dir) = setup("rename");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems =
            [item("old.txt", 3, 0, false, 10), item("sub", 4, 0, true, 0)].into();
        // The file now has a new name and sits in `sub`.
        local.dir("sub", Some(4));
        local.file("sub\\new.txt", 10, Some((3, false)));
        local.entries.borrow_mut().get_mut(&p("sub\\new.txt")).unwrap().mtime_unix_nanos = 1_000;
        local.located.borrow_mut().insert(vec![3; 16], p("sub\\new.txt"));
        api.accept(applied(3, 4, "new.txt", false));
        auth.process(&signals(&[p("old.txt"), p("sub\\new.txt")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 1, "a move was also sent as a delete");
        assert_eq!(requests[0].kind, ProviderChangeKind::Modify as i32);
        assert_eq!(requests[0].parent_item_id, Some(vec![4; 16]));
        assert_eq!(requests[0].name.as_deref(), Some("new.txt"));
        assert_eq!(
            requests[0].parent_generation,
            Some(5),
            "the folder it left, as the user saw it"
        );
        assert!(requests[0].content.is_none(), "a rename must not re-send the bytes");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An editor saves through a temporary file that is renamed over the original: the original's
    /// item is deleted first and the temporary file's item takes its name.
    #[test]
    fn a_file_renamed_over_another_item_deletes_that_item_first() {
        let (auth, dir) = setup("displace");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems =
            [item("doc.txt", 3, 0, false, 10), item("doc.tmp", 4, 0, false, 10)].into();
        // `doc.tmp` (item 4) now sits at `doc.txt`; item 3 is no longer anywhere.
        local.file("doc.txt", 10, Some((4, false)));
        local.entries.borrow_mut().get_mut(&p("doc.txt")).unwrap().mtime_unix_nanos = 1_000;
        api.accept_delete();
        api.accept(applied(4, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt"), p("doc.tmp")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests[0].kind, ProviderChangeKind::Delete as i32);
        assert_eq!(requests[0].item_id, vec![3; 16]);
        assert_eq!(requests[1].kind, ProviderChangeKind::Modify as i32);
        assert_eq!(requests[1].item_id, vec![4; 16]);
        assert_eq!(requests[1].name.as_deref(), Some("doc.txt"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_vanished_item_is_deleted_only_when_it_is_nowhere_in_the_sync_root() {
        let (auth, dir) = setup("delete");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("gone.txt", 3, 0, false, 10)].into();
        api.accept_delete();
        let report = auth.process(&signals(&[p("gone.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Delete as i32);
        assert_eq!(request.base_version_hash, vec![3; 40]);
        assert_eq!(report.applied, 1);
        assert!(shown.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Only a confirmed absence authorizes a delete: a path that cannot be inspected, or a search
    /// of the sync root that could not be completed, is retried.
    #[test]
    fn an_entry_that_cannot_be_inspected_is_never_deleted() {
        let (auth, dir) = setup("uninspectable");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("busy.txt", 3, 0, false, 10)].into();
        local.unreadable.borrow_mut().insert(p("busy.txt"));
        let report = auth.process(&signals(&[p("busy.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty(), "a delete was sent for an unreadable entry");
        assert!(report.retry.contains(&p("busy.txt")));

        local.unreadable.borrow_mut().clear();
        *local.unsearchable.borrow_mut() = true;
        let report = auth.process(&signals(&[p("busy.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty(), "a delete was sent after an incomplete search");
        assert!(report.retry.contains(&p("busy.txt")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_deleted_folder_is_one_recursive_delete() {
        let (auth, dir) = setup("rmdir");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems =
            [item("d", 4, 0, true, 0), item("d\\x", 5, 4, false, 1), item("d\\y", 6, 4, false, 1)]
                .into();
        api.accept_delete();
        auth.process(&signals(&[p("d"), p("d\\x"), p("d\\y")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 1, "the children were deleted one by one as well");
        assert!(requests[0].recursive);
        assert!(shown.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_plain_file_that_replaced_an_item_is_a_content_modify_not_a_collision() {
        let (auth, dir) = setup("replace");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 20, None);
        api.accept(applied(3, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Modify as i32);
        assert_eq!(request.item_id, vec![3; 16]);
        assert!(request.content.is_some());
        assert_eq!(
            local.adopted.borrow()[0].1,
            vec![3; 16],
            "the new file must become the item's placeholder"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_busy_or_silent_daemon_leads_to_a_retry_and_never_to_a_second_operation() {
        let (auth, dir) = setup("retry");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        local.file("b.txt", 3, None);
        let mut shown = ShownItems::new();
        // The daemon does not answer: the operation stays journaled and is the only one sent.
        let report = auth.process(&signals(&[p("a.txt"), p("b.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        assert_eq!(
            api.requests.borrow().len(),
            1,
            "a second operation started over an unanswered one"
        );
        // Asked again, the same operation goes first; the daemon is not ready for it.
        api.fail(ProviderApplyFailure::NotReady);
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        let requests = api.requests.borrow();
        assert_eq!(
            requests[1].operation_seq, requests[0].operation_seq,
            "the repeat must carry the same sequence"
        );
        assert!(shown.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_that_is_still_changing_is_not_sent() {
        let (auth, dir) = setup("unstable");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        *local.unstable.borrow_mut() = true;
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        assert!(api.requests.borrow().is_empty(), "an unstable file was sent");
        assert!(
            !auth.pending_file().exists(),
            "nothing was journaled for a copy that was not made"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// After a crash the journaled request is sent again with the SAME session and sequence, so
    /// the daemon recognizes it instead of applying it twice.
    #[test]
    fn a_crash_between_send_and_answer_replays_the_same_operation() {
        let (auth, dir) = setup("journal");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        let mut shown = ShownItems::new();
        // No answer: the journal stays.
        auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        let first = api.requests.borrow()[0].clone();
        assert!(auth.pending_file().exists());

        // A restart: a new Authoring over the same state directory.
        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.accept(applied(7, 0, "a.txt", false));
        let report = reopened.resume(&mut shown, &local, &api);
        let replay = api.requests.borrow()[1].clone();
        assert_eq!(
            (replay.session_id.clone(), replay.operation_seq, replay.request_id.clone()),
            (first.session_id.clone(), first.operation_seq, first.request_id.clone())
        );
        assert_eq!(replay.content, first.content);
        assert_eq!(replay.name, first.name);
        assert_eq!(report.applied, 1);
        assert_eq!(local.adopted.borrow()[0].1, vec![7; 16]);
        assert!(!reopened.pending_file().exists());

        // Sequence numbers keep increasing across the restart.
        local.file("b.txt", 3, None);
        api.accept(applied(8, 0, "b.txt", false));
        reopened.process(&signals(&[p("b.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow()[2].operation_seq > first.operation_seq);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_symbolic_link_and_a_placeholder_of_an_unseen_item_are_not_sent() {
        let (auth, dir) = setup("skip");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.entries.borrow_mut().insert(
            p("link"),
            LocalStat {
                is_dir: false,
                is_symlink: true,
                size: 0,
                mtime_unix_nanos: 0,
                placeholder: None,
            },
        );
        local.file("remote.txt", 3, Some((9, true)));
        let mut shown = ShownItems::new();
        let report =
            auth.process(&signals(&[p("link"), p("remote.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty());
        assert!(report.rewalk, "an unseen item should lead to a fresh look");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The item an edit was based on is gone: the bytes are kept under the daemon's suggested
    /// name and become the user's own file again (no item identity), to be sent as a new item.
    #[test]
    fn kept_local_bytes_lose_the_old_items_identity_and_are_sent_again_as_new() {
        let (auth, dir) = setup("keep-local");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        local.file("doc (kept).txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: false,
            failure: ProviderApplyFailure::KeepLocal as i32,
            suggested_name: "doc (kept).txt".into(),
            ..Default::default()
        }));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert_eq!(*local.unbound.borrow(), vec![p("doc (kept).txt")]);
        assert!(report.retry.contains(&p("doc (kept).txt")));
        assert!(report.rewalk);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refusal_for_good_is_reported_not_retried() {
        let (auth, dir) = setup("refuse");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        api.fail(ProviderApplyFailure::NotAuthorized);
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.is_empty());
        assert_eq!(report.refused.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
