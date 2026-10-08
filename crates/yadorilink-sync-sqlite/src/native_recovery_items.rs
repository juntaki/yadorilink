//! Recovery items: remote-only versions a rebootstrap would otherwise destroy.
//!
//! A rebootstrap installs a checkpoint that does not contain every head this
//! replica holds. A live head of another author that the target lacks is on disk
//! and equal to the index, so nothing re-asserts it, and the install would remove
//! it; if that author never returns, the group's last copy would be gone. Before
//! the destructive step every such head is therefore saved as a local recovery
//! item: the version record, the bytes when this replica holds them, and why it
//! was saved. Nothing is authored for it, ever.
//!
//! Items live apart from the rebootstrap's transient area, in a store of their
//! own (`<items root>/<group digest>/<item id>/`), and their rows are not touched
//! by the install. Only [`discard_recovery_item`] deletes one. Restoring is a
//! user action that authors one ordinary put with a new dot.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_frontier::AuthorState;
use yadorilink_replica_domain::native_state::{DeltaHash, Dot};

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_authoring::AuthoredPuts;
use crate::native_bootstrap::VerifiedNativeBootstrap;
use crate::native_rebootstrap::BlockedReason;
use crate::native_rebootstrap_recovery::{
    create_dirs_durably, ensure_private_dir_durably, group_dir_name, lstat_no_link, read_regular,
    refuse_synced_location, sha256, sync_dir, write_durable, AreaError, ManifestRemoteOnly,
};

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One row per saved item, written only after its files are durable. Never cleared
        -- by an install; only an explicit discard deletes a row.
        CREATE TABLE IF NOT EXISTS native_recovery_item (
            group_id           TEXT NOT NULL,
            item_id            TEXT NOT NULL,
            kind               TEXT NOT NULL,
            path               TEXT NOT NULL,
            author_device      TEXT NOT NULL,
            author_incarnation BLOB NOT NULL,
            seq                INTEGER NOT NULL,
            provenance         BLOB NOT NULL,
            version_hash       BLOB NOT NULL,
            content            TEXT NOT NULL,
            size               INTEGER NOT NULL,
            content_sha256     BLOB NOT NULL,
            -- JSON array of the hex hashes of the version's blocks this replica holds. Every
            -- block-store sweep treats them as live for as long as the row exists.
            retained_blocks    TEXT NOT NULL,
            source_recovery_id TEXT NOT NULL,
            created_at         INTEGER NOT NULL,
            PRIMARY KEY (group_id, item_id)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// Why a head is saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    /// A head of another author that the target does not contain.
    RemoteOnly,
    /// A head above the cutoff at which the target closes its author: inadmissible
    /// old-incarnation data, and possibly the last copy of its bytes.
    BeyondClosureCutoff,
}

impl ItemKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::RemoteOnly => "remote_only",
            Self::BeyondClosureCutoff => "beyond_closure_cutoff",
        }
    }

    fn parse(text: &str) -> Result<Self, SyncSqliteError> {
        match text {
            "remote_only" => Ok(Self::RemoteOnly),
            "beyond_closure_cutoff" => Ok(Self::BeyondClosureCutoff),
            other => Err(corrupt(format!("unknown recovery item kind {other:?}"))),
        }
    }
}

/// What the item holds of the version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemContent {
    /// The record and the bytes (none for a directory or a symlink).
    Complete,
    /// The record is held, the bytes are not all held. The blocks that are held are kept.
    Unavailable,
    /// Not even the version record is held.
    RecordUnavailable,
}

impl ItemContent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Unavailable => "unavailable",
            Self::RecordUnavailable => "record_unavailable",
        }
    }

    fn parse(text: &str) -> Result<Self, SyncSqliteError> {
        match text {
            "complete" => Ok(Self::Complete),
            "unavailable" => Ok(Self::Unavailable),
            "record_unavailable" => Ok(Self::RecordUnavailable),
            other => Err(corrupt(format!("unknown recovery item content {other:?}"))),
        }
    }
}

fn corrupt(detail: impl Into<String>) -> SyncSqliteError {
    SyncSqliteError::CorruptState(detail.into())
}

/// A head the target lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteOnlyHead {
    pub path: SyncPath,
    pub dot: Dot,
    pub provenance: DeltaHash,
    pub version: VersionHash,
    pub kind: ItemKind,
}

impl RemoteOnlyHead {
    /// Names the item: the same head always has the same id, so saving it twice is one item.
    pub fn item_id(&self, group: &FolderGroupId) -> String {
        let mut bytes = Vec::new();
        for field in [
            group.as_str().as_bytes(),
            self.kind.as_str().as_bytes(),
            self.path.as_str().as_bytes(),
            self.dot.author.device.0.as_bytes(),
            &self.dot.author.incarnation.0,
            &self.dot.seq.get().to_be_bytes(),
            &self.provenance.0,
            &self.version.0,
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        hex::encode(sha256(&bytes))
    }
}

/// A saved item as the user sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryItem {
    pub item_id: String,
    pub kind: ItemKind,
    pub path: SyncPath,
    pub dot: Dot,
    pub provenance: DeltaHash,
    pub version: VersionHash,
    pub content: ItemContent,
    pub size: u64,
    /// Hex hashes of the version's blocks this replica holds, kept alive by the item.
    pub retained_blocks: Vec<String>,
    pub source_recovery_id: String,
}

// --- what to save ----------------------------------------------------------------------------------

/// The live heads of `group` that `target` lacks, by head identity `(path, dot, provenance)`.
///
/// A head the target holds under an identical identity is not saved again. Comparing an
/// author's sequence with the target's entry proves nothing about which chain a head sits on,
/// so a position never excuses a head; it only decides the reason: a head above the cutoff at
/// which the target closes its author is `BeyondClosureCutoff`, any other is `RemoteOnly`.
/// `replayed` holds the deltas of this device's own uncovered intent; their heads are replayed
/// as new deltas, not saved.
pub fn plan_remote_only(
    conn: &Connection,
    group: &FolderGroupId,
    target: &VerifiedNativeBootstrap,
    replayed: &BTreeSet<DeltaHash>,
) -> Result<Vec<RemoteOnlyHead>, SyncSqliteError> {
    let local = crate::native_store::load_state(conn, group)?;
    let mut out = Vec::new();
    for (path, heads) in &local.heads {
        for (dot, payload) in heads {
            if replayed.contains(&payload.provenance) {
                continue;
            }
            let contained = target
                .state()
                .heads
                .get(path)
                .and_then(|theirs| theirs.get(dot))
                .is_some_and(|theirs| theirs.provenance == payload.provenance);
            if contained {
                continue;
            }
            let beyond = match target.author_state(&dot.author) {
                Some(AuthorState::Closed { frontier }) => {
                    dot.seq.get() > frontier.map_or(0, |entry| entry.seq.get())
                }
                _ => false,
            };
            out.push(RemoteOnlyHead {
                path: path.clone(),
                dot: dot.clone(),
                provenance: payload.provenance,
                version: payload.version,
                kind: if beyond { ItemKind::BeyondClosureCutoff } else { ItemKind::RemoteOnly },
            });
        }
    }
    Ok(out)
}

// --- the store -------------------------------------------------------------------------------------

const RECORD_FILE: &str = "record.bin";
const CONTENT_FILE: &str = "content";

fn is_item_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn group_dir(items_root: &Path, group: &FolderGroupId) -> PathBuf {
    items_root.join(group_dir_name(group))
}

fn item_dir(items_root: &Path, group: &FolderGroupId, item_id: &str) -> PathBuf {
    group_dir(items_root, group).join(item_id)
}

fn remove_dir(dir: &Path) -> Result<(), AreaError> {
    if lstat_no_link(dir)?.is_some() {
        fs::remove_dir_all(dir)?;
        if let Some(parent) = dir.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

/// What one item holds, as it is written.
pub(crate) struct ItemBody {
    pub content: ItemContent,
    pub record: Option<FileVersion>,
    pub bytes: Vec<u8>,
    /// Hex hashes of the blocks of `record` that are held locally.
    pub retained_blocks: Vec<String>,
}

/// Makes the group's directory of the store, refusing a location inside a synced root.
pub(crate) fn open_store(
    items_root: &Path,
    group: &FolderGroupId,
    sync_roots: &[PathBuf],
) -> Result<(), AreaError> {
    if let Some(parent) = items_root.parent() {
        create_dirs_durably(parent)?;
    }
    ensure_private_dir_durably(items_root)?;
    refuse_synced_location(items_root, sync_roots)?;
    ensure_private_dir_durably(&group_dir(items_root, group))
}

/// Removes what a crash left in the group's store that no row names: files written for an item
/// whose row never landed. A registered item is never touched.
pub(crate) fn sweep_unregistered(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
) -> Result<(), SyncSqliteError> {
    let dir = group_dir(items_root, group);
    let area = |e: AreaError| corrupt(e.to_string());
    if lstat_no_link(&dir).map_err(area)?.is_none() {
        return Ok(());
    }
    let registered: BTreeSet<String> = registered_ids(conn, group)?;
    for entry in fs::read_dir(&dir).map_err(|e| corrupt(e.to_string()))? {
        let entry = entry.map_err(|e| corrupt(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !registered.contains(&name) {
            let path = entry.path();
            if path.is_dir() {
                remove_dir(&path).map_err(area)?;
            }
        }
    }
    Ok(())
}

/// The blocks every item of every group keeps alive: the one root source a block-store sweep
/// adds to the live set. Present exactly while the item's row is.
pub(crate) fn retained_block_hashes_all_groups(
    conn: &Connection,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT retained_blocks FROM native_recovery_item")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = BTreeSet::new();
    for row in rows {
        let blocks: Vec<String> = serde_json::from_str(&row?)
            .map_err(|e| corrupt(format!("a recovery item's retained blocks: {e}")))?;
        out.extend(blocks);
    }
    Ok(out)
}

fn registered_ids(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT item_id FROM native_recovery_item WHERE group_id = ?1")?;
    let ids = stmt.query_map([group.as_str()], |row| row.get::<_, String>(0))?;
    Ok(ids.collect::<Result<_, _>>()?)
}

/// Writes the files of one item, each durable, and the chain of names to them.
pub(crate) fn write_item_files(
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
    body: &ItemBody,
) -> Result<(), AreaError> {
    let dir = item_dir(items_root, group, item_id);
    remove_dir(&dir)?;
    ensure_private_dir_durably(&dir)?;
    if let Some(record) = &body.record {
        write_durable(&dir, RECORD_FILE, &record.canonical_encoding())?;
    }
    if body.content == ItemContent::Complete {
        write_durable(&dir, CONTENT_FILE, &body.bytes)?;
    }
    let mut level = Some(dir.as_path());
    for _ in 0..3 {
        let Some(path) = level else { break };
        sync_dir(path)?;
        level = path.parent();
    }
    Ok(())
}

/// Registers an item whose files are durable. Replacing a row is how an item whose bytes were
/// missing before becomes complete; it never removes one.
pub(crate) fn register_item(
    conn: &Connection,
    group: &FolderGroupId,
    head: &RemoteOnlyHead,
    item_id: &str,
    body: &ItemBody,
    source_recovery_id: &str,
    now: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR REPLACE INTO native_recovery_item \
         (group_id, item_id, kind, path, author_device, author_incarnation, seq, provenance, \
          version_hash, content, size, content_sha256, retained_blocks, source_recovery_id, \
          created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            group.as_str(),
            item_id,
            head.kind.as_str(),
            head.path.as_str(),
            head.dot.author.device.0,
            &head.dot.author.incarnation.0[..],
            head.dot.seq.get() as i64,
            &head.provenance.0[..],
            &head.version.0[..],
            body.content.as_str(),
            body.bytes.len() as i64,
            &sha256(&body.bytes)[..],
            serde_json::to_string(&body.retained_blocks).map_err(|e| corrupt(e.to_string()))?,
            source_recovery_id,
            now,
        ],
    )?;
    Ok(())
}

/// The manifest's statement of a saved item.
pub(crate) fn manifest_entry(
    group: &FolderGroupId,
    head: &RemoteOnlyHead,
    body: &ItemBody,
) -> ManifestRemoteOnly {
    ManifestRemoteOnly {
        item_id: head.item_id(group),
        kind: head.kind.as_str().into(),
        path: head.path.as_str().to_owned(),
        author: head.dot.author.clone(),
        seq: head.dot.seq.get(),
        provenance: head.provenance,
        version: head.version,
        content: body.content.as_str().into(),
        size: body.bytes.len() as u64,
        content_sha256: sha256(&body.bytes),
    }
}

/// Whether the item `entry` names is a registered row and its files read back as written.
pub(crate) fn item_is_durable(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    entry: &ManifestRemoteOnly,
) -> Result<bool, SyncSqliteError> {
    let registered = conn
        .query_row(
            "SELECT kind, path, author_device, author_incarnation, seq, provenance, version_hash, \
                    content, size, content_sha256 \
             FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
            (group.as_str(), &entry.item_id),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((kind, path, device, incarnation, seq, provenance, version, content, size, digest)) =
        registered
    else {
        return Ok(false);
    };
    let same = kind == entry.kind
        && path == entry.path
        && device == entry.author.device.0
        && incarnation == entry.author.incarnation.0
        && seq as u64 == entry.seq
        && provenance == entry.provenance.0
        && version == entry.version.0
        && content == entry.content
        && size as u64 == entry.size
        && digest == entry.content_sha256;
    if !same {
        return Ok(false);
    }
    let dir = item_dir(items_root, group, &entry.item_id);
    let content = ItemContent::parse(&entry.content)?;
    Ok(read_item(&dir, content, &entry.version, &entry.content_sha256).is_ok())
}

/// Reads an item's record and bytes back and checks both against what was saved.
fn read_item(
    dir: &Path,
    content: ItemContent,
    version: &VersionHash,
    content_sha256: &[u8; 32],
) -> Result<(Option<FileVersion>, Vec<u8>), AreaError> {
    let record = if content == ItemContent::RecordUnavailable {
        None
    } else {
        let bytes = read_regular(&dir.join(RECORD_FILE))?;
        let record = FileVersion::from_canonical_encoding(&bytes).map_err(|e| {
            AreaError::Inconsistent(format!("an item record does not decode: {e:?}"))
        })?;
        if record.version_hash != *version || record.verify_hash().is_err() {
            return Err(AreaError::Inconsistent(
                "an item record does not hash to its version".into(),
            ));
        }
        Some(record)
    };
    let bytes = if content == ItemContent::Complete {
        let bytes = read_regular(&dir.join(CONTENT_FILE))?;
        if sha256(&bytes) != *content_sha256 {
            return Err(AreaError::Inconsistent("an item's bytes are not the ones saved".into()));
        }
        bytes
    } else {
        Vec::new()
    };
    Ok((record, bytes))
}

/// Every named item is durable, or the first that is not.
pub(crate) fn verify_items(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    entries: &[ManifestRemoteOnly],
) -> Result<(), BlockedReason> {
    for entry in entries {
        let durable = item_is_durable(conn, items_root, group, entry).map_err(|e| {
            BlockedReason::PreservationFailed(crate::native_rebootstrap::PreservationFailure::Io {
                detail: e.to_string(),
            })
        })?;
        if !durable {
            return Err(BlockedReason::RemoteOnlyUnpreserved { item: entry.item_id.clone() });
        }
    }
    Ok(())
}

// --- listing, discarding, restoring --------------------------------------------------------------

type Row =
    (String, String, String, String, Vec<u8>, i64, Vec<u8>, Vec<u8>, String, i64, String, String);

pub fn list_recovery_items(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Vec<RecoveryItem>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT item_id, kind, path, author_device, author_incarnation, seq, provenance, \
                version_hash, content, size, source_recovery_id, retained_blocks \
         FROM native_recovery_item WHERE group_id = ?1 ORDER BY created_at, item_id",
    )?;
    let rows = stmt.query_map([group.as_str()], |row| {
        Ok::<Row, rusqlite::Error>((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
        ))
    })?;
    let hash = |bytes: Vec<u8>| -> Result<[u8; 32], SyncSqliteError> {
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| corrupt("a recovery item hash is not 32 bytes"))
    };
    let mut out = Vec::new();
    for row in rows {
        let (
            item_id,
            kind,
            path,
            device,
            incarnation,
            seq,
            provenance,
            version,
            content,
            size,
            source,
            retained,
        ) = row?;
        let incarnation = <[u8; 16]>::try_from(incarnation.as_slice())
            .map_err(|_| corrupt("a recovery item incarnation is not 16 bytes"))?;
        out.push(RecoveryItem {
            item_id,
            kind: ItemKind::parse(&kind)?,
            path: SyncPath(path),
            dot: Dot {
                author: AuthorId {
                    device: DeviceId(device),
                    incarnation: IncarnationId(incarnation),
                },
                seq: AuthorSeq(seq as u64),
            },
            provenance: DeltaHash(hash(provenance)?),
            version: VersionHash(hash(version)?),
            content: ItemContent::parse(&content)?,
            size: size as u64,
            retained_blocks: serde_json::from_str(&retained)
                .map_err(|e| corrupt(format!("a recovery item's retained blocks: {e}")))?,
            source_recovery_id: source,
        });
    }
    Ok(out)
}

fn find_item(
    conn: &Connection,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<Option<(RecoveryItem, [u8; 32])>, SyncSqliteError> {
    if !is_item_id(item_id) {
        return Ok(None);
    }
    let digest: Option<Vec<u8>> = conn
        .query_row(
            "SELECT content_sha256 FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
            (group.as_str(), item_id),
            |row| row.get(0),
        )
        .optional()?;
    let Some(digest) = digest else { return Ok(None) };
    let digest = <[u8; 32]>::try_from(digest.as_slice())
        .map_err(|_| corrupt("a recovery item digest is not 32 bytes"))?;
    Ok(list_recovery_items(conn, group)?
        .into_iter()
        .find(|item| item.item_id == item_id)
        .map(|item| (item, digest)))
}

/// The bytes an item holds, read back and checked against the digest it was saved under.
pub fn read_item_content(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<Vec<u8>, SyncSqliteError> {
    let (item, digest) = find_item(conn, group, item_id)?
        .ok_or_else(|| SyncSqliteError::NotFound("no such recovery item".into()))?;
    read_item(&item_dir(items_root, group, item_id), item.content, &item.version, &digest)
        .map(|(_, bytes)| bytes)
        .map_err(|e| corrupt(e.to_string()))
}

/// The only operation that deletes an item: its row, then its files. Refused while the group is
/// frozen by a rebootstrap. Returns whether an item was found.
pub fn discard_recovery_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<bool, SyncSqliteError> {
    if crate::native_rebootstrap::group_frozen(conn, group.as_str())? {
        return Err(SyncSqliteError::GroupFrozen { group_id: group.as_str().to_owned() });
    }
    if !is_item_id(item_id) {
        return Ok(false);
    }
    let removed = conn.execute(
        "DELETE FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
        (group.as_str(), item_id),
    )?;
    remove_dir(&item_dir(items_root, group, item_id)).map_err(|e| corrupt(e.to_string()))?;
    Ok(removed > 0)
}

/// Why an unavailable item could not be completed.
#[derive(Debug)]
pub enum CompleteError {
    NotFound,
    /// The item is not `Unavailable`: there is nothing to complete.
    NotUnavailable,
    /// The bytes are not the item's version.
    WrongBytes,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for CompleteError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// The items of `group` that hold a version record but not all of its bytes, with the record.
pub fn unavailable_items(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
) -> Result<Vec<(RecoveryItem, FileVersion)>, SyncSqliteError> {
    let mut out = Vec::new();
    for item in list_recovery_items(conn, group)? {
        if item.content != ItemContent::Unavailable {
            continue;
        }
        let dir = item_dir(items_root, group, &item.item_id);
        let bytes = read_regular(&dir.join(RECORD_FILE)).map_err(|e| corrupt(e.to_string()))?;
        let record = FileVersion::from_canonical_encoding(&bytes)
            .map_err(|e| corrupt(format!("an item record does not decode: {e:?}")))?;
        if record.version_hash != item.version || record.verify_hash().is_err() {
            return Err(corrupt("an item record does not hash to its version"));
        }
        out.push((item, record));
    }
    Ok(out)
}

/// Makes an `Unavailable` item `Complete` once its version's bytes are held: the bytes are
/// checked block by block against the record, written durably beside it, and only then does the
/// row say `complete` and keep every block alive. A crash between the two leaves the item
/// unavailable with a stray content file that the next completion overwrites.
pub fn complete_unavailable_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
    bytes: &[u8],
) -> Result<(), CompleteError> {
    let (item, record) = unavailable_items(conn, items_root, group)?
        .into_iter()
        .find(|(item, _)| item.item_id == item_id)
        .ok_or_else(|| match find_item(conn, group, item_id) {
            Ok(Some(_)) => CompleteError::NotUnavailable,
            Ok(None) => CompleteError::NotFound,
            Err(error) => CompleteError::Store(error),
        })?;
    let mut offset = 0usize;
    let mut fits = bytes.len() as u64 == record.size;
    for block in &record.blocks {
        let end = offset + block.size as usize;
        fits =
            fits && bytes.get(offset..end).is_some_and(|part| sha256(part)[..] == block.hash.0[..]);
        offset = end;
    }
    if !fits {
        return Err(CompleteError::WrongBytes);
    }
    let dir = item_dir(items_root, group, &item.item_id);
    write_durable(&dir, CONTENT_FILE, bytes).map_err(|e| corrupt(e.to_string()))?;
    sync_dir(&dir).map_err(|e| corrupt(e.to_string()))?;
    let retained = serde_json::to_string(&hex_block_hashes(&record))
        .map_err(|e| CompleteError::Store(corrupt(e.to_string())))?;
    conn.execute(
        "UPDATE native_recovery_item \
         SET content = 'complete', size = ?3, content_sha256 = ?4, retained_blocks = ?5 \
         WHERE group_id = ?1 AND item_id = ?2 AND content = 'unavailable'",
        rusqlite::params![
            group.as_str(),
            item_id,
            bytes.len() as i64,
            &sha256(bytes)[..],
            retained
        ],
    )
    .map_err(SyncSqliteError::from)?;
    Ok(())
}

fn hex_block_hashes(record: &FileVersion) -> Vec<String> {
    record.blocks.iter().map(|block| hex::encode(&block.hash.0)).collect()
}

/// Every group that has a recovery item or an own unit a rebootstrap did not replay, whether or
/// not the group is still linked here: the data outlives the group.
pub fn groups_with_preserved_data(
    conn: &Connection,
) -> Result<BTreeSet<FolderGroupId>, SyncSqliteError> {
    let mut groups = BTreeSet::new();
    for table in ["native_recovery_item", "native_unreplayed_unit"] {
        let mut stmt = conn.prepare(&format!("SELECT DISTINCT group_id FROM {table}"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            groups.insert(FolderGroupId(row?));
        }
    }
    Ok(groups)
}

/// Takes a restored version's bytes into the caller's block store.
pub type ImportBytes<'a> = dyn FnMut(&FileVersion, &[u8]) -> Result<(), String> + 'a;

#[derive(Debug)]
pub enum RestoreError {
    NotFound,
    /// The item holds no version record.
    RecordUnavailable,
    /// The item holds the record but not the bytes.
    ContentUnavailable,
    /// What the store holds is not what was saved.
    Corrupt(String),
    /// The caller could not take the bytes into its block store.
    Import(String),
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for RestoreError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// Authors one ordinary put of the item's version at its original path, as `author`, after
/// `import` has taken the bytes into the caller's block store. A new dot is minted; the
/// original dot and provenance are not restored, and the put follows the ordinary rules for a
/// path that is occupied or contested. The item stays. Refused while the group is frozen.
pub fn restore_recovery_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
    author: &LocalAuthor<'_>,
    import: &mut ImportBytes<'_>,
) -> Result<AuthoredPuts, RestoreError> {
    if crate::native_rebootstrap::group_frozen(conn, group.as_str())? {
        return Err(RestoreError::Store(SyncSqliteError::GroupFrozen {
            group_id: group.as_str().to_owned(),
        }));
    }
    let (item, digest) = find_item(conn, group, item_id)?.ok_or(RestoreError::NotFound)?;
    match item.content {
        ItemContent::RecordUnavailable => return Err(RestoreError::RecordUnavailable),
        ItemContent::Unavailable => return Err(RestoreError::ContentUnavailable),
        ItemContent::Complete => {}
    }
    let (record, bytes) =
        read_item(&item_dir(items_root, group, item_id), item.content, &item.version, &digest)
            .map_err(|e| RestoreError::Corrupt(e.to_string()))?;
    let record =
        record.ok_or_else(|| RestoreError::Corrupt("a complete item has no record".into()))?;
    if record.meta.record_kind == RecordKind::File {
        import(&record, &bytes).map_err(RestoreError::Import)?;
    }
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(SyncSqliteError::from)?;
    crate::dag_store::put_file_version(&tx, group.as_str(), &record)?;
    let op = Op::Put { path: item.path.clone(), version: item.version };
    let authored = crate::native_authoring::author_op(&tx, group, author, &op, &item.path)?;
    tx.commit().map_err(SyncSqliteError::from)?;
    Ok(authored)
}
