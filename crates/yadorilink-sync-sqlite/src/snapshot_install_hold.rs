//! `SnapshotInstallHoldRepository` owns `snapshot_install_holds`: the paths
//! a HistoryBase snapshot install replaced in the index but whose disk it
//! has not reconciled yet.
//!
//! An install replaces a group's rows in one transaction and writes no
//! file, because a filesystem cannot join a database transaction. So for
//! every path whose installed row describes something other than what the
//! replaced row described, the object on disk still belongs to the replaced
//! row -- its full bytes, its placeholder, or an edit of it that local
//! capture never saw -- while the index already names the installed
//! version. That object is not a local edit of the installed version: its
//! base is the replaced row, and authoring it on top of the installed
//! version would publish old content, or an edit of old content, as the
//! newest write to every peer. A hold is the durable record of that state,
//! written in the install's own transaction so no crash can separate the
//! two.
//!
//! While a path is held:
//!
//! - local capture authors nothing for it -- no edit, no offline deletion
//!   (local capture consults [`held_paths`], and every local-authoring
//!   entry point in [`crate::file_index`] refuses a held path in its own
//!   transaction with [`SyncSqliteError::PathAwaitingSnapshotInstallReconciliation`]);
//! - the projection scheduler does not claim it
//!   ([`crate::projection_obligations::claim_runnable_obligations`]), and no
//!   materializer writes it, since writing the installed version would
//!   overwrite whatever is there without looking at it.
//!
//! The reconciliation pass is the one writer of a held path. It classifies
//! the object on disk against the [`PriorPlacement`] recorded here:
//!
//! - nothing there, or exactly what the replaced row placed (the same
//!   bytes, mode and xattrs; the same symlink target; or that row's own
//!   untouched placeholder) is **stale** and is removed;
//! - an untouched placeholder of the installed row is already the
//!   installed projection and is kept;
//! - anything else is **ambiguous**: an edit of the replaced version made
//!   before the install and never captured, or one made after it on top of
//!   the stale bytes. Either way its base is the replaced version, and the
//!   two cannot be told apart, so it is preserved rather than authored: it
//!   is moved aside to a conflict-copy name, which local capture then
//!   captures as a new file.
//!
//! Then it places the installed row's projection and releases the hold
//! with [`release_in_tx`]. A change observed at the path after the release
//! is an ordinary local edit of the installed version: the only thing on
//! disk at that point is what the reconciliation itself placed.

use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
use yadorilink_replica_domain::file::RecordKind;
pub use yadorilink_replica_domain::session_state::{PriorPlacement, SnapshotInstallHold};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

pub(crate) fn init_snapshot_install_hold_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS snapshot_install_holds (
            group_id                    TEXT NOT NULL,
            path                        TEXT NOT NULL,
            -- NULL: the replaced index had no live row here, so nothing
            -- this device placed can be on disk under this name.
            prior_record_kind           TEXT,
            prior_materialization_state TEXT,
            prior_size                  INTEGER,
            prior_blocks_json           TEXT,
            prior_unix_mode             INTEGER,
            prior_xattrs_json           TEXT,
            prior_symlink_target        BLOB,
            held_at_unix_nanos          INTEGER NOT NULL,
            -- Moves every time an install holds the path again, so a
            -- reconciliation that read an earlier install's row cannot
            -- release the hold a later one renewed.
            generation                  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path)
        );",
    )?;
    Ok(())
}

/// A boolean SQL expression, true when `{path}` of `{group}` is held. The
/// caller replaces `{group}` and `{path}` with its own column references.
const HELD_SQL: &str = "EXISTS (SELECT 1 FROM snapshot_install_holds h \
     WHERE h.group_id = {group} AND h.path = {path})";

pub(crate) fn held_sql(group: &str, path: &str) -> String {
    HELD_SQL.replace("{group}", group).replace("{path}", path)
}

/// The replaced row's columns, as the install read them before replacing
/// it. Strings are the rows' own encodings, compared and stored as-is.
pub(crate) struct ReplacedRow {
    pub(crate) record_kind: String,
    pub(crate) materialization_state: String,
    pub(crate) size: i64,
    pub(crate) mtime_unix_nanos: i64,
    pub(crate) blocks_json: String,
    pub(crate) unix_mode: i64,
    pub(crate) xattrs_json: String,
    pub(crate) symlink_target: Option<Vec<u8>>,
    pub(crate) placeholder_dev: Option<i64>,
    pub(crate) placeholder_ino: Option<i64>,
    pub(crate) placeholder_provider_kind: Option<String>,
}

impl ReplacedRow {
    /// Whether `self` and `other` describe the same object on disk: the same
    /// content, the same metadata a projection writes, the same kind.
    fn places_the_same_object_as(&self, other: &ReplacedRow) -> bool {
        self.record_kind == other.record_kind
            && self.size == other.size
            && self.mtime_unix_nanos == other.mtime_unix_nanos
            && self.blocks_json == other.blocks_json
            && self.unix_mode == other.unix_mode
            && self.xattrs_json == other.xattrs_json
            && self.symlink_target == other.symlink_target
    }
}

/// Every live current row of `group_id`, keyed by path.
pub(crate) fn live_rows(
    conn: &Connection,
    group_id: &str,
) -> Result<HashMap<String, ReplacedRow>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, record_kind, materialization_state, size, mtime_unix_nanos, blocks_json, \
                unix_mode, xattrs_json, symlink_target, placeholder_dev, placeholder_ino, \
                placeholder_provider_kind \
         FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            ReplacedRow {
                record_kind: r.get(1)?,
                materialization_state: r.get(2)?,
                size: r.get(3)?,
                mtime_unix_nanos: r.get(4)?,
                blocks_json: r.get(5)?,
                unix_mode: r.get(6)?,
                xattrs_json: r.get(7)?,
                symlink_target: r.get(8)?,
                placeholder_dev: r.get(9)?,
                placeholder_ino: r.get(10)?,
                placeholder_provider_kind: r.get(11)?,
            },
        ))
    })?;
    rows.collect::<Result<HashMap<_, _>, _>>().map_err(Into::into)
}

/// Moves every live File or Symlink row whose path the installed rows
/// need as a directory -- because a live row lives below it -- to the
/// conflict-copy name the namespace projection relocates it to, and
/// returns each move as `(from, to)`. Runs in the install's own
/// transaction, after the rows are written and before
/// [`settle_replaced_rows`] decides the holds, so the holds are decided on
/// the rows the disk has to end up matching.
///
/// A filesystem cannot hold `a` as a file while `a/x` exists, and a base
/// can carry both: its rows are per path, and nothing in them says which
/// names are directories. Left as they are, reconciliation would place
/// `a`'s placeholder and then fail `a/x` on `ENOTDIR` forever. The
/// projection (`yadorilink_replica_engine::namespace`) is what every
/// device agrees on instead: `a` is a directory, and its File or Symlink
/// is relocated to its deterministic copy name beside it. That is what
/// this writes into the index, exactly as the reconcile pass leaves the
/// index when it relocates a leaf (the copy name's row holds the entry,
/// under the change that authored it; no row claims the leaf at `a`).
/// Nothing is authored: relocation is a projection, not a fact.
///
/// The copy name is the one the live projection gives the same head (see
/// [`row_head`]), so a device that installed this base and one that
/// converged to it live place the file under the same name.
pub(crate) fn relocate_rows_displaced_by_descendants(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<(String, String)>, SyncSqliteError> {
    use std::collections::BTreeSet;

    let live = live_row_kinds(conn, group_id)?;
    let has_live_descendant =
        |path: &str| live.range(format!("{path}/")..format!("{path}0")).next().is_some();
    let levels: BTreeSet<String> = live
        .iter()
        .filter(|(path, kind)| **kind != RecordKind::Directory && has_live_descendant(path))
        .map(|(path, _)| parent_of(path).to_owned())
        .collect();

    let mut moves = Vec::new();
    for parent in levels {
        moves.extend(level_relocations(conn, group_id, &live, &parent, &BTreeSet::new())?);
    }
    move_current_rows(conn, group_id, &moves)?;
    Ok(moves)
}

/// Moves the live File or Symlink row at `path` to the copy name the
/// namespace projection gives it when a directory holds its name, holds
/// the copy name for the reconciliation pass to place, records the
/// directory at `path` as retained for its untracked content (`removable`:
/// the identity of a directory this device made there, which may go once
/// it is empty; `None` keeps it for good), and releases `path`'s hold --
/// all only while that hold is still at `generation`. Returns the copy
/// name, or `None` when the hold moved (an install renewed it) or `path`
/// has no live File or Symlink row to move; nothing is written then.
///
/// One transaction, because nothing brings `path` back once its hold is
/// released: a directory left unrecorded there would read to capture as
/// one the user made, and be authored over the installed entry.
///
/// For the reconciliation pass, when a directory it may not remove (the
/// user's, or one holding content this device does not replicate) sits
/// where an installed entry belongs: the live projection keeps the entry at
/// its copy name beside that directory, and so does this. Left at `path`,
/// the row would name a file where the disk has a directory, which the
/// offline-delete scan reads as that file's deletion.
pub(crate) fn relocate_held_entry_beside_directory_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    generation: i64,
    removable: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
    now_unix_nanos: i64,
) -> Result<Option<String>, SyncSqliteError> {
    let held_at: Option<i64> = conn
        .query_row(
            "SELECT generation FROM snapshot_install_holds WHERE group_id = ?1 AND path = ?2",
            params![group_id, path],
            |r| r.get(0),
        )
        .optional()?;
    if held_at != Some(generation) {
        return Ok(None);
    }
    let live = live_row_kinds(conn, group_id)?;
    if !matches!(live.get(path), Some(RecordKind::File | RecordKind::Symlink)) {
        return Ok(None);
    }
    let occupied = std::collections::BTreeSet::from([path.to_owned()]);
    let Some(to) = level_relocations(conn, group_id, &live, parent_of(path), &occupied)?
        .into_iter()
        .find(|(from, _)| from == path)
        .map(|(_, to)| to)
    else {
        return Ok(None);
    };
    move_current_rows(conn, group_id, &[(path.to_owned(), to.clone())])?;
    hold_in_tx(conn, group_id, &to, None, now_unix_nanos)?;
    crate::structural_origin::record_retained_directory(
        conn,
        group_id,
        path,
        crate::structural_origin::RETAINED_UNTRACKED_CONTENT,
        removable,
        now_unix_nanos,
    )?;
    conn.execute(
        "DELETE FROM snapshot_install_holds WHERE group_id = ?1 AND path = ?2 AND generation = ?3",
        params![group_id, path, generation],
    )?;
    Ok(Some(to))
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Every live current row of `group_id`, with its kind, in path order.
fn live_row_kinds(
    conn: &Connection,
    group_id: &str,
) -> Result<std::collections::BTreeMap<String, RecordKind>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, record_kind FROM files \
         WHERE group_id = ?1 AND state = 'current' AND deleted = 0",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((r.get::<_, String>(0)?, RecordKind::from_db_str(&r.get::<_, String>(1)?)))
    })?;
    rows.collect::<Result<_, _>>().map_err(Into::into)
}

/// The relocations the namespace projection makes at the level below
/// `parent`, from the live rows (`live`), with the names in `occupied`
/// held by directories besides the ones the rows need.
fn level_relocations(
    conn: &Connection,
    group_id: &str,
    live: &std::collections::BTreeMap<String, RecordKind>,
    parent: &str,
    occupied: &std::collections::BTreeSet<String>,
) -> Result<Vec<(String, String)>, SyncSqliteError> {
    use std::collections::{BTreeMap, BTreeSet};
    use yadorilink_replica_engine::conflict::PathHead;
    use yadorilink_replica_engine::namespace::{project_level, PhysicalNode, Placement};

    let lower = if parent.is_empty() { String::new() } else { format!("{parent}/") };
    let in_level = live
        .range::<str, _>((std::ops::Bound::Excluded(lower.as_str()), std::ops::Bound::Unbounded));
    let mut children: BTreeMap<String, Vec<PathHead>> = BTreeMap::new();
    let mut with_live_descendant: BTreeSet<String> = occupied.clone();
    let mut kinds: HashMap<[u8; 32], RecordKind> = HashMap::new();
    for (path, _) in in_level {
        let Some(rest) = path.strip_prefix(lower.as_str()) else { break };
        match rest.split_once('/') {
            // Deeper: it only makes its level entry a directory.
            Some((child, _)) => {
                with_live_descendant.insert(format!("{lower}{child}"));
            }
            None => {
                let row = crate::store::read_canonical_current_row(conn, group_id, path)?
                    .ok_or_else(|| {
                        SyncSqliteError::CorruptState(format!(
                            "the live row of {path} vanished inside its transaction"
                        ))
                    })?;
                kinds.insert(row.version_hash().0, row.snapshot.record_kind);
                children.insert(path.clone(), vec![row_head(conn, group_id, path, &row)?]);
            }
        }
    }
    let level =
        project_level(&children, &with_live_descendant, |version| kinds.get(version).copied())
            .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?;
    let mut moves = Vec::new();
    for (name, node) in level.nodes() {
        if let PhysicalNode::Entry(entry) = node {
            if entry.placement == Placement::Relocated {
                moves.push((entry.source.clone(), name.clone()));
            }
        }
    }
    Ok(moves)
}

/// The head a live row at `path` stands for, as the live path frontier
/// would carry it -- so its copy name is the one the live projection gives
/// it: the installed base's winning head of `path` when that head names the
/// row's version (its change, Lamport and naming device), with no mtime
/// stamp, since the frontier carries none. A base carries one current row
/// per path, so the path has no competing head to place here.
///
/// A row the base's heads do not account for (a base without a head
/// summary for it) falls back to what the row itself records: its
/// authoring change and origin device.
fn row_head(
    conn: &Connection,
    group_id: &str,
    path: &str,
    row: &crate::store::CanonicalCurrentRow,
) -> Result<yadorilink_replica_engine::conflict::PathHead, SyncSqliteError> {
    use yadorilink_replica_engine::conflict::{
        resolve_path_heads, PathHead, PathHeadContent, PathResolution,
    };
    let version_hash = row.version_hash().0;
    let mut stmt = conn.prepare(
        "SELECT change_hash, device_id, lamport, version_hash, naming_device_id \
         FROM history_base_path_heads WHERE group_id = ?1 AND path = ?2",
    )?;
    let heads = stmt
        .query_map(params![group_id, path], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .map(|row| {
            let (change_hash, device_id, lamport, version, naming_device_id) = row?;
            let hash = |bytes: Vec<u8>, what: &str| {
                <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    SyncSqliteError::CorruptState(format!(
                        "installed base head of {path:?} carries a {what} that is not 32 bytes"
                    ))
                })
            };
            Ok(PathHead {
                change_hash: hash(change_hash, "change hash")?,
                lamport: u64::try_from(lamport).unwrap_or(0),
                device_id,
                naming_device_id,
                content: Some(PathHeadContent {
                    version_hash: hash(version, "version hash")?,
                    mtime_unix_nanos: 0,
                }),
            })
        })
        .collect::<Result<Vec<_>, SyncSqliteError>>()?;
    if let PathResolution::Present { winner, .. } = resolve_path_heads(path, &heads) {
        let head = &heads[winner];
        if head.content.as_ref().is_some_and(|content| content.version_hash == version_hash) {
            return Ok(head.clone());
        }
    }
    let device = row.origin_device_id.clone().unwrap_or_default();
    Ok(PathHead {
        change_hash: row.authoring_change_hash.map_or([0; 32], |hash| hash.0),
        lamport: 0,
        device_id: device.clone(),
        naming_device_id: device,
        content: Some(PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
    })
}

/// Moves each `(from, to)` current row to `to`. The copy name has no live
/// row (the projection gave it out), but it may have history, a tombstone
/// included: the moved row becomes its current row, after all of it.
fn move_current_rows(
    conn: &Connection,
    group_id: &str,
    moves: &[(String, String)],
) -> Result<(), SyncSqliteError> {
    for (from, to) in moves {
        conn.execute(
            "UPDATE files SET state = 'superseded' \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            params![group_id, to],
        )?;
        let next_seq: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version_seq), 0) + 1 FROM files \
             WHERE group_id = ?1 AND path = ?2",
            params![group_id, to],
            |r| r.get(0),
        )?;
        conn.execute(
            "UPDATE files SET path = ?3, version_seq = ?4 \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            params![group_id, from, to, next_seq],
        )?;
    }
    Ok(())
}

/// Whether any live current row of `group_id` lies strictly below `path`:
/// the index's own answer to whether `path` has to be a directory for
/// what is installed under it. "Below" is the namespace relation: the
/// half-open range (`path/`, `path0`), never a `LIKE`.
pub fn has_live_descendant_row(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM files WHERE group_id = ?1 AND path > ?2 AND path < ?3 \
               AND state = 'current' AND deleted = 0 LIMIT 1",
            params![group_id, format!("{path}/"), format!("{path}0")],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Settles every path an install's row replacement touched, given the live
/// rows it `replaced` (read before the replacement) and the rows it has
/// just written. Runs in the install's own transaction.
///
/// A path whose installed row places exactly the object the replaced row
/// placed is not replaced on disk at all, so the replaced row's
/// materialization state and placeholder identity -- facts about that
/// object -- carry over, and the path is not held. Every other path either
/// row makes live is held, recording what the replaced row placed. A path
/// already held from an earlier install stays held with its original
/// record and carries nothing over: its disk was never reconciled.
pub(crate) fn settle_replaced_rows(
    conn: &Connection,
    group_id: &str,
    replaced: &HashMap<String, ReplacedRow>,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    let installed = live_rows(conn, group_id)?;
    let mut paths: Vec<&String> = replaced.keys().chain(installed.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        let prior = replaced.get(path);
        let unchanged = match (prior, installed.get(path)) {
            (Some(prior), Some(installed)) => prior.places_the_same_object_as(installed),
            _ => false,
        };
        if unchanged && !is_held(conn, group_id, path)? {
            let prior = prior.expect("an unchanged path has a replaced row");
            conn.execute(
                "UPDATE files SET materialization_state = ?3, placeholder_dev = ?4, \
                        placeholder_ino = ?5, placeholder_provider_kind = ?6 \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                params![
                    group_id,
                    path,
                    prior.materialization_state,
                    prior.placeholder_dev,
                    prior.placeholder_ino,
                    prior.placeholder_provider_kind,
                ],
            )?;
            continue;
        }
        hold_in_tx(conn, group_id, path, prior, now_unix_nanos)?;
    }
    Ok(())
}

/// Holds `path`, recording `prior` as what may be on disk under it. A path
/// already held keeps its original record: a second install before the
/// first was reconciled has not changed what is on disk, and the rows the
/// second one replaced were never placed. Its generation moves, though: the
/// installed row a reconciliation in flight read is no longer the one the
/// hold stands for.
pub(crate) fn hold_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    prior: Option<&ReplacedRow>,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO snapshot_install_holds \
         (group_id, path, prior_record_kind, prior_materialization_state, prior_size, \
          prior_blocks_json, prior_unix_mode, prior_xattrs_json, prior_symlink_target, \
          held_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(group_id, path) DO UPDATE SET generation = generation + 1",
        params![
            group_id,
            path,
            prior.map(|row| row.record_kind.as_str()),
            prior.map(|row| row.materialization_state.as_str()),
            prior.map(|row| row.size),
            prior.map(|row| row.blocks_json.as_str()),
            prior.map(|row| row.unix_mode),
            prior.map(|row| row.xattrs_json.as_str()),
            prior.and_then(|row| row.symlink_target.as_deref()),
            now_unix_nanos,
        ],
    )?;
    Ok(())
}

pub fn is_held(conn: &Connection, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM snapshot_install_holds WHERE group_id = ?1 AND path = ?2",
            params![group_id, path],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub fn held_paths(conn: &Connection, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt = conn
        .prepare("SELECT path FROM snapshot_install_holds WHERE group_id = ?1 ORDER BY path ASC")?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn list_holds(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<SnapshotInstallHold>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, prior_record_kind, prior_materialization_state, prior_size, \
                prior_blocks_json, prior_unix_mode, prior_xattrs_json, prior_symlink_target, \
                generation \
         FROM snapshot_install_holds WHERE group_id = ?1 ORDER BY path ASC",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, Option<Vec<u8>>>(7)?,
            r.get::<_, i64>(8)?,
        ))
    })?;
    let mut holds = Vec::new();
    for row in rows {
        let (
            path,
            kind,
            state,
            size,
            blocks_json,
            unix_mode,
            xattrs_json,
            symlink_target,
            generation,
        ) = row?;
        let prior = match kind {
            None => None,
            Some(kind) => Some(PriorPlacement {
                record_kind: RecordKind::from_db_str(&kind),
                placeholder: state.as_deref() == Some("placeholder"),
                size: size.unwrap_or(0).max(0) as u64,
                blocks: serde_json::from_str(blocks_json.as_deref().unwrap_or("[]")).map_err(
                    |error| {
                        SyncSqliteError::CorruptState(format!(
                            "a snapshot install hold's replaced block list is corrupt: {error}"
                        ))
                    },
                )?,
                unix_mode: crate::file_index::decode_unix_mode_column(unix_mode.unwrap_or(-1)),
                xattrs: crate::file_index::decode_xattrs_column(
                    xattrs_json.as_deref().unwrap_or("[]"),
                )?,
                symlink_target,
            }),
        };
        holds.push(SnapshotInstallHold { path, prior, generation });
    }
    Ok(holds)
}

/// Releases `path` at `generation`: the reconciliation has left disk holding
/// the projection of the installed row it read (or nothing, where that row
/// is not live). Returns whether it was released -- `false` when the path is
/// not held, or is held at another generation because an install renewed
/// the hold after the reconciliation read it. That hold is left in place.
///
/// In the same transaction, a live installed row gets a pending projection
/// obligation. The scheduler then drives the path to its policy's final
/// state, and until it has, the obligation is what tells the offline-delete
/// scan that a path with nothing under its name is still being placed.
pub fn release_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    generation: i64,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let removed = conn.execute(
        "DELETE FROM snapshot_install_holds WHERE group_id = ?1 AND path = ?2 AND generation = ?3",
        params![group_id, path, generation],
    )?;
    if removed == 0 {
        return Ok(false);
    }
    let live: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 \
            AND state = 'current' AND deleted = 0)",
        params![group_id, path],
        |r| r.get(0),
    )?;
    if live {
        crate::projection_obligations::bump_projection_obligations_for_touched_paths(
            conn,
            group_id,
            &[path],
            now_unix_nanos,
        )?;
    }
    Ok(true)
}

/// Refuses a local authoring of `path` while it is held. Called inside the
/// authoring transaction itself, so a capture prepared before an install
/// and committed after it cannot slip past: it is the only point that sees
/// the hold and the authoring atomically.
pub(crate) fn refuse_local_authoring_if_held(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    if is_held(conn, group_id, path)? {
        return Err(SyncSqliteError::PathAwaitingSnapshotInstallReconciliation {
            group_id: group_id.to_owned(),
            path: path.to_owned(),
        });
    }
    Ok(())
}

pub struct SnapshotInstallHoldRepository {
    database: Arc<SyncDatabase>,
}

impl SnapshotInstallHoldRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    pub fn is_held(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| is_held(conn, group_id, path))
    }

    /// See [`has_live_descendant_row`].
    pub fn has_live_descendant_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| has_live_descendant_row(conn, group_id, path))
    }

    /// Every held path of `group_id`, in path order.
    pub fn held_paths(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| held_paths(conn, group_id))
    }

    pub fn list(&self, group_id: &str) -> Result<Vec<SnapshotInstallHold>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| list_holds(conn, group_id))
    }

    /// See [`relocate_held_entry_beside_directory_in_tx`].
    pub fn relocate_held_entry_beside_directory(
        &self,
        group_id: &str,
        path: &str,
        generation: i64,
        removable: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
        now_unix_nanos: i64,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            relocate_held_entry_beside_directory_in_tx(
                tx,
                group_id,
                path,
                generation,
                removable,
                now_unix_nanos,
            )
        })
    }

    /// See [`release_in_tx`].
    pub fn release(
        &self,
        group_id: &str,
        path: &str,
        generation: i64,
        now_unix_nanos: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            release_in_tx(tx, group_id, path, generation, now_unix_nanos)
        })
    }
}
