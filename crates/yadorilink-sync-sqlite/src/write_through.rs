//! Write-through: which entry a local operation on a copy name is an
//! operation on.
//!
//! The namespace projection can place a path's File or Symlink under a
//! conflict-copy name of that path: relocated because the path has to be a
//! directory (a live descendant, or an explicit Directory, which keeps its
//! path), or held there on this device (a directory it may not
//! remove, or a case-fold collision). The index then holds the entry's row
//! under the copy name, written by the change that put the entry at its
//! own path. No change ever authored anything at the copy name.
//!
//! A user who deletes or edits that copy is deleting or editing the entry,
//! so the capture authors `Delete(a)` / `Put(a)` for its source `a` and
//! never an op at the copy name ([`write_through_source`]). A copy some
//! change did author as an entry of its own (a conflict copy made durable,
//! or any file someone wrote under such a name) is that entry, and an
//! operation on it is an ordinary one at its own path.
//!
//! The change authored for it supersedes only the source's head the
//! copy's row was written from. Everything else live at the source -- the
//! explicit Directory that keeps the path, a peer's newer write, a losing
//! File -- stays concurrent with it: the commit seam signs it onto the
//! frontier without the source's unseen heads (see
//! `file_index::emit_local_write_onto_frontier`).
//!
//! A recursive delete or directory rename that observed such a copy
//! writes it through the same way ([`write_recursive_operation_through`]):
//! `rm -rf p` deletes `p/a`, and `mv p q` deletes `p/a` and puts `q/a`,
//! never an op at the copy name. A directory made where the copy was (a
//! type change) deletes the source first, then is a new entry of its own.

use rusqlite::{params, Connection, OptionalExtension};

use yadorilink_replica_domain::conflict::{conflict_copy_source_path, is_conflict_copy_path};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_engine::conflict::{dag_conflict_loser_is_a, PathHead, PathHeadContent};

use crate::dag_store::{get_file_version, live_path_heads};
use crate::error::SyncSqliteError;

/// The source entry a local operation on `path` is an operation on, when
/// `path` is a copy name at which the projection places the source's own
/// File or Symlink winner: `path`'s live row is that winner's content under
/// the change that wrote it at the source, and no change authored anything
/// at `path` itself. `None` for every other path, which authors at its own
/// name.
///
/// The source's heads are its live path frontier, or, for a path no live
/// change has touched since a HistoryBase install, the installed base's
/// heads (the install relocates such a row the same way).
pub fn write_through_source(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<String>, SyncSqliteError> {
    if !is_conflict_copy_path(path) {
        return Ok(None);
    }
    let source = conflict_copy_source_path(path);
    if source == path {
        return Ok(None);
    }
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, path)? else {
        return Ok(None);
    };
    if row.snapshot.deleted
        || !matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
    {
        return Ok(None);
    }
    let Some(authoring) = row.authoring_change_hash else { return Ok(None) };
    // Authored at its own name: an entry of its own, whatever it is named.
    if !heads_of(conn, group_id, path)?.is_empty() {
        return Ok(None);
    }
    let version = row.version_hash().0;
    let known = (version, row.snapshot.record_kind);
    let Some(winner) = best_leaf_head(conn, group_id, &heads_of(conn, group_id, &source)?, known)?
    else {
        return Ok(None);
    };
    let placed = winner.change_hash == authoring.0
        && winner.content.as_ref().is_some_and(|content| content.version_hash == version);
    // The copy still shows an earlier version of the same leaf: a later
    // write of the source that descends from the one the copy holds is
    // admitted, and the reconcile has not yet moved the copy. The user is
    // still acting on that entry; the write is signed without the heads
    // the copy has not seen, so it stays concurrent with them.
    let behind = !placed
        && wrote_version_at(conn, group_id, &authoring.0, &source, &version)?
        && crate::dag_store::path_frontier::is_ancestor_bounded(
            conn,
            &authoring,
            &yadorilink_replica_domain::ids::ChangeHash(winner.change_hash),
        )?;
    Ok((placed || behind).then_some(source))
}

/// Whether `change` wrote `version` at `path` (its content effect there).
fn wrote_version_at(
    conn: &Connection,
    group_id: &str,
    change: &[u8; 32],
    path: &str,
    version: &[u8; 32],
) -> Result<bool, SyncSqliteError> {
    let written: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT version_hash FROM change_path_effects \
              WHERE group_id = ?1 AND path = ?2 AND change_hash = ?3",
            params![group_id, path, &change[..]],
            |row| row.get(0),
        )
        .optional()?;
    Ok(written.flatten().is_some_and(|written| written.as_slice() == version.as_slice()))
}

/// The recursive operation's `mutations` with every op on a copy name
/// written through to its source (see [`write_through_source`]): the
/// delete of a copy a recursive delete or rename observed is authored at
/// the entry the copy is, and a rename's put of that copy under the new
/// name at the entry's own new path. The rows stay where they are.
///
/// A copy whose source already has an op of its own in the operation
/// (an explicit Directory at the source, deleted or moved with it) keeps
/// its op at the copy name: one change carries one op per path, and the
/// source's own op already supersedes what the copy's parents name there.
pub(crate) fn write_recursive_operation_through(
    conn: &Connection,
    group_id: &str,
    kind: &yadorilink_replica_domain::recursive_operation::RecursiveOperationKind,
    mutations: &[yadorilink_replica_domain::session_state::PreparedLocalMutation],
) -> Result<Vec<yadorilink_replica_domain::session_state::PreparedLocalMutation>, SyncSqliteError> {
    use yadorilink_replica_domain::change::Op;
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
    use yadorilink_replica_domain::session_state::PreparedLocalMutation;

    let op_path = |op: &Op| match op {
        Op::Put { path, .. } | Op::Delete { path } => Some(path.as_str().to_string()),
        Op::Move { .. } => None,
    };
    let mut taken: std::collections::HashSet<String> =
        mutations.iter().filter_map(|m| op_path(m.op())).collect();
    let mut out = mutations.to_vec();
    // Old copy path -> the source its delete was written through to.
    let mut written: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for mutation in &mut out {
        let PreparedLocalMutation::Delete { record, op } = mutation else { continue };
        if op_path(op).as_deref() != Some(record.path.as_str()) {
            continue;
        }
        let Some(source) = write_through_source(conn, group_id, &record.path)? else { continue };
        if !taken.insert(source.clone()) {
            continue;
        }
        *op = Op::Delete { path: SyncPath(source.clone()) };
        written.insert(record.path.clone(), source);
    }
    if let RecursiveOperationKind::RenameTree { from, to } = kind {
        let (from, to) = (from.as_str(), to.as_str());
        for mutation in &mut out {
            let PreparedLocalMutation::Upsert { record, op, .. } = mutation else { continue };
            let Op::Put { path, .. } = op else { continue };
            let Some(rest) = path.as_str().strip_prefix(to) else { continue };
            if path.as_str() != record.path || !written.contains_key(&format!("{from}{rest}")) {
                continue;
            }
            let copy_source =
                yadorilink_replica_domain::conflict::conflict_copy_source_path(&record.path);
            let Some(source) = write_through_op_path(&record.path, &copy_source) else {
                continue;
            };
            if !taken.insert(source.to_string()) {
                continue;
            }
            *path = SyncPath(source.to_string());
        }
    }
    Ok(out)
}

/// Whether a single-op local write of the row at `record_path` whose op
/// is at `op_path` is a write-through: the op is at another path, and
/// `record_path` is a copy name of it. Returns the op path when it is.
pub(crate) fn write_through_op_path<'a>(record_path: &str, op_path: &'a str) -> Option<&'a str> {
    (op_path != record_path
        && is_conflict_copy_path(record_path)
        && conflict_copy_source_path(record_path) == op_path)
        .then_some(op_path)
}

/// `path`'s live heads: the path frontier's, or the installed base's when
/// the frontier has none.
fn heads_of(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let live = live_path_heads(conn, group_id, path)?;
    if !live.is_empty() {
        return Ok(live);
    }
    let mut stmt = conn.prepare_cached(
        "SELECT change_hash, device_id, lamport, version_hash, naming_device_id \
         FROM history_base_path_heads WHERE group_id = ?1 AND path = ?2",
    )?;
    let rows = stmt.query_map(params![group_id, path], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut heads = Vec::new();
    for row in rows {
        let (change_hash, device_id, lamport, version_hash, naming_device_id) = row?;
        let hash = |bytes: Vec<u8>| {
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "installed base head of {path:?} carries a hash that is not 32 bytes"
                ))
            })
        };
        heads.push(PathHead {
            change_hash: hash(change_hash)?,
            lamport: u64::try_from(lamport).unwrap_or(0),
            device_id,
            naming_device_id,
            content: Some(PathHeadContent {
                version_hash: hash(version_hash)?,
                mtime_unix_nanos: 0,
            }),
        });
    }
    Ok(heads)
}

/// The best-ranked File or Symlink content head: the one the projection
/// places as the path's own leaf (at the path, or relocated). `None` when
/// there is none, or a content head's kind is not known here (undecidable:
/// never a reason to write through). `known` is the kind of the version
/// the copy's row holds, which an installed base's head may name without
/// this replica holding the version itself.
fn best_leaf_head(
    conn: &Connection,
    group_id: &str,
    heads: &[PathHead],
    known: ([u8; 32], RecordKind),
) -> Result<Option<PathHead>, SyncSqliteError> {
    let mut best: Option<&PathHead> = None;
    for head in heads {
        let Some(content) = head.content.as_ref() else { continue };
        let kind = if content.version_hash == known.0 {
            known.1
        } else {
            let version = yadorilink_replica_domain::ids::VersionHash(content.version_hash);
            match get_file_version(conn, group_id, &version)? {
                Some(file_version) => file_version.meta.record_kind,
                None => return Ok(None),
            }
        };
        if !matches!(kind, RecordKind::File | RecordKind::Symlink) {
            continue;
        }
        if best.is_none_or(|b| {
            dag_conflict_loser_is_a(b.lamport, &b.change_hash, head.lamport, &head.change_hash)
        }) {
            best = Some(head);
        }
    }
    Ok(best.cloned())
}
