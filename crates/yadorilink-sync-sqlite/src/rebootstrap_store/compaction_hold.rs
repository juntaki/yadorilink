//! Holding one group's compaction while it has a conflict only its user
//! can resolve.
//!
//! A seal carries, per path, at most one live head per author: the base's
//! summary has nowhere to put a second, so a seal of a group that holds
//! two refuses (`SealRefusal::TwoHeadsFromOneAuthor`). The state is not
//! corruption. It arises in ordinary use: an author's version of a path
//! that its own device was not showing when it wrote the path again -- an
//! installed base's losing head it had at a conflict-copy name, or a
//! version admitted during the write's debounce -- is not superseded by
//! the write (a change supersedes only what its writer was shown), so the
//! path keeps both. The two stay visible, one at the path and one at its
//! conflict-copy name, and the fork closes only when the user deletes or
//! edits one of them. The summary format is deliberately not extended to
//! carry it.
//!
//! So the refusal holds this group's compaction and nothing else:
//! admission, capture, projection and every other group go on as before.
//! [`seal_group_unless_held`] records the paths the refusal names, with
//! the live heads each had, and does not try again while those heads are
//! unchanged -- a retry needs something to have happened at one of those
//! paths, which is what resolving the conflict is. [`held_paths`] and
//! [`copy_holds_compaction`] are the status reading of the same record:
//! which recorded paths still hold two live heads of one author, and
//! which conflict copies carry one of those heads. Those are different
//! questions from the retry's: a path whose heads changed may still hold
//! the fork (a peer's concurrent write joined it), and a path can have
//! other copies (a peer's losing version) whose resolution does not
//! touch the fork.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection};

use super::seal::{seal_group, SealRefusal, VerifiedSeal};
use crate::SyncSqliteError;

/// What [`seal_group_unless_held`] did.
#[derive(Debug)]
pub enum SealAttempt {
    /// The group was sealed.
    Sealed(Box<VerifiedSeal>),
    /// The group holds a conflict a seal cannot carry, at `paths`; its
    /// compaction waits until one of them changes.
    Held { paths: Vec<String> },
}

/// Seals `group_id` in the caller's transaction, unless its compaction is
/// held.
///
/// Held means an earlier attempt was refused because a path held two live
/// heads of one author, and none of the paths it named has changed since.
/// Then nothing is attempted and the held paths are returned. Otherwise
/// any stale hold is dropped and [`seal_group`] runs; a refusal of the
/// same kind is recorded as the group's hold (every such path, not only
/// the first) and returned as [`SealAttempt::Held`], never as an error.
/// Every other refusal and error is returned as it is.
pub fn seal_group_unless_held(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
) -> Result<SealAttempt, SyncSqliteError> {
    super::init_rebootstrap_schema(tx)?;
    let recorded = recorded_paths(tx, group_id)?;
    if !recorded.is_empty() {
        let unchanged = unchanged_recorded_paths(tx, group_id)?;
        if unchanged.len() == recorded.len() {
            return Ok(SealAttempt::Held { paths: unchanged });
        }
        tx.execute("DELETE FROM compaction_holds WHERE group_id = ?1", [group_id])?;
    }
    match seal_group(tx, group_id) {
        Ok(seal) => Ok(SealAttempt::Sealed(Box::new(seal))),
        Err(SyncSqliteError::SealRefused {
            refusal: SealRefusal::TwoHeadsFromOneAuthor { .. },
            ..
        }) => {
            let paths = paths_with_two_heads_from_one_author(tx, group_id)?;
            if paths.is_empty() {
                return Err(SyncSqliteError::CorruptState(format!(
                    "the seal of group {group_id} was refused for two live heads of one author \
                     at a path, but the group's summary holds none"
                )));
            }
            let mut record = tx.prepare_cached(
                "INSERT INTO compaction_holds (group_id, path, live_heads) VALUES (?1, ?2, ?3)",
            )?;
            for path in &paths {
                record.execute(params![group_id, path, live_heads_of(tx, group_id, path)?])?;
            }
            Ok(SealAttempt::Held { paths })
        }
        Err(error) => Err(error),
    }
}

/// The paths of `group_id` whose unresolved conflict its compaction is
/// waiting for: recorded by the last refused seal, and still holding two
/// live heads of one author, whether or not other heads have joined or
/// left the path since. Empty when the group's compaction is not held, or
/// when every recorded path's fork has closed (the next attempt decides
/// again).
pub fn held_paths(conn: &Connection, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
    let mut out = Vec::new();
    for path in recorded_paths(conn, group_id)? {
        if !same_author_heads(conn, group_id, &path)?.is_empty() {
            out.push(path);
        }
    }
    Ok(out)
}

/// Whether the conflict copy at `copy_path` is one the group's compaction
/// is waiting for: its source path is held (see [`held_paths`]) and the
/// version the copy holds is one of the two (or more) live heads of one
/// author there, so deleting or editing it closes that fork. A copy of
/// any other version of the source -- a peer's concurrent losing head --
/// is an ordinary conflict: resolving it leaves the fork, and the hold,
/// as they are.
pub fn copy_holds_compaction(
    conn: &Connection,
    group_id: &str,
    copy_path: &str,
) -> Result<bool, SyncSqliteError> {
    let source = yadorilink_replica_domain::conflict::conflict_copy_source_path(copy_path);
    if source == copy_path {
        return Ok(false);
    }
    let recorded: bool = conn
        .prepare_cached("SELECT 1 FROM compaction_holds WHERE group_id = ?1 AND path = ?2")?
        .exists(params![group_id, source])?;
    if !recorded {
        return Ok(false);
    }
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, copy_path)? else {
        return Ok(false);
    };
    let Some(authoring) = row.authoring_change_hash.filter(|_| !row.snapshot.deleted) else {
        return Ok(false);
    };
    Ok(same_author_heads(conn, group_id, &source)?.contains(&authoring.0))
}

/// The recorded paths still holding exactly the live heads they held when
/// the refusal recorded them: what a held seal waits on changing.
fn unchanged_recorded_paths(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT path, live_heads FROM compaction_holds WHERE group_id = ?1 ORDER BY path",
    )?;
    let rows: Vec<(String, Vec<u8>)> = stmt
        .query_map([group_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for (path, heads) in rows {
        if live_heads_of(conn, group_id, &path)? == heads {
            out.push(path);
        }
    }
    Ok(out)
}

/// `path`'s live content heads whose author has another one there: the
/// fork a seal cannot carry. A tombstone head is no head a base carries
/// (the summary a seal checks holds content heads only), so a delete
/// that closed the fork is not a second head of its author. Empty when
/// every author has at most one.
fn same_author_heads(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<BTreeSet<[u8; 32]>, SyncSqliteError> {
    let mut by_author: BTreeMap<String, Vec<[u8; 32]>> = BTreeMap::new();
    for head in crate::dag_store::live_path_heads(conn, group_id, path)? {
        if head.content.is_none() {
            continue;
        }
        by_author.entry(head.device_id).or_default().push(head.change_hash);
    }
    Ok(by_author.into_values().filter(|heads| heads.len() > 1).flatten().collect())
}

fn recorded_paths(conn: &Connection, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt =
        conn.prepare_cached("SELECT path FROM compaction_holds WHERE group_id = ?1 ORDER BY path")?;
    let paths = stmt.query_map([group_id], |row| row.get(0))?.collect::<Result<_, _>>()?;
    Ok(paths)
}

/// Every path at which the group's summary holds two live heads of one
/// author, in path order.
fn paths_with_two_heads_from_one_author(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<String>, SyncSqliteError> {
    let summary = super::build_group_history_summary(conn, group_id)?;
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for head in &summary.path_heads {
        if !seen.insert((head.path.as_str(), head.device_id.as_str())) {
            paths.insert(head.path.clone());
        }
    }
    Ok(paths.into_iter().collect())
}

/// `path`'s live heads (the current epoch's and the installed base's
/// unnamed ones), as their sorted change hashes laid end to end: what has
/// to change at `path` before a held seal is tried again.
fn live_heads_of(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<u8>, SyncSqliteError> {
    let mut heads: Vec<[u8; 32]> = crate::dag_store::live_path_heads(conn, group_id, path)?
        .into_iter()
        .map(|head| head.change_hash)
        .collect();
    heads.sort_unstable();
    Ok(heads.concat())
}
