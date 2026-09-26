//! The base heads a change on a history base supersedes: exactly the ones
//! it names.
//!
//! A change written above an installed history base does not descend from
//! the whole base. It carries a signed set of the base's heads its author
//! actually saw at the paths it touches
//! ([`Change::observed_base_heads`]), and those are the only base heads it
//! supersedes. A base head at a touched path that the change does not name
//! stays live beside it, exactly as a version a writer never saw stays live
//! beside an edit on the group's original history. Base heads are not DAG
//! nodes here -- the changes that wrote them were absorbed by the base --
//! so ancestry never decides anything about them.
//!
//! This module holds the three sides of that rule:
//!
//! * [`observed_base_heads_for`]: what a local write names, from what its
//!   writer was shown at each path it touches;
//! * [`invalid_observed_base_head`]: what admission (and local emission)
//!   refuses -- a name that is not a head of the change's own base at any
//!   path it touches;
//! * [`record_naming`] and [`unnamed_base_heads_at`] /
//!   [`unnamed_base_heads_in_range`]: the derived per-path record of which
//!   base heads the current epoch has named, and the base heads still live
//!   because nothing has.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection};
use yadorilink_replica_domain::change::{Change, Op, MAX_OBSERVED_BASE_HEADS};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::rebootstrap::HistoryEpoch;
use yadorilink_replica_engine::conflict::{PathHead, PathHeadContent};

use crate::error::SyncSqliteError;

/// What a writer was shown, per path: the changes whose versions the path's
/// row held when the write was made. A path with no entry was shown nothing.
pub type SeenVersions = BTreeMap<String, BTreeSet<ChangeHash>>;

/// The base heads a local write of `ops` names, given what its writer was
/// shown at each path it touches.
///
/// With `G_p` the base heads still live at `p` (carried by the installed
/// base there and not yet named by the current epoch), a write that touches
/// the paths `T` names
///
/// ```text
/// O = { x | some p in T: x in G_p and x in seen_p }
///   ∩ { x | every q in T: x in G_q implies x in seen_q }
/// ```
///
/// The second half is the intersection rule (OBS-HONEST): one flat set
/// serves every path the change touches, so a base head that heads two of
/// them is named only when the writer saw it at both. Where it did not,
/// the head is left live at both -- a spurious conflict copy is
/// recoverable, a superseded version is not.
///
/// The defaults for the product questions the plan leaves open are decided
/// here, and only here:
///
/// * Q1 (OWN-HEAD-NAMED): an author's own base head is **not** named
///   unless it was shown to the writer like any other head. Preservation
///   first, as before a seal; a seal refuses the resulting second head of
///   one author at a path (`TwoHeadsFromOneAuthor`) until the fork closes.
/// * Q2: at most [`MAX_OBSERVED_BASE_HEADS`] names.
/// * Q3: one flat set per change with the intersection rule above, not a
///   set per op.
/// * Q4: a directory that lost its path to a leaf (DIR-1) is never shown
///   there, so showing the winning leaf does **not** count as having seen
///   it: it is not named, and it stays live beside the write.
///
/// Empty on the group's original history, which has no base.
pub(crate) fn observed_base_heads_for(
    conn: &Connection,
    group_id: &str,
    ops: &[Op],
    seen: &SeenVersions,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    if crate::rebootstrap_store::current_history_epoch(conn, group_id)? == HistoryEpoch::Genesis {
        return Ok(Vec::new());
    }
    let touched: BTreeSet<&str> = ops.iter().flat_map(super::op_touched_paths).collect();
    let mut live: BTreeMap<&str, BTreeSet<ChangeHash>> = BTreeMap::new();
    for path in &touched {
        let heads = unnamed_base_heads_at(conn, group_id, path)?
            .into_iter()
            .map(|head| ChangeHash(head.change_hash))
            .collect();
        live.insert(path, heads);
    }
    let shown = |path: &str, head: &ChangeHash| {
        seen.get(path).is_some_and(|versions| versions.contains(head))
    };
    let mut named: BTreeSet<ChangeHash> = BTreeSet::new();
    for (path, heads) in &live {
        named.extend(heads.iter().filter(|head| shown(path, head)).copied());
    }
    named
        .retain(|head| live.iter().all(|(path, heads)| !heads.contains(head) || shown(path, head)));
    if named.len() > MAX_OBSERVED_BASE_HEADS {
        return Err(SyncSqliteError::InvalidInput(format!(
            "cannot emit local change for group {group_id}: it would name {} observed base \
             heads, more than {MAX_OBSERVED_BASE_HEADS}",
            named.len()
        )));
    }
    Ok(named.into_iter().collect())
}

/// The first observed base head `change` names that its own base does not
/// carry at any path it touches, or `None` when every name is one.
///
/// Measured against the base's `Gamma` (`history_base_path_heads`), not
/// against the heads still live here: a sibling that already named the
/// same head does not make this name invalid, so the verdict does not
/// depend on delivery order. The caller has already established that
/// `change` is written on the history this replica is on.
pub(crate) fn invalid_observed_base_head(
    conn: &Connection,
    change: &Change,
) -> Result<Option<ChangeHash>, SyncSqliteError> {
    let Some(first) = change.observed_base_heads.first() else { return Ok(None) };
    let Some(base) = change.history_epoch.base() else { return Ok(Some(*first)) };
    if change.observed_base_heads.len() > MAX_OBSERVED_BASE_HEADS {
        return Ok(change.observed_base_heads.last().copied());
    }
    let touched: BTreeSet<&str> = change.ops.iter().flat_map(super::op_touched_paths).collect();
    let mut carried = conn.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM history_base_path_heads \
         WHERE group_id = ?1 AND base_hash = ?2 AND path = ?3 AND change_hash = ?4)",
    )?;
    'names: for head in &change.observed_base_heads {
        for path in &touched {
            let found: bool = carried.query_row(
                params![change.group_id.as_str(), &base.0[..], path, &head.0[..]],
                |row| row.get(0),
            )?;
            if found {
                continue 'names;
            }
        }
        return Ok(Some(*head));
    }
    Ok(None)
}

/// Records the base heads `change` names at the paths it touches, as
/// superseded there. Called for every change as its path effects are
/// recorded -- at admission and when the path frontier is rebuilt -- so the
/// record is derived from retained history. Idempotent.
pub(crate) fn record_naming(conn: &Connection, change: &Change) -> Result<(), SyncSqliteError> {
    let hash = change.compute_hash();
    let mut name = conn.prepare_cached(
        "INSERT OR IGNORE INTO history_base_named_heads \
         (group_id, path, change_hash, naming_change) \
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for (path, head) in naming_of(conn, change)? {
        name.execute(params![change.group_id.as_str(), path, &head.0[..], &hash.0[..]])?;
    }
    Ok(())
}

/// Whether the stored record of what `change` named is exactly what its
/// signed bytes name. Run at startup inside the pass that already decodes
/// every retained change, beside the check of its path effects: a lost row
/// would make a base head the epoch superseded live again, and a spurious
/// one would bury a live base head for good.
pub(crate) fn naming_matches_change(
    conn: &Connection,
    change: &Change,
) -> Result<bool, SyncSqliteError> {
    let hash = change.compute_hash();
    let mut stmt = conn.prepare_cached(
        "SELECT path, change_hash FROM history_base_named_heads \
         WHERE group_id = ?1 AND naming_change = ?2",
    )?;
    let rows = stmt.query_map(params![change.group_id.as_str(), &hash.0[..]], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut stored: BTreeSet<(String, Vec<u8>)> = BTreeSet::new();
    for row in rows {
        stored.insert(row?);
    }
    let expected: BTreeSet<(String, Vec<u8>)> =
        naming_of(conn, change)?.into_iter().map(|(path, head)| (path, head.0.to_vec())).collect();
    Ok(stored == expected)
}

/// `(path, base head)` for every base head `change` names at a path it
/// touches that its base carries there.
fn naming_of(
    conn: &Connection,
    change: &Change,
) -> Result<Vec<(String, ChangeHash)>, SyncSqliteError> {
    if change.observed_base_heads.is_empty() {
        return Ok(Vec::new());
    }
    let Some(base) = change.history_epoch.base() else { return Ok(Vec::new()) };
    let touched: BTreeSet<&str> = change.ops.iter().flat_map(super::op_touched_paths).collect();
    let mut carried = conn.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM history_base_path_heads \
         WHERE group_id = ?1 AND base_hash = ?2 AND path = ?3 AND change_hash = ?4)",
    )?;
    let mut out = Vec::new();
    for path in touched {
        for head in &change.observed_base_heads {
            let found: bool = carried.query_row(
                params![change.group_id.as_str(), &base.0[..], path, &head.0[..]],
                |row| row.get(0),
            )?;
            if found {
                out.push((path.to_string(), *head));
            }
        }
    }
    Ok(out)
}

/// Clears the group's record ahead of a rebuild replaying every retained
/// change's names into it. Kept: the names a change a checkpoint pruned
/// recorded, while its prune record stands and the base still carries the
/// head -- its signed bytes are gone, and with them any way to derive them
/// again.
pub(crate) fn clear_derived_naming(
    conn: &Connection,
    group_id: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM history_base_named_heads \
         WHERE group_id = ?1 AND ( \
             NOT EXISTS (SELECT 1 FROM pruned_changes p \
                         WHERE p.group_id = history_base_named_heads.group_id \
                           AND p.change_hash = history_base_named_heads.naming_change) \
             OR NOT EXISTS (SELECT 1 FROM history_base_path_heads b \
                            WHERE b.group_id = history_base_named_heads.group_id \
                              AND b.path = history_base_named_heads.path \
                              AND b.change_hash = history_base_named_heads.change_hash))",
        [group_id],
    )?;
    Ok(())
}

/// The check [`naming_matches_change`] cannot make, since it walks
/// retained changes: rows no retained change accounts for. A row whose
/// naming change is neither retained nor pruned, or that names a head
/// the installed base does not carry at its path, was never recorded by
/// admission.
pub(crate) const UNACCOUNTED_NAMING_SQL: &str = "SELECT DISTINCT n.group_id \
     FROM history_base_named_heads n \
     WHERE NOT EXISTS (SELECT 1 FROM changes c \
                       WHERE c.group_id = n.group_id AND c.change_hash = n.naming_change) \
       AND NOT EXISTS (SELECT 1 FROM pruned_changes p \
                       WHERE p.group_id = n.group_id AND p.change_hash = n.naming_change) \
     UNION \
     SELECT DISTINCT n.group_id \
     FROM history_base_named_heads n \
     WHERE NOT EXISTS (SELECT 1 FROM history_base_path_heads b \
                       WHERE b.group_id = n.group_id AND b.path = n.path \
                         AND b.change_hash = n.change_hash)";

/// The installed base's heads at `path` that no admitted change on the
/// current epoch has named: the base's part of `path`'s live heads.
pub(crate) fn unnamed_base_heads_at(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT b.path, b.change_hash, b.lamport, b.device_id, b.naming_device_id, \
                b.version_hash \
         FROM history_base_path_heads b \
         WHERE b.group_id = ?1 AND b.path = ?2 AND NOT EXISTS ( \
             SELECT 1 FROM history_base_named_heads n \
             WHERE n.group_id = b.group_id AND n.path = b.path \
               AND n.change_hash = b.change_hash)",
    )?;
    let mut rows = stmt.query(params![group_id, path])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(base_head_from_row(row)?.1);
    }
    Ok(out)
}

/// [`unnamed_base_heads_at`] for every path strictly between `lower` and
/// `upper` (no upper bound when `None`) that the current epoch has
/// touched -- that holds a live head of its own -- in path order.
///
/// Touched paths only: at a path the current epoch has not written, the
/// installed base's heads are all its heads and the rows the base
/// installed already hold their projection, which is what every reader of
/// the live path frontier has always taken an untouched path to mean.
pub(crate) fn unnamed_base_heads_in_range(
    conn: &Connection,
    group_id: &str,
    lower: &str,
    upper: Option<&str>,
) -> Result<Vec<(String, PathHead)>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT b.path, b.change_hash, b.lamport, b.device_id, b.naming_device_id, \
                b.version_hash \
         FROM history_base_path_heads b \
         WHERE b.group_id = ?1 AND b.path > ?2 AND (?3 IS NULL OR b.path < ?3) \
           AND EXISTS (SELECT 1 FROM path_live_heads h \
                       WHERE h.group_id = b.group_id AND h.path = b.path) \
           AND NOT EXISTS ( \
             SELECT 1 FROM history_base_named_heads n \
             WHERE n.group_id = b.group_id AND n.path = b.path \
               AND n.change_hash = b.change_hash) \
         ORDER BY b.path",
    )?;
    let mut rows = stmt.query(params![group_id, lower, upper])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(base_head_from_row(row)?);
    }
    Ok(out)
}

fn base_head_from_row(row: &rusqlite::Row<'_>) -> Result<(String, PathHead), SyncSqliteError> {
    let path: String = row.get(0)?;
    let hash = |bytes: Vec<u8>| {
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "installed base head of {path:?} carries a hash that is not 32 bytes"
            ))
        })
    };
    let lamport: i64 = row.get(2)?;
    let head = PathHead {
        change_hash: hash(row.get(1)?)?,
        lamport: u64::try_from(lamport).map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "installed base head of {path:?} is stored at Lamport {lamport}"
            ))
        })?,
        device_id: row.get(3)?,
        naming_device_id: row.get(4)?,
        content: Some(PathHeadContent { version_hash: hash(row.get(5)?)?, mtime_unix_nanos: 0 }),
    };
    Ok((path, head))
}
