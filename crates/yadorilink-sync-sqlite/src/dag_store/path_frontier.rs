//! What a path currently resolves to, answered by reading it rather than
//! by re-deriving it.
//!
//! Resolving a path used to mean walking the group's ancestry backwards
//! from its current heads, decoding every visited change and scanning its
//! op list, discarding each one that turned out not to touch the path,
//! and stopping a lineage only once it found one that did. That is
//! O(history length) per path resolved, and it does not care how many
//! times the path itself was ever written: on a 10,000-file import
//! admitted as ~10,000 one-op changes, resolving eight paths cost ~92,000
//! change decodes, about 11,500 per path, for paths that had been written
//! exactly once each.
//!
//! Two derived tables replace that walk:
//!
//! - [`change_path_effects`](init_path_frontier_schema): what each change
//!   does to each path it touches, normalized out of its signed ops at
//!   admission time. The hot read path never decodes an encoded change.
//! - `path_live_heads`: for each path, the changes touching it that are
//!   causally maximal in the currently admitted DAG. Resolving a path is
//!   a read of this table, and nothing else.
//!
//! Neither is canonical. The signed `Change` remains the only authority;
//! these stand next to `change_parents` and `group_heads` as things
//! derived from it, rebuildable from it, and maintained in the same
//! transaction that admits it. [`rebuild_group`] reconstructs both from
//! retained history alone.
//!
//! # Why this is current state only
//!
//! `path_live_heads` answers "what does this path resolve to now". It
//! deliberately cannot answer "what did this path resolve to at some
//! earlier frontier" -- that is a different question with a different
//! cost model, and history-inspection features (rewind and friends)
//! answer it against the historical DAG and `change_time_index`. Folding
//! both into one table would put a historical walk back on the
//! convergence hot path, which is the thing this module exists to
//! remove.
//!
//! # Admission does not inherit the walk
//!
//! Moving work from read time to write time only helps if write time is
//! itself bounded. Admitting a change `C` that touches path `P` has to
//! decide, for each head `H` currently live on `P`, whether `C`
//! supersedes it -- that is, whether `H` is an ancestor of `C`. Answered
//! naively, that is the same unbounded walk, just relocated.
//!
//! It is answered from structure instead, in three steps, none of which
//! is proportional to history length:
//!
//! 1. **Whole-frontier supersession.** If `C`'s parents cover every head
//!    the group had before `C` arrived, then every live head of every
//!    path is in `C`'s causal past, because every one of them was
//!    reachable from some group head and every group head is now a parent
//!    of `C`. The whole question collapses to a delete, with no ancestry
//!    query at all. This is the shape ordinary local emission always has
//!    (it signs onto the current frontier), but it is a structural test
//!    on the change, not a local-only shortcut: a remote change that
//!    happens to cover the frontier takes exactly the same path.
//!
//! 2. **Spine points.** When a group has exactly one head, that head is
//!    an ancestor of every change admitted after it, and every change
//!    admitted before it is one of its ancestors -- a single head means
//!    nothing else is unsuperseded. Each change records the local
//!    admission ordinal of the most recent such point in its own causal
//!    past (`spine_ord`). Any head whose own ordinal is at or below that
//!    point is therefore an ancestor, decided by two integer lookups.
//!
//! 3. **A walk bounded by the spine.** Only heads newer than that point
//!    are left, and the backward walk that settles them prunes at the
//!    spine ordinal and at the candidate's own lamport (an ancestor's
//!    lamport is always strictly smaller, so a lower lamport can no
//!    longer reach it). What remains is the group's genuine divergence
//!    window -- the changes admitted since its branches last agreed --
//!    which is a property of how concurrent the group is, not of how long
//!    it has existed.
//!
//! Step 2's ordinal is why a locally-assigned admission order is recorded
//! at all. A lamport value cannot stand in for it: a change that arrives
//! late carrying a low lamport is not thereby an ancestor of anything, it
//! is merely concurrent, and treating the two as the same would silently
//! resurrect superseded content.

use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, VersionHash};
use yadorilink_replica_engine::conflict::{path_effects_of_change, PathHead, PathHeadContent};
use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotPathHead;

/// A path effect that lands content.
const EFFECT_CONTENT: i64 = 0;
/// A path effect that removes the path: a delete, or the source side of a
/// move away from it.
const EFFECT_REMOVAL: i64 = 1;

pub(crate) fn init_path_frontier_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- What a change does to each path it touches, normalized out of
        -- its signed ops when it is admitted. Derived from the change and
        -- nothing else, exactly like `change_parents` is derived from its
        -- parents: the signed `Change` stays the only authority, and
        -- `rebuild_group` reconstructs every row here from retained
        -- history.
        --
        -- It exists so resolving a path never decodes an encoded change
        -- to look for ops that mention it. `version_hash` is NULL exactly
        -- when `effect_kind` is a removal. `lamport`/`device_id` are
        -- copied from the carrier change so the read is a single-table
        -- lookup rather than a join back to `changes`; both are immutable
        -- for an admitted change, so there is nothing for them to drift
        -- against.
        CREATE TABLE IF NOT EXISTS change_path_effects (
            group_id         TEXT NOT NULL,
            path             TEXT NOT NULL,
            change_hash      BLOB NOT NULL,
            effect_kind      INTEGER NOT NULL,
            version_hash     BLOB,
            lamport          INTEGER NOT NULL,
            device_id        TEXT NOT NULL,
            naming_device_id TEXT NOT NULL,
            PRIMARY KEY (group_id, path, change_hash)
        );
        CREATE INDEX IF NOT EXISTS change_path_effects_by_change
            ON change_path_effects(change_hash);

        -- The causally maximal changes touching each path, across the
        -- whole currently admitted DAG. This is what an ordinary path
        -- resolution reads, and all it reads.
        --
        -- Current state only, on purpose: it tracks the live frontier and
        -- carries no history, so it cannot answer what a path held at an
        -- earlier frontier and must not be extended to try.
        CREATE TABLE IF NOT EXISTS path_live_heads (
            group_id    TEXT NOT NULL,
            path        TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, path, change_hash)
        );
        CREATE INDEX IF NOT EXISTS path_live_heads_by_change
            ON path_live_heads(group_id, change_hash);

        -- Local admission order, and the spine summary that makes
        -- supersession decidable without a history-length walk -- see this
        -- module's own doc comment. Both are device-local derived facts,
        -- not signed ones: two replicas holding identical history will
        -- generally disagree about them, and are meant to.
        CREATE TABLE IF NOT EXISTS change_causal_order (
            change_hash   BLOB PRIMARY KEY,
            group_id      TEXT NOT NULL,
            admission_ord INTEGER NOT NULL,
            spine_ord     INTEGER NOT NULL
        );
        -- The unique ordinal index is created separately, after any
        -- pre-existing duplicate has been cleared -- see below.

        -- Monotone per-group ordinal source. A counter rather than
        -- `MAX(admission_ord)` so compaction, which deletes the oldest
        -- retained changes, can never hand out an ordinal twice.
        CREATE TABLE IF NOT EXISTS group_admission_ord (
            group_id TEXT NOT NULL PRIMARY KEY,
            next_ord INTEGER NOT NULL
        );
        "#,
    )?;

    // A duplicate ordinal must fail loudly rather than silently corrupt a
    // later ancestry shortcut, which is what the unique index is for. But
    // creating it over a database that already holds one would fail the
    // open itself, before the rebuild that could fix it ever runs -- and
    // this is derived state, so a rebuild always can. Clear the affected
    // groups' ordering first; the startup check then sees retained
    // changes with no ordinal and rebuilds them from canonical history.
    let duplicated: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT group_id FROM change_causal_order \
             WHERE (group_id, admission_ord) IN ( \
                 SELECT group_id, admission_ord FROM change_causal_order \
                 GROUP BY group_id, admission_ord HAVING COUNT(*) > 1)",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for group_id in duplicated {
        conn.execute(
            "DELETE FROM change_causal_order WHERE group_id = ?1",
            rusqlite::params![&group_id],
        )?;
        conn.execute(
            "DELETE FROM group_admission_ord WHERE group_id = ?1",
            rusqlite::params![&group_id],
        )?;
    }

    // UNIQUE, not merely indexed. Every supersession shortcut rests on
    // the ordinal being a genuine linear extension of the DAG on this
    // device; two changes sharing one would not fail, it would quietly
    // answer ancestry questions wrong. The counter is what stops that
    // happening, and this is what stops a future bug in the counter from
    // being silent. The DROP upgrades the non-unique index an earlier
    // build of this table created, and is a no-op afterwards.
    conn.execute_batch(
        "DROP INDEX IF EXISTS change_causal_order_by_group; \
         CREATE UNIQUE INDEX IF NOT EXISTS change_causal_order_unique_ord \
             ON change_causal_order(group_id, admission_ord);",
    )?;
    Ok(())
}

/// The heads a path resolves from: `Gamma`'s heads of `path` -- the path
/// frontier's live heads, or the installed base's heads when nothing
/// written on the base has touched the path.
pub fn path_gamma_heads(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let live = live_path_heads(conn, group_id, path)?;
    if !live.is_empty() {
        return Ok(live);
    }
    Ok(untouched_base_heads(conn, group_id, BaseHeadRange::Exact(path), None)?
        .into_iter()
        .map(|(_, head)| head)
        .collect())
}

/// Which of the installed base's heads [`untouched_base_heads`] reads.
enum BaseHeadRange<'a> {
    Exact(&'a str),
    /// Strictly below `lower`, which ends in `/`; everything for `""`.
    Below(&'a str),
}

/// The installed base's heads, as `(path, head)`, of the paths in `range`
/// that nothing written on the base has touched -- the part of `Gamma` the
/// base still decides. A path the frontier holds any head for, a removal
/// included, is decided by the frontier alone. The summary tables hold
/// only the installed base's rows: every install replaces them.
fn untouched_base_heads(
    conn: &Connection,
    group_id: &str,
    range: BaseHeadRange<'_>,
    limit: Option<usize>,
) -> Result<Vec<(String, PathHead)>, SyncSqliteError> {
    let (lower, upper, exact) = match range {
        BaseHeadRange::Exact(path) => (path.to_owned(), None, true),
        BaseHeadRange::Below(lower) => {
            let upper = lower.strip_suffix('/').map(|dir| format!("{dir}0"));
            (lower.to_owned(), upper, false)
        }
    };
    let mut stmt = conn.prepare_cached(
        "SELECT b.path, b.change_hash, b.device_id, b.lamport, b.version_hash, \
                b.naming_device_id \
         FROM history_base_path_heads b \
         WHERE b.group_id = ?1 \
           AND (CASE WHEN ?4 THEN b.path = ?2 ELSE b.path > ?2 AND (?3 IS NULL OR b.path < ?3) END) \
           AND NOT EXISTS (SELECT 1 FROM path_live_heads h \
                           WHERE h.group_id = b.group_id AND h.path = b.path) \
         ORDER BY b.path, b.change_hash \
         LIMIT ?5",
    )?;
    let limit = limit.map_or(-1, |limit| i64::try_from(limit).unwrap_or(i64::MAX));
    let rows = stmt.query_map(rusqlite::params![group_id, lower, upper, exact, limit], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    let mut heads = Vec::new();
    for row in rows {
        let (path, change_hash, device_id, lamport, version_hash, naming_device_id) = row?;
        heads.push((
            path,
            PathHead {
                change_hash: hash_32(&change_hash, "history_base_path_heads.change_hash")?,
                lamport: u64::try_from(lamport).unwrap_or(0),
                device_id,
                naming_device_id,
                content: Some(PathHeadContent {
                    version_hash: hash_32(&version_hash, "history_base_path_heads.version_hash")?,
                    mtime_unix_nanos: 0,
                }),
            },
        ));
    }
    Ok(heads)
}

/// [`live_heads_by_path`] over `Gamma`: every path's heads, the installed
/// base's where nothing written on the base has touched the path.
pub fn gamma_heads_by_path(
    conn: &Connection,
    group_id: &str,
) -> Result<BTreeMap<String, Vec<PathHead>>, SyncSqliteError> {
    let mut out = live_heads_by_path(conn, group_id)?;
    for (path, head) in untouched_base_heads(conn, group_id, BaseHeadRange::Below(""), None)? {
        out.entry(path).or_default().push(head);
    }
    Ok(out)
}

/// [`live_heads_at_level`] over `Gamma`.
#[allow(clippy::type_complexity)]
pub fn gamma_heads_at_level(
    conn: &Connection,
    group_id: &str,
    parent: &str,
) -> Result<(BTreeMap<String, Vec<PathHead>>, std::collections::BTreeSet<String>), SyncSqliteError>
{
    let (mut children, mut with_live_descendant) = live_heads_at_level(conn, group_id, parent)?;
    let lower = if parent.is_empty() { String::new() } else { format!("{parent}/") };
    for (path, head) in untouched_base_heads(conn, group_id, BaseHeadRange::Below(&lower), None)? {
        match path[lower.len()..].split_once('/') {
            None => children.entry(path).or_default().push(head),
            // Every head a base carries is a content head.
            Some((child, _)) => {
                with_live_descendant.insert(format!("{lower}{child}"));
            }
        }
    }
    Ok((children, with_live_descendant))
}

/// [`has_live_descendant`] over `Gamma`.
pub fn gamma_has_live_descendant(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    if has_live_descendant(conn, group_id, path)? {
        return Ok(true);
    }
    Ok(!untouched_base_heads(conn, group_id, BaseHeadRange::Below(&format!("{path}/")), Some(1))?
        .is_empty())
}

/// The live heads of `path`, ready to hand to `resolve_path_heads`.
///
/// One indexed lookup per table, returning as many rows as the path has
/// live heads -- normally one. No change is decoded, no ancestry is
/// walked, and nothing here is proportional to the group's history.
///
/// Above an installed history base, a path the current epoch has touched
/// also has the base's heads there that no change of the epoch named (see
/// `observed_base_heads`): they are live beside the epoch's own until one
/// is named. A path the epoch has not touched reads as it always has --
/// no live head -- and its heads are the base's, which the rows the base
/// installed already project.
pub fn live_path_heads(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let mut heads = live_epoch_path_heads(conn, group_id, path)?;
    if !heads.is_empty() {
        let base = super::observed_base_heads::unnamed_base_heads_at(conn, group_id, path)?;
        extend_with_base_heads(&mut heads, base);
    }
    Ok(heads)
}

/// Adds the base heads in `base` that `heads` does not already hold.
fn extend_with_base_heads(heads: &mut Vec<PathHead>, base: Vec<PathHead>) {
    for head in base {
        if !heads.iter().any(|held| held.change_hash == head.change_hash) {
            heads.push(head);
        }
    }
}

/// The live heads of `path` written on the current epoch (and, on the
/// group's original history, every live head): the causally maximal
/// changes touching it, without the installed base's heads.
///
/// What a question about the DAG itself reads -- which parents a write
/// cuts, which heads a change closes over by ancestry. A base head is no
/// DAG node, so it has no place in either.
pub(crate) fn live_epoch_path_heads(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<PathHead>, SyncSqliteError> {
    // LEFT JOIN, so a live head whose effect row is missing comes back as
    // a NULL rather than as no row at all. An inner join would drop it
    // from the result, and a path whose only head vanished that way reads
    // as "nothing ever touched this" -- silence, for a row missing from a
    // table nothing outside this module writes. That is the one answer it
    // must not give.
    let mut stmt = conn.prepare_cached(
        "SELECT h.path, h.change_hash, e.effect_kind, e.version_hash, e.lamport, e.device_id, \
                e.naming_device_id \
         FROM path_live_heads h \
         LEFT JOIN change_path_effects e \
           ON e.group_id = h.group_id AND e.path = h.path AND e.change_hash = h.change_hash \
         WHERE h.group_id = ?1 AND h.path = ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![group_id, path])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(live_head_from_row(row, group_id)?.1);
    }
    Ok(out)
}

/// The live heads of every path in the group, by path: the whole input
/// [`yadorilink_replica_engine::namespace::project`] takes. One scan of
/// the group's live heads, failing closed on a missing effect row exactly
/// as [`live_path_heads`] does.
pub fn live_heads_by_path(
    conn: &Connection,
    group_id: &str,
) -> Result<BTreeMap<String, Vec<PathHead>>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT h.path, h.change_hash, e.effect_kind, e.version_hash, e.lamport, e.device_id, \
                e.naming_device_id \
         FROM path_live_heads h \
         LEFT JOIN change_path_effects e \
           ON e.group_id = h.group_id AND e.path = h.path AND e.change_hash = h.change_hash \
         WHERE h.group_id = ?1",
    )?;
    let mut rows = stmt.query([group_id])?;
    let mut out: BTreeMap<String, Vec<PathHead>> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let (path, head) = live_head_from_row(row, group_id)?;
        out.entry(path).or_default().push(head);
    }
    // The installed base's unnamed heads at every touched path, as
    // `live_path_heads` reads them.
    for (path, head) in
        super::observed_base_heads::unnamed_base_heads_in_range(conn, group_id, "", None)?
    {
        if let Some(heads) = out.get_mut(&path) {
            extend_with_base_heads(heads, vec![head]);
        }
    }
    Ok(out)
}

/// One directory level of the group's live heads: the live heads of every
/// path whose parent is `parent` (`""` for the root), and the paths at
/// that level with a live content head strictly below them -- what
/// [`yadorilink_replica_engine::namespace::project_level`] takes.
///
/// One range scan over `parent`'s subtree (the whole group for the root),
/// failing closed on a missing effect row exactly as [`live_path_heads`]
/// does. Heads deeper than the level are not decoded beyond whether they
/// hold content.
#[allow(clippy::type_complexity)]
pub fn live_heads_at_level(
    conn: &Connection,
    group_id: &str,
    parent: &str,
) -> Result<(BTreeMap<String, Vec<PathHead>>, std::collections::BTreeSet<String>), SyncSqliteError>
{
    if parent.ends_with('/') {
        return Err(SyncSqliteError::InvalidInput(format!(
            "level query needs a normalized parent path, got {parent:?}"
        )));
    }
    let (lower, upper) = if parent.is_empty() {
        (String::new(), None)
    } else {
        (format!("{parent}/"), Some(format!("{parent}0")))
    };
    let mut stmt = conn.prepare_cached(
        "SELECT h.path, h.change_hash, e.effect_kind, e.version_hash, e.lamport, e.device_id, \
                e.naming_device_id \
         FROM path_live_heads h \
         LEFT JOIN change_path_effects e \
           ON e.group_id = h.group_id AND e.path = h.path AND e.change_hash = h.change_hash \
         WHERE h.group_id = ?1 AND h.path > ?2 AND (?3 IS NULL OR h.path < ?3)",
    )?;
    let mut rows = stmt.query(rusqlite::params![group_id, lower, upper])?;
    let mut children: BTreeMap<String, Vec<PathHead>> = BTreeMap::new();
    let mut with_live_descendant = std::collections::BTreeSet::new();
    let mut place = |path: String, head: PathHead| {
        let rest = &path[lower.len()..];
        match rest.split_once('/') {
            None => extend_with_base_heads(children.entry(path).or_default(), vec![head]),
            Some((child, _)) => {
                if head.content.is_some() {
                    with_live_descendant.insert(format!("{lower}{child}"));
                }
            }
        }
    };
    while let Some(row) = rows.next()? {
        let (path, head) = live_head_from_row(row, group_id)?;
        place(path, head);
    }
    // The installed base's unnamed heads at the touched paths of the
    // subtree, as `live_path_heads` reads them.
    for (path, head) in super::observed_base_heads::unnamed_base_heads_in_range(
        conn,
        group_id,
        &lower,
        upper.as_deref(),
    )? {
        place(path, head);
    }
    Ok((children, with_live_descendant))
}

/// One `(path, head)` from a `path_live_heads` row LEFT JOINed to its
/// effect, in the column order [`live_path_heads`] selects.
fn live_head_from_row(
    row: &rusqlite::Row<'_>,
    group_id: &str,
) -> Result<(String, PathHead), SyncSqliteError> {
    let path: String = row.get(0)?;
    let hash_bytes: Vec<u8> = row.get(1)?;
    let effect_kind: Option<i64> = row.get(2)?;
    let version_hash: Option<Vec<u8>> = row.get(3)?;
    let lamport: Option<i64> = row.get(4)?;
    let device_id: Option<String> = row.get(5)?;
    let naming_device_id: Option<String> = row.get(6)?;
    let (Some(effect_kind), Some(lamport), Some(device_id), Some(naming_device_id)) =
        (effect_kind, lamport, device_id, naming_device_id)
    else {
        return Err(SyncSqliteError::CorruptState(format!(
            "live head {} for path {path:?} in group {group_id:?} has no recorded path \
             effect; the derived path frontier has diverged from retained history and must \
             be rebuilt",
            ChangeHash(hash_32(&hash_bytes, "path_live_heads.change_hash")?).to_hex()
        )));
    };
    let change_hash = hash_32(&hash_bytes, "change_path_effects.change_hash")?;
    let content = content_from_effect(effect_kind, version_hash)?;
    Ok((
        path,
        PathHead { change_hash, lamport: lamport as u64, device_id, naming_device_id, content },
    ))
}

/// Up to `limit` distinct paths strictly below `path` that currently hold
/// a live content head, in path order.
///
/// "Below" is the namespace relation, not a string prefix: `a/x` is below
/// `a`, while `a-b`, `a.txt` and `a0` are not, although all of them sort
/// between `a` and `a/x` or share its first byte. The range is the
/// half-open byte interval (`path/`, `path0`): `0` is the byte after `/`,
/// so every path of the form `path/...` falls inside and nothing else
/// does. No `LIKE`: `_` and `%` are ordinary file-name characters, and a
/// range over the primary key is an index seek either way.
///
/// A live head whose effect row is missing fails closed exactly as in
/// [`live_path_heads`]: silence here would read as "nothing below", which
/// is the answer that lets a directory be treated as empty.
///
/// Cost: the seek visits the live heads in the range in path order and
/// stops after `limit` distinct content paths, so an answer that exists is
/// cheap. Live removal heads in the range are stepped over one by one, so
/// "nothing below" costs one row per path in the subtree that is still
/// held as a tombstone.
pub fn live_descendant_paths(
    conn: &Connection,
    group_id: &str,
    path: &str,
    limit: usize,
) -> Result<Vec<String>, SyncSqliteError> {
    if path.is_empty() || path.ends_with('/') {
        return Err(SyncSqliteError::InvalidInput(format!(
            "descendant query needs a normalized non-root path, got {path:?}"
        )));
    }
    let lower = format!("{path}/");
    let upper = format!("{path}0");
    let mut stmt = conn.prepare_cached(
        "SELECT h.path, e.effect_kind \
         FROM path_live_heads h \
         LEFT JOIN change_path_effects e \
           ON e.group_id = h.group_id AND e.path = h.path AND e.change_hash = h.change_hash \
         WHERE h.group_id = ?1 AND h.path > ?2 AND h.path < ?3 \
           AND (e.effect_kind = ?4 OR e.effect_kind IS NULL) \
         ORDER BY h.path",
    )?;
    let mut rows = stmt.query(rusqlite::params![group_id, lower, upper, EFFECT_CONTENT])?;
    let mut out: Vec<String> = Vec::new();
    while let Some(row) = rows.next()? {
        let descendant: String = row.get(0)?;
        if row.get::<_, Option<i64>>(1)?.is_none() {
            return Err(SyncSqliteError::CorruptState(format!(
                "a live head of path {descendant:?} in group {group_id:?} has no recorded path \
                 effect; the derived path frontier has diverged from retained history and must \
                 be rebuilt"
            )));
        }
        if out.last() != Some(&descendant) {
            if out.len() == limit {
                break;
            }
            out.push(descendant);
        }
    }
    // A touched path below can also hold content only through a base head
    // no change of the current epoch named. Both lists are in path order,
    // so the first `limit` of their union is among the first `limit` of
    // each.
    let mut base_paths: Vec<String> = Vec::new();
    for (descendant, _) in super::observed_base_heads::unnamed_base_heads_in_range(
        conn,
        group_id,
        &lower,
        Some(&upper),
    )? {
        if base_paths.last() != Some(&descendant) {
            if base_paths.len() == limit {
                break;
            }
            base_paths.push(descendant);
        }
    }
    if !base_paths.is_empty() {
        out.extend(base_paths);
        out.sort();
        out.dedup();
        out.truncate(limit);
    }
    Ok(out)
}

/// Whether anything strictly below `path` currently holds a live content
/// head: the descendant half of whether `path` has to be a directory. See
/// [`live_descendant_paths`].
pub fn has_live_descendant(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    Ok(!live_descendant_paths(conn, group_id, path, 1)?.is_empty())
}

/// The group frontier as it stood without the versions of `path` a writer
/// has not seen: every such live head of `path`, and everything descending
/// from one, cut away, and the causally maximal changes of what remains
/// returned.
///
/// These are the parents for a local write. `seen` is the one version of
/// `path` its author has seen, if any. A live head that is `seen` or an
/// ancestor of it is a version the author wrote over, and the write
/// supersedes it as it should. Any other live head -- a peer's version
/// concurrent with `seen` or built on top of it, or every version when the
/// author has seen none -- is one the author never saw. Signing the write
/// onto the plain frontier would claim it as causal past, and at those
/// parents it is superseded rather than concurrent, so it is never
/// preserved as a conflict copy. Cutting only the live heads themselves is
/// not enough: a later change descending from one -- an edit of another
/// path, say -- would still make the claim transitively. A `seen` that is
/// no longer retained is ancestor of no live head, so every live head is
/// cut: a spurious conflict copy of the author's own older version is
/// recoverable, a superseded version is not.
///
/// `None` when nothing is cut: `path` has no live head, which is the
/// ordinary case for a new path, or every live head is one the author saw,
/// the ordinary case for an edit. The caller signs onto the plain frontier
/// and pays nothing here beyond one indexed lookup (and, with `seen`, one
/// bounded ancestry check per live head). Otherwise the walk is
/// proportional to the changes descending from the cut heads, not to
/// history.
///
/// `Some(vec![])` is a legitimate answer: every retained change descends
/// from a cut head of `path` that is itself a root, as when two devices
/// each start a group by writing the same path. The write is then a root
/// too, concurrent with the other one.
pub(crate) fn frontier_without_unseen_path_heads(
    conn: &Connection,
    group_id: &str,
    path: &str,
    seen: Option<&ChangeHash>,
) -> Result<Option<Vec<ChangeHash>>, SyncSqliteError> {
    let seen: Vec<ChangeHash> = seen.copied().into_iter().collect();
    frontier_without_unseen_heads_of_paths(conn, group_id, &[(path, &seen)])
}

/// [`frontier_without_unseen_path_heads`] for one write that touches
/// several paths at once (one part of a recursive delete or rename): the
/// live heads of every path that are not a version its writer has seen are
/// cut, together with everything descending from them.
///
/// Each path comes with the versions of it the writer has seen. A live head
/// that is one of them, or an ancestor of one, is superseded by the write
/// as it should be; every other live head is kept concurrent with it.
/// `None` when nothing is cut for any path.
pub(crate) fn frontier_without_unseen_heads_of_paths(
    conn: &Connection,
    group_id: &str,
    paths: &[(&str, &[ChangeHash])],
) -> Result<Option<Vec<ChangeHash>>, SyncSqliteError> {
    let mut heads = Vec::new();
    for (path, seen) in paths {
        // The current epoch's heads only: a base head is no DAG node, so
        // it is never cut from a write's parents. Whether a write
        // supersedes one is decided by whether it names it.
        'heads: for head in live_epoch_path_heads(conn, group_id, path)? {
            let head = ChangeHash(head.change_hash);
            for seen in seen.iter() {
                if head == *seen || is_ancestor_bounded(conn, &head, seen)? {
                    continue 'heads;
                }
            }
            heads.push(head);
        }
    }
    if heads.is_empty() {
        return Ok(None);
    }

    // Everything at or above a cut head of `path`. Joined to `changes`
    // so a held orphan, whose ancestry edges are recorded before it is
    // admitted, is never mistaken for part of the retained DAG.
    let mut children = conn.prepare_cached(
        "SELECT p.child_hash FROM change_parents p \
         JOIN changes c ON c.change_hash = p.child_hash \
         WHERE p.parent_hash = ?1 AND c.group_id = ?2",
    )?;
    let mut cut: HashSet<ChangeHash> = HashSet::new();
    let mut pending: Vec<ChangeHash> = heads;
    while let Some(change) = pending.pop() {
        if !cut.insert(change) {
            continue;
        }
        let rows = children.query_map(rusqlite::params![&change.0[..], group_id], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        for row in rows {
            pending.push(ChangeHash(hash_32(&row?, "change_parents.child_hash")?));
        }
    }

    // Every maximal change outside the cut is either a current group head
    // or a parent of something inside it; nothing else can be maximal.
    let mut candidates: Vec<ChangeHash> = super::frontier_index::group_heads(conn, group_id)?
        .into_iter()
        .filter(|head| !cut.contains(head))
        .collect();
    for change in &cut {
        for parent in parents_including_pruned(conn, change)? {
            if !cut.contains(&parent) {
                candidates.push(parent);
            }
        }
    }
    candidates.sort();
    candidates.dedup();

    let mut parents = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let mut covered = false;
        for other in &candidates {
            if is_ancestor_bounded(conn, candidate, other)? {
                covered = true;
                break;
            }
        }
        if !covered {
            parents.push(*candidate);
        }
    }
    Ok(Some(parents))
}

/// Every path's causally maximal CONTENT heads across the whole group, as
/// a history base carries them.
///
/// Content only: a head that removes its path lands nothing, so it is not
/// a member of that path's content-head set. It is still a live head, and
/// it is still what supersedes the writes it descends from — that work has
/// already happened by the time these rows exist, which is why reading
/// them is enough and no ancestry is walked here.
///
/// Nothing is collapsed by `version_hash`. Two devices that wrote
/// identical bytes concurrently are two heads, and a delete descending
/// from only one of them removes only that one; folding them together
/// would lose the other's content with no trace that it existed.
pub(crate) fn live_content_heads_for_group(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<SnapshotPathHead>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT h.path, h.change_hash, e.device_id, c.author_seq, e.lamport, e.version_hash, \
                e.naming_device_id \
         FROM path_live_heads h \
         JOIN change_path_effects e \
           ON e.group_id = h.group_id AND e.path = h.path AND e.change_hash = h.change_hash \
         JOIN changes c ON c.change_hash = h.change_hash \
         WHERE h.group_id = ?1 AND e.effect_kind = ?2 AND e.version_hash IS NOT NULL",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id, EFFECT_CONTENT], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (path, hash, device_id, author_seq, lamport, version_hash, naming_device_id) = row?;
        if author_seq < 1 {
            return Err(SyncSqliteError::CorruptState(format!(
                "live head of path {path:?} in group {group_id:?} is stored at author sequence \
                 {author_seq}, which is not a position in any author chain"
            )));
        }
        out.push(SnapshotPathHead {
            path,
            change_hash: ChangeHash(hash_32(&hash, "path_live_heads.change_hash")?),
            device_id,
            author_seq: AuthorSeq(author_seq as u64),
            lamport: lamport as u64,
            version_hash: VersionHash(hash_32(&version_hash, "change_path_effects.version_hash")?),
            naming_device_id,
        });
    }
    Ok(out)
}

/// Every live head of every path in the group, content and removal alike,
/// as `(path, change)`.
///
/// What a caller needs to know which paths a set of changes has touched at
/// all: a path whose only live head removed it has no content head, but it
/// was still written.
pub(crate) fn live_heads_for_group(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<(String, ChangeHash)>, SyncSqliteError> {
    let mut stmt =
        conn.prepare("SELECT path, change_hash FROM path_live_heads WHERE group_id = ?1")?;
    let rows = stmt
        .query_map([group_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (path, hash) = row?;
        out.push((path, ChangeHash(hash_32(&hash, "path_live_heads.change_hash")?)));
    }
    Ok(out)
}

/// Every retained change in this group that touches `path`, as the heads
/// they would contribute there.
///
/// Unfiltered by any frontier: this is the whole candidate set for the
/// path, which is bounded by how often the path has been written rather
/// than by how much history the group has. Resolving the path against
/// some particular frontier is then a question about this small set,
/// instead of a reason to walk the DAG looking for members of it.
pub(crate) fn effects_touching_path(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT e.change_hash, e.effect_kind, e.version_hash, e.lamport, e.device_id, \
                e.naming_device_id \
         FROM change_path_effects e \
         JOIN changes c ON c.change_hash = e.change_hash \
         WHERE e.group_id = ?1 AND e.path = ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id, path], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (hash_bytes, effect_kind, version_hash, lamport, device_id, naming_device_id) = row?;
        out.push(PathHead {
            change_hash: hash_32(&hash_bytes, "change_path_effects.change_hash")?,
            lamport: lamport as u64,
            device_id,
            naming_device_id,
            content: content_from_effect(effect_kind, version_hash)?,
        });
    }
    Ok(out)
}

/// Whether the stored path effects for one change still say what the
/// change's own signed ops say.
///
/// This is the check that closes the gap the row-shape checks cannot see.
/// They ask whether rows are missing or contradict each other; this asks
/// whether they still match the thing they were derived from. Losing both
/// an effect row and its live-head row together, for instance, leaves a
/// perfectly self-consistent index in which that path simply never
/// existed -- invisible to every structural check, and visible here.
///
/// Cheap because of where it is called from. Startup already decodes
/// every retained change to re-verify it against its own bytes; this runs
/// inside that existing loop, so it adds one indexed lookup and one op
/// scan per change, not a second decode pass.
pub(crate) fn effects_match_change(
    conn: &Connection,
    group_id: &str,
    change: &Change,
) -> Result<bool, SyncSqliteError> {
    let hash = change.compute_hash();
    let mut stmt = conn.prepare_cached(
        "SELECT path, effect_kind, version_hash, lamport, device_id, naming_device_id \
         FROM change_path_effects WHERE group_id = ?1 AND change_hash = ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id, &hash.0[..]], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    /// `(effect_kind, version_hash, lamport, device_id, naming_device_id)`.
    type StoredEffect = (i64, Option<Vec<u8>>, i64, String, String);
    let mut stored: HashMap<String, StoredEffect> = HashMap::new();
    for row in rows {
        let (path, kind, version, lamport, device, naming) = row?;
        stored.insert(path, (kind, version, lamport, device, naming));
    }

    let expected = path_effects_of_change(change);
    if expected.len() != stored.len() {
        return Ok(false);
    }
    for (path, head) in expected {
        let Some((kind, version, lamport, device, naming)) = stored.remove(&path) else {
            return Ok(false);
        };
        let (want_kind, want_version) = match &head.content {
            Some(content) => (EFFECT_CONTENT, Some(content.version_hash.to_vec())),
            None => (EFFECT_REMOVAL, None),
        };
        if kind != want_kind
            || version != want_version
            || lamport != head.lamport as i64
            || device != head.device_id
            || naming != head.naming_device_id
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `ancestor` is a strict ancestor of `descendant`, both already
/// admitted, decided without a walk proportional to the group's history.
///
/// The same three steps admission uses, against a descendant read from
/// the store rather than one being admitted right now: reject on lamport,
/// accept from the spine ordinal, and otherwise walk only the divergence
/// window above that ordinal. See this module's own doc comment for why
/// each step is sound.
///
/// Answers conservatively when it cannot place one of the two: a change
/// with no recorded ordinal falls through to the walk rather than being
/// guessed about.
pub(crate) fn is_ancestor_bounded(
    conn: &Connection,
    ancestor: &ChangeHash,
    descendant: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    if ancestor == descendant {
        return Ok(false);
    }
    let (Some(ancestor_lamport), Some(descendant_lamport)) =
        (lamport_including_pruned(conn, ancestor)?, lamport_including_pruned(conn, descendant)?)
    else {
        return Ok(false);
    };
    if ancestor_lamport >= descendant_lamport {
        return Ok(false);
    }
    let spine_floor = match causal_order_of(conn, descendant)? {
        Some((_, spine_ord)) => spine_ord,
        None => 0,
    };
    if spine_floor > 0 {
        if let Some((ancestor_ord, _)) = causal_order_of(conn, ancestor)? {
            if ancestor_ord <= spine_floor {
                return Ok(true);
            }
        }
    }
    let seeds = parents_including_pruned(conn, descendant)?;
    walk_reaches(conn, ancestor, ancestor_lamport, seeds, spine_floor)
}

/// The backward walk shared by both ancestry decisions: from `seeds`,
/// looking for `candidate`, pruning every branch that provably can no
/// longer reach it.
fn walk_reaches(
    conn: &Connection,
    candidate: &ChangeHash,
    candidate_lamport: u64,
    seeds: Vec<ChangeHash>,
    spine_floor: i64,
) -> Result<bool, SyncSqliteError> {
    let mut seen: HashSet<ChangeHash> = HashSet::new();
    let mut queue: VecDeque<ChangeHash> = seeds.into_iter().collect();
    while let Some(node) = queue.pop_front() {
        if node == *candidate {
            return Ok(true);
        }
        if !seen.insert(node) {
            continue;
        }
        let Some(node_lamport) = lamport_including_pruned(conn, &node)? else {
            continue;
        };
        if node_lamport <= candidate_lamport {
            continue;
        }
        if spine_floor > 0 {
            match causal_order_of(conn, &node)? {
                Some((node_ord, _)) if node_ord <= spine_floor => continue,
                _ => {}
            }
        }
        for parent in parents_including_pruned(conn, &node)? {
            if !seen.contains(&parent) {
                queue.push_back(parent);
            }
        }
    }
    Ok(false)
}

/// Records everything derived from `change` the moment it is admitted:
/// its normalized path effects, its place in the local admission order,
/// and the resulting movement of every touched path's live frontier.
///
/// Must be called on the same connection, inside the same transaction,
/// and *after* the caller has updated `group_heads` for this change --
/// the whole-frontier test in step 1 of this module's doc comment reads
/// the post-admission head set, and would otherwise see the pre-admission
/// one and decide the opposite.
pub(crate) fn record_admission(
    conn: &Connection,
    change: &Change,
    hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    let group_id = change.group_id.as_str();
    let admission_ord = next_admission_ord(conn, group_id)?;

    // Inherited from the parents, and therefore strictly older than this
    // change: the spine point this change is being measured against must
    // never be the change itself, or a head equal to it would read as its
    // own ancestor.
    let mut parent_spine_ord: i64 = 0;
    for parent in &change.parents {
        if let Some((_, spine)) = causal_order_of(conn, parent)? {
            parent_spine_ord = parent_spine_ord.max(spine);
        }
    }

    // A group left with a single head has nothing unsuperseded besides
    // that head, so this change is now an ancestor of everything admitted
    // after it and a descendant of everything admitted before it. Counting
    // heads is also exactly the whole-frontier test: the group ends up
    // single-headed precisely when this change's parents covered every
    // head it had.
    let head_count: i64 = conn
        .prepare_cached("SELECT COUNT(*) FROM group_heads WHERE group_id = ?1")?
        .query_row(rusqlite::params![group_id], |row| row.get(0))?;
    let covers_whole_frontier = head_count == 1;
    let spine_ord = if covers_whole_frontier { admission_ord } else { parent_spine_ord };

    conn.prepare_cached(
        "INSERT OR REPLACE INTO change_causal_order \
         (change_hash, group_id, admission_ord, spine_ord) VALUES (?1, ?2, ?3, ?4)",
    )?
    .execute(rusqlite::params![&hash.0[..], group_id, admission_ord, spine_ord])?;

    for (path, head) in path_effects_of_change(change) {
        record_effect(conn, group_id, &path, &head)?;
        advance_path_frontier(
            conn,
            group_id,
            &path,
            change,
            hash,
            covers_whole_frontier,
            parent_spine_ord,
        )?;
    }
    // The installed base's heads leave the live frontier only by being
    // named, never by ancestry: `advance_path_frontier` sees the current
    // epoch's heads alone.
    super::observed_base_heads::record_naming(conn, change)?;
    Ok(())
}

/// Persists one normalized path effect. `INSERT OR REPLACE` rather than
/// `INSERT OR IGNORE`: re-admitting the identical change must be a no-op
/// either way, but a row that somehow disagrees with the change it is
/// derived from should be corrected, not preserved.
fn record_effect(
    conn: &Connection,
    group_id: &str,
    path: &str,
    head: &PathHead,
) -> Result<(), SyncSqliteError> {
    let (effect_kind, version_hash) = match &head.content {
        Some(content) => (EFFECT_CONTENT, Some(content.version_hash.to_vec())),
        None => (EFFECT_REMOVAL, None),
    };
    let mut stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO change_path_effects \
         (group_id, path, change_hash, effect_kind, version_hash, lamport, device_id, \
          naming_device_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    stmt.execute(rusqlite::params![
        group_id,
        path,
        &head.change_hash[..],
        effect_kind,
        version_hash,
        head.lamport as i64,
        head.device_id.as_str(),
        head.naming_device_id.as_str(),
    ])?;
    Ok(())
}

/// Moves one path's live frontier to account for `change` touching it.
fn advance_path_frontier(
    conn: &Connection,
    group_id: &str,
    path: &str,
    change: &Change,
    hash: &ChangeHash,
    covers_whole_frontier: bool,
    parent_spine_ord: i64,
) -> Result<(), SyncSqliteError> {
    if covers_whole_frontier {
        // Every live head of this path was reachable from some group head,
        // and this change's parents covered all of them -- so all of them
        // are in its causal past, with nothing left to decide per head.
        conn.prepare_cached("DELETE FROM path_live_heads WHERE group_id = ?1 AND path = ?2")?
            .execute(rusqlite::params![group_id, path])?;
    } else {
        let existing = live_head_hashes(conn, group_id, path)?;
        for existing_hash in existing {
            if existing_hash == *hash {
                continue;
            }
            if is_ancestor_of_admitted(conn, &existing_hash, change, parent_spine_ord)? {
                conn.prepare_cached(
                    "DELETE FROM path_live_heads \
                     WHERE group_id = ?1 AND path = ?2 AND change_hash = ?3",
                )?
                .execute(rusqlite::params![
                    group_id,
                    path,
                    &existing_hash.0[..]
                ])?;
            }
        }
    }
    conn.prepare_cached(
        "INSERT OR IGNORE INTO path_live_heads (group_id, path, change_hash) \
         VALUES (?1, ?2, ?3)",
    )?
    .execute(rusqlite::params![group_id, path, &hash.0[..]])?;
    Ok(())
}

/// Whether `candidate` is an ancestor of `admitted`, which is being
/// admitted right now.
///
/// Correct only under that precondition, and it is what makes the answer
/// cheap: a change is admitted only once every one of its parents already
/// is, so at this moment every ancestor of `admitted` is present and
/// `admitted` is an ancestor of nothing. The question is therefore purely
/// backward-looking.
///
/// See this module's doc comment for why none of the three steps below is
/// proportional to the group's history length.
fn is_ancestor_of_admitted(
    conn: &Connection,
    candidate: &ChangeHash,
    admitted: &Change,
    parent_spine_ord: i64,
) -> Result<bool, SyncSqliteError> {
    // Lamport strictly increases along every parent edge, so an ancestor's
    // is always strictly smaller. Settles every unrelated pair for the
    // cost of one lookup.
    // A live head is by construction an admitted change, so both of these
    // exist for any candidate this is asked about. A missing one means the
    // derived tables have lost rows relative to the history they are
    // derived from, and there is no safe guess available here: answering
    // "not an ancestor" would leave a superseded head live and invent a
    // conflict where none exists, and answering "ancestor" would drop a
    // head that should have stayed and lose content. Fail, and let the
    // rebuild at startup put the group back.
    let Some((candidate_ord, _)) = causal_order_of(conn, candidate)? else {
        return Err(SyncSqliteError::CorruptState(format!(
            "live path head {} has no admission ordinal; the derived path frontier has \
             diverged from retained history and must be rebuilt",
            candidate.to_hex()
        )));
    };
    let Some(candidate_lamport) = lamport_including_pruned(conn, candidate)? else {
        return Err(SyncSqliteError::CorruptState(format!(
            "live path head {} is not a retained change; the derived path frontier has \
             diverged from retained history and must be rebuilt",
            candidate.to_hex()
        )));
    };
    if candidate_lamport >= admitted.lamport {
        return Ok(false);
    }

    // At or below the most recent single-head point in the admitted
    // change's own causal past: that point is an ancestor of the admitted
    // change, and everything ordered at or before it is an ancestor of
    // that point.
    if parent_spine_ord > 0 && candidate_ord <= parent_spine_ord {
        return Ok(true);
    }

    // Whatever is left lies inside the group's divergence window. Walk it,
    // pruning at the spine ordinal (anything at or below it is an ancestor
    // of the spine point, which the candidate is not) and at the
    // candidate's own lamport (a lower lamport can no longer reach it).
    //
    // The walk crosses compacted history, because compaction does not
    // remove a clean causal prefix: a retention root keeps one change
    // alive while the changes below it go, so a still-retained candidate
    // can sit on the far side of a pruned change from the one being
    // admitted. Following only live edges would make those two look
    // causally unrelated, and a genuinely superseded head would come back
    // to life next to its own descendant -- stale content resurfacing as
    // a conflict, triggered by a prune that touched neither of them. The
    // tombstones exist for exactly this: a pruned change keeps its
    // lamport and every ancestry edge that touched it.
    walk_reaches(conn, candidate, candidate_lamport, admitted.parents.clone(), parent_spine_ord)
}

/// A change's parents across the compaction boundary: live ancestry
/// edges and the tombstoned ones a prune left behind, unioned exactly the
/// way `is_ancestor` unions them.
///
/// No join back to `changes`. An admitted change's parents are themselves
/// admitted or tombstoned -- startup enforces that -- so every hash this
/// returns is a real node, and requiring a live row would silently drop
/// the pruned bridges this exists to cross.
fn parents_including_pruned(
    conn: &Connection,
    child: &ChangeHash,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT parent_hash FROM change_parents WHERE child_hash = ?1 \
         UNION \
         SELECT parent_hash FROM pruned_change_parents WHERE child_hash = ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![&child.0[..]], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(ChangeHash(hash_32(&row?, "change_parents.parent_hash")?));
    }
    Ok(out)
}

fn live_head_hashes(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT change_hash FROM path_live_heads WHERE group_id = ?1 AND path = ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id, path], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(ChangeHash(hash_32(&row?, "path_live_heads.change_hash")?));
    }
    Ok(out)
}

fn causal_order_of(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<Option<(i64, i64)>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT admission_ord, spine_ord FROM change_causal_order WHERE change_hash = ?1",
    )?;
    let mut rows = stmt.query(rusqlite::params![&hash.0[..]])?;
    match rows.next()? {
        Some(row) => Ok(Some((row.get(0)?, row.get(1)?))),
        None => Ok(None),
    }
}

/// A change's lamport, whether it is still retained or has been compacted
/// away.
///
/// The walk uses this to prune branches that can no longer reach the
/// candidate, and it has to work on a pruned bridge too -- a tombstone
/// keeps its lamport for precisely this. Reading only live rows would
/// make every pruned node look unknown, and the walk would stop at the
/// first one rather than crossing it.
fn lamport_including_pruned(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<Option<u64>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT lamport FROM changes WHERE change_hash = ?1 \
         UNION ALL \
         SELECT lamport FROM pruned_changes WHERE change_hash = ?1 \
         LIMIT 1",
    )?;
    let mut rows = stmt.query(rusqlite::params![&hash.0[..]])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get::<_, i64>(0)? as u64)),
        None => Ok(None),
    }
}

/// Hands out this group's next admission ordinal.
///
/// The ordinal must be a genuine linear extension of the DAG on this
/// device, so it must never be reused. Two things could make it
/// reused, and neither is allowed to pass quietly:
///
/// `optional`, not `.ok()`, because a genuine query failure read as
/// "this group has no counter yet" would restart numbering from 1.
///
/// And a counter row that is simply *absent* means "no admission has
/// happened for this group" only if nothing has been ordered for it yet.
/// If `change_causal_order` already holds rows for the group, the absence
/// is a lost row, and starting again from 1 would hand out ordinals that
/// are already in use -- which does not fail, it silently answers later
/// ancestry questions wrong. That is corruption, and it is reported as
/// corruption; startup rebuilds the group and restores the counter with
/// it.
fn next_admission_ord(conn: &Connection, group_id: &str) -> Result<i64, SyncSqliteError> {
    let current: Option<i64> = conn
        .prepare_cached("SELECT next_ord FROM group_admission_ord WHERE group_id = ?1")?
        .query_row(rusqlite::params![group_id], |row| row.get(0))
        .optional()?;
    let ord = match current {
        Some(ord) => ord,
        None => {
            let already_ordered: i64 = conn
                .prepare_cached("SELECT COUNT(*) FROM change_causal_order WHERE group_id = ?1")?
                .query_row(rusqlite::params![group_id], |row| row.get(0))?;
            if already_ordered > 0 {
                return Err(SyncSqliteError::CorruptState(format!(
                    "group {group_id:?} has {already_ordered} ordered changes but no admission \
                     counter; restarting it would reissue ordinals already in use, so the \
                     derived path frontier must be rebuilt"
                )));
            }
            1
        }
    };
    conn.prepare_cached(
        "INSERT OR REPLACE INTO group_admission_ord (group_id, next_ord) VALUES (?1, ?2)",
    )?
    .execute(rusqlite::params![group_id, ord + 1])?;
    Ok(ord)
}

/// One stored effect row's content half: the version it lands, or
/// `None` when it removes the path.
fn content_from_effect(
    effect_kind: i64,
    version_hash: Option<Vec<u8>>,
) -> Result<Option<PathHeadContent>, SyncSqliteError> {
    match effect_kind {
        EFFECT_CONTENT => {
            let bytes = version_hash.ok_or_else(|| {
                SyncSqliteError::CorruptState(
                    "change_path_effects row lands content but has no version_hash".to_string(),
                )
            })?;
            Ok(Some(PathHeadContent {
                version_hash: hash_32(&bytes, "change_path_effects.version_hash")?,
                // The per-path fold this normalizes stamps a fixed 0 here;
                // a head's real mtime lives in the file version resolved
                // on the content path.
                mtime_unix_nanos: 0,
            }))
        }
        EFFECT_REMOVAL => Ok(None),
        other => Err(SyncSqliteError::CorruptState(format!(
            "change_path_effects.effect_kind was {other}, expected 0 or 1"
        ))),
    }
}

fn hash_32(bytes: &[u8], what: &str) -> Result<[u8; 32], SyncSqliteError> {
    bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!("{what} had {} bytes, expected 32", bytes.len()))
    })
}

/// Forgets everything derived for `hash`. Called when a change leaves
/// retained history -- compaction, or a rebootstrap that discards a prior
/// history base.
///
/// A path whose last live head is dropped this way resolves as untouched,
/// which is the same answer the walk this module replaced gave for a
/// pruned change: it was unreachable from the group's heads and so was
/// never a candidate. Compaction is responsible for not pruning content
/// that is still needed; that has not changed.
pub(crate) fn forget_change(conn: &Connection, hash: &ChangeHash) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM path_live_heads WHERE change_hash = ?1",
        rusqlite::params![&hash.0[..]],
    )?;
    conn.execute(
        "DELETE FROM change_path_effects WHERE change_hash = ?1",
        rusqlite::params![&hash.0[..]],
    )?;
    conn.execute(
        "DELETE FROM change_causal_order WHERE change_hash = ?1",
        rusqlite::params![&hash.0[..]],
    )?;
    Ok(())
}

/// Rebuilds every derived row for `group_id` from retained history alone.
///
/// This is what makes the two tables genuinely derived rather than a
/// second source of truth: it is the migration for a database that
/// predates them, the repair for one whose rows were lost or never
/// written, and the way a rebootstrap re-derives a group after replacing
/// its history wholesale.
///
/// It replays admission in a deterministic topological order -- ascending
/// `(lamport, change_hash)`, which is a valid one because lamport strictly
/// increases along every parent edge -- and runs each change through the
/// same frontier update ordinary admission runs. The replay therefore
/// cannot disagree with incremental maintenance: there is only one
/// implementation of the rule, used twice.
///
/// The admission ordinals it assigns are not the ones the original live
/// admissions used, and are not meant to be. They only have to be a
/// linear extension of the DAG on this device, which any topological
/// replay is.
pub fn rebuild_group(conn: &Connection, group_id: &str) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM path_live_heads WHERE group_id = ?1", rusqlite::params![group_id])?;
    conn.execute(
        "DELETE FROM change_path_effects WHERE group_id = ?1",
        rusqlite::params![group_id],
    )?;
    conn.execute(
        "DELETE FROM change_causal_order WHERE group_id = ?1",
        rusqlite::params![group_id],
    )?;
    conn.execute(
        "DELETE FROM group_admission_ord WHERE group_id = ?1",
        rusqlite::params![group_id],
    )?;
    super::observed_base_heads::clear_derived_naming(conn, group_id)?;

    let ordered = retained_changes_in_topological_order(conn, group_id)?;

    // The replay's own view of the frontier. `record_admission` reads
    // `group_heads` for the whole-frontier test, and that table already
    // holds the group's *final* head set here rather than its head set
    // partway through the replay -- so the test is evaluated from this
    // in-memory frontier instead and handed in.
    let mut heads: HashSet<ChangeHash> = HashSet::new();
    let mut spine_by_hash: HashMap<ChangeHash, i64> = HashMap::new();
    let mut next_ord: i64 = 1;

    for change in &ordered {
        let hash = change.compute_hash();
        for parent in &change.parents {
            heads.remove(parent);
        }
        heads.insert(hash);

        let admission_ord = next_ord;
        next_ord += 1;
        let parent_spine_ord = change
            .parents
            .iter()
            .filter_map(|parent| spine_by_hash.get(parent).copied())
            .max()
            .unwrap_or(0);
        let covers_whole_frontier = heads.len() == 1;
        let spine_ord = if covers_whole_frontier { admission_ord } else { parent_spine_ord };
        spine_by_hash.insert(hash, spine_ord);

        conn.execute(
            "INSERT OR REPLACE INTO change_causal_order \
             (change_hash, group_id, admission_ord, spine_ord) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&hash.0[..], group_id, admission_ord, spine_ord],
        )?;

        for (path, head) in path_effects_of_change(change) {
            record_effect(conn, group_id, &path, &head)?;
            advance_path_frontier(
                conn,
                group_id,
                &path,
                change,
                &hash,
                covers_whole_frontier,
                parent_spine_ord,
            )?;
        }
        // Recorded afresh: the record was cleared above except for the
        // names pruned changes recorded, which still supersede their base
        // heads and go with the base when the next epoch reset replaces it.
        super::observed_base_heads::record_naming(conn, change)?;
    }

    conn.execute(
        "INSERT OR REPLACE INTO group_admission_ord (group_id, next_ord) VALUES (?1, ?2)",
        rusqlite::params![group_id, next_ord],
    )?;
    Ok(())
}

fn retained_changes_in_topological_order(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<Change>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT encoded FROM changes WHERE group_id = ?1 ORDER BY lamport ASC, change_hash ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let encoded = row?;
        let change = Change::from_wire_bytes(&encoded).map_err(|e| {
            SyncSqliteError::CorruptState(format!(
                "retained change in group {group_id} could not be decoded while rebuilding the \
                 path frontier: {e}"
            ))
        })?;
        out.push(change);
    }
    Ok(out)
}

/// Every group whose derived path state does not hold up against
/// canonical history, and so has to be rebuilt from it.
///
/// The invariant being defended is that `path_live_heads` holds exactly
/// the causally maximal touchers of each path. Checking that directly
/// means recomputing it, which is the rebuild -- too expensive to run on
/// every startup. What runs instead is a set of consequences of the
/// invariant, each of which is a cheap indexed query, and which together
/// catch every way a row has actually been observed to go wrong:
///
/// 1. **A group with history but no effects at all.** A change that
///    touched no path could not have been emitted, so this means the
///    index was never built -- a database predating these tables -- or
///    was lost wholesale.
/// 2. **A path with retained effects but no live head.** The touchers of
///    a path are a finite non-empty set, so they always have at least one
///    maximal element. No live head for a path something still touches is
///    proof a row was lost.
/// 3. **A live head with no effect row.** Resolving a path joins the two;
///    a head missing its effect cannot be resolved at all.
/// 4. **A live head naming a change that is not retained.** It can never
///    resolve, and nothing will ever supersede it.
/// 5. **A retained change with no admission ordinal.** Not a dormant
///    inconsistency: admission fails closed on a live head without one,
///    so this is a future admission that cannot complete.
/// 6. **An ordinal at or beyond the group's next.** The next admission
///    would reuse it. Catches a counter row that went missing or
///    backwards, which would silently corrupt every later ancestry
///    shortcut rather than fail.
/// 7. **A live head another live head descends from.** The ancestor was
///    never maximal, so it should not be recorded. Costs an ancestry
///    query only for paths recording more than one head, which is the
///    conflicted minority; a path at the usual width of one costs
///    nothing.
/// 8. **A named base head no change accounts for.** A row in
///    `history_base_named_heads` whose naming change is neither retained
///    nor pruned, or that names a head the installed base does not carry
///    at its path, buries a live base head for good. (Whether each
///    retained change's rows match its signed names is checked with its
///    path effects, in the pass that already decodes it.)
///
/// Check 2 is the one that matters most and the one an earlier version of
/// this function got wrong. It anchored on `group_heads` instead --
/// validating only the effects of changes that are *currently* group
/// heads. But a path's live head is normally not a group head: the group
/// moves on, later changes touch other paths, and the change that last
/// wrote this path falls behind the frontier while remaining perfectly
/// live for it. On a 10,000-file import that check inspected one change
/// out of ten thousand, and a row lost anywhere else was never noticed --
/// the path resolved as absent, silently, forever.
///
/// What is deliberately NOT checked is whether an effect row's *contents*
/// still match the ops of the change it was derived from. Verifying that
/// means decoding every retained change and re-deriving its effects,
/// which is exactly the history-length decode cost this index exists to
/// remove, reintroduced on the startup path where it would hurt most. The
/// signed change remains authoritative and is already re-verified against
/// its own bytes by the retained-history repair that runs just before
/// this; what is not re-derived here is the projection of those verified
/// bytes. A future integrity sweep that wants that guarantee should run
/// out of band, not at every open.
///
/// No check tries to identify which rows are wrong or to mend them in
/// place. A derived index caught disagreeing with its source has no
/// credible partial state to preserve; rebuilding the group from
/// canonical history is both simpler and the only answer certainly right.
pub(crate) fn groups_needing_rebuild(conn: &Connection) -> Result<Vec<String>, SyncSqliteError> {
    let mut groups: Vec<String> = Vec::new();
    let note = |group_id: String, groups: &mut Vec<String>| {
        if !groups.contains(&group_id) {
            groups.push(group_id);
        }
    };

    for sql in [
        // 1. History, but no derived effects at all.
        "SELECT DISTINCT c.group_id FROM changes c \
         WHERE NOT EXISTS (SELECT 1 FROM change_path_effects e WHERE e.group_id = c.group_id)",
        // 2. A path something retained still touches, with no live head.
        "SELECT DISTINCT e.group_id FROM change_path_effects e \
         JOIN changes c ON c.change_hash = e.change_hash \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM path_live_heads l \
             WHERE l.group_id = e.group_id AND l.path = e.path)",
        // 3. A live head with no effect row to resolve it from.
        "SELECT DISTINCT l.group_id FROM path_live_heads l \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM change_path_effects e \
             WHERE e.group_id = l.group_id AND e.path = l.path \
               AND e.change_hash = l.change_hash)",
        // 4. A live head naming a change that is no longer retained.
        "SELECT DISTINCT l.group_id FROM path_live_heads l \
         WHERE NOT EXISTS (SELECT 1 FROM changes c WHERE c.change_hash = l.change_hash)",
        // 5. A retained change with no admission ordinal.
        "SELECT DISTINCT c.group_id FROM changes c \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM change_causal_order o WHERE o.change_hash = c.change_hash)",
        // 6. Ordinals issued at or beyond what the counter will hand out
        // next, which means the next admission would reuse one. Covers a
        // counter row that went missing entirely as well as one that
        // went backwards.
        "SELECT DISTINCT o.group_id FROM change_causal_order o \
         WHERE o.admission_ord >= COALESCE( \
             (SELECT g.next_ord FROM group_admission_ord g WHERE g.group_id = o.group_id), 0)",
        // 8. A named base head no retained or pruned change accounts for.
        super::observed_base_heads::UNACCOUNTED_NAMING_SQL,
    ] {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            note(row?, &mut groups);
        }
    }

    // 7. Supersession among the heads a path actually records. Only paths
    // recording more than one are considered, so a converged path costs a
    // row in this scan and no ancestry query at all.
    let mut contested = conn.prepare(
        "SELECT group_id, path FROM path_live_heads \
         GROUP BY group_id, path HAVING COUNT(*) > 1",
    )?;
    let rows =
        contested.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    let contested: Vec<(String, String)> = rows.collect::<Result<_, _>>()?;
    for (group_id, path) in contested {
        if groups.contains(&group_id) {
            continue;
        }
        let heads = live_head_hashes(conn, &group_id, &path)?;
        let mut superseded = false;
        'pairs: for candidate in &heads {
            for other in &heads {
                if other == candidate {
                    continue;
                }
                if super::retained_history_integrity::is_ancestor(conn, candidate, other)? {
                    superseded = true;
                    break 'pairs;
                }
            }
        }
        if superseded {
            note(group_id, &mut groups);
        }
    }

    Ok(groups)
}
