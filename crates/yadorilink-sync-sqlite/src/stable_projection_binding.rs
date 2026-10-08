//! Stable projection binding: once a head becomes a loser at a path (the
//! pure resolver, `native_materialize::project`/`project_own_node`, places
//! it as a conflict-copy rather than at its own path), its visible path is
//! fixed and must never change as a side effect of a DIFFERENT head's own
//! action (the winner's own later rename/delete). This is presentation
//! state -- exactly the same kind conflict-copy filename disambiguation
//! already is -- held here, at the file-index/materialization integration
//! layer, never inside `NativeState`'s causal model.
//!
//! A head is identified by its `Dot` (`author: AuthorId, seq: AuthorSeq`).
//!
//! **The identity a binding is keyed by includes its own source path**,
//! not just the head's Dot alone. Every op in one `NativeDelta` shares one
//! Dot, so the SAME Dot can become a loser at TWO DIFFERENT paths in one
//! delta, each needing its OWN, independent stable path. Keying by identity
//! alone would let the two collide (one overwriting or masking the other)
//! and would let a stale binding at a since-vacated path survive GC merely
//! because the SAME identity is still live at some OTHER path.
//!
//! A binding row is written the first time its (path, head) pair is
//! observed as a loser. A row outlives its head: the dead binding keeps
//! reserving its name. Rows are read by level
//! ([`native_bindings_in_levels`]), so their number does not slow a plan; a
//! recovery bundle carries only the rows of live heads.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::native_resolver::PlacementOrigin;
use yadorilink_replica_engine::native_snapshot::NativeKeptHead;

use crate::error::SyncSqliteError;
use crate::native_store::as_array32;

/// Per-thread counts of placement and binding rows read by the level readers,
/// for tests that pin that planning a level reads that level's rows only.
/// Compiled out of production builds.
#[cfg(any(test, feature = "test-support"))]
pub mod level_row_counters {
    use std::cell::Cell;

    thread_local! {
        static PLACEMENTS: Cell<u64> = const { Cell::new(0) };
        static BINDINGS: Cell<u64> = const { Cell::new(0) };
    }

    /// Zeroes this thread's counters.
    pub fn reset() {
        PLACEMENTS.with(|c| c.set(0));
        BINDINGS.with(|c| c.set(0));
    }

    /// `(placement rows, binding rows)` read since the last [`reset`].
    pub fn snapshot() -> (u64, u64) {
        (PLACEMENTS.with(Cell::get), BINDINGS.with(Cell::get))
    }

    pub(crate) fn placement() {
        PLACEMENTS.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn binding() {
        BINDINGS.with(|c| c.set(c.get() + 1));
    }
}

#[cfg(any(test, feature = "test-support"))]
use level_row_counters::{
    binding as count_binding_row_read, placement as count_placement_row_read,
};
#[cfg(not(any(test, feature = "test-support")))]
fn count_binding_row_read() {}
#[cfg(not(any(test, feature = "test-support")))]
fn count_placement_row_read() {}

/// Creates the stable-projection-binding tables on `conn`.
pub fn init_stable_projection_binding_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS native_stable_projection_binding (
            group_id     TEXT NOT NULL,
            source_path  TEXT NOT NULL,
            author       TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            seq          INTEGER NOT NULL,
            stable_path  TEXT NOT NULL,
            -- The directory level each path lives on (`""` for the root): a
            -- level's plan reads the names of its own level only.
            source_parent  TEXT NOT NULL,
            stable_parent  TEXT NOT NULL,
            PRIMARY KEY (group_id, source_path, author, incarnation, seq)
        );

        -- The reverse direction (physical path -> identity), for
        -- capture/write-through's `resolve_*_physical_path`: given a
        -- literal path a filesystem event names, is it a currently-bound
        -- conflict-copy, and if so, of what? A binding's `stable_path` is
        -- unique per group by construction (assignment always checks for
        -- an occupied name before binding), so this is a point lookup, not
        -- a scan.
        -- Physical placement: what the index row at a physical path shows,
        -- by exact identity. Unlike a stable-name binding it lives as long
        -- as the physical row does (see `native_projection_binding`), not
        -- as long as the head is live.
        CREATE TABLE IF NOT EXISTS native_physical_placement (
            group_id      TEXT NOT NULL,
            physical_path TEXT NOT NULL,
            source_path   TEXT NOT NULL,
            author        TEXT NOT NULL,
            incarnation   BLOB NOT NULL,
            seq           INTEGER NOT NULL,
            provenance    BLOB NOT NULL,
            version       BLOB NOT NULL,
            origin        TEXT NOT NULL,
            -- The directory level each path lives on (`""` for the root).
            physical_parent  TEXT NOT NULL,
            source_parent    TEXT NOT NULL,
            PRIMARY KEY (group_id, physical_path)
        );

        CREATE INDEX IF NOT EXISTS native_stable_projection_binding_by_stable_path
            ON native_stable_projection_binding (group_id, stable_path);
        CREATE INDEX IF NOT EXISTS native_stable_projection_binding_by_source_parent
            ON native_stable_projection_binding (group_id, source_parent);
        CREATE INDEX IF NOT EXISTS native_stable_projection_binding_by_stable_parent
            ON native_stable_projection_binding (group_id, stable_parent);
        CREATE INDEX IF NOT EXISTS native_physical_placement_by_physical_parent
            ON native_physical_placement (group_id, physical_parent);
        CREATE INDEX IF NOT EXISTS native_physical_placement_by_source_parent
            ON native_physical_placement (group_id, source_parent);
        -- The copies of one source path: asked for by every edit and every
        -- settlement of that path.
        CREATE INDEX IF NOT EXISTS native_physical_placement_by_source
            ON native_physical_placement (group_id, source_path);
        "#,
    )?;
    Ok(())
}

/// One native head's identity, scoped to the path it names: `(source
/// path, author device, incarnation, seq)`.
pub type NativeHeadIdentity = (String, String, [u8; 16], u64);

/// Every native stable-projection binding currently recorded for `group_id`.
pub fn native_bindings(
    conn: &Connection,
    group_id: &str,
) -> Result<BTreeMap<NativeHeadIdentity, String>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT source_path, author, incarnation, seq, stable_path FROM native_stable_projection_binding \
         WHERE group_id = ?1",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        let path: String = row.get(0)?;
        let author: String = row.get(1)?;
        let incarnation: Vec<u8> = row.get(2)?;
        let seq: i64 = row.get(3)?;
        let stable_path: String = row.get(4)?;
        Ok((path, author, incarnation, seq, stable_path))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (path, author, incarnation, seq, stable_path) = row?;
        let incarnation: [u8; 16] = as_array16(&incarnation)?;
        out.insert((path, author, incarnation, seq as u64), stable_path);
    }
    Ok(out)
}

/// Records a NEW native binding. A no-op if one already exists.
pub fn native_bind(
    conn: &Connection,
    group_id: &str,
    identity: &NativeHeadIdentity,
    stable_path: &str,
) -> Result<(), SyncSqliteError> {
    let (path, author, incarnation, seq) = identity;
    conn.execute(
        "INSERT OR IGNORE INTO native_stable_projection_binding \
         (group_id, source_path, author, incarnation, seq, stable_path, source_parent, \
          stable_parent) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            group_id,
            path,
            author,
            incarnation.as_slice(),
            *seq as i64,
            stable_path,
            parent_of(path),
            parent_of(stable_path)
        ],
    )?;
    Ok(())
}

/// Every native binding of `group_id` whose head is a live head, the facts a
/// recovery bundle carries. A dead binding still reserves its name locally but is
/// not part of what a checkpoint commits to.
pub fn native_live_bindings(
    conn: &Connection,
    group_id: &str,
) -> Result<BTreeMap<NativeHeadIdentity, String>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT b.source_path, b.author, b.incarnation, b.seq, b.stable_path \
         FROM native_stable_projection_binding b \
         WHERE b.group_id = ?1 AND EXISTS ( \
             SELECT 1 FROM native_heads h \
             WHERE h.group_id = b.group_id AND h.path = b.source_path \
               AND h.author = b.author AND h.incarnation = b.incarnation AND h.seq = b.seq)",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (path, author, incarnation, seq, stable_path) = row?;
        out.insert((path, author, as_array16(&incarnation)?, seq as u64), stable_path);
    }
    Ok(out)
}

/// The directory level `path` lives on: everything before its last `/`, `""`
/// for a top-level name.
pub(crate) fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// The native stable-projection bindings of `group_id` that name a path on one
/// of the levels `parents`, as the source of a head or as its stable name. A
/// copy's stable name is a sibling of its source, so a level's plan needs
/// these and no others.
pub fn native_bindings_in_levels(
    conn: &Connection,
    group_id: &str,
    parents: &BTreeSet<String>,
) -> Result<BTreeMap<NativeHeadIdentity, String>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT source_path, author, incarnation, seq, stable_path \
         FROM native_stable_projection_binding WHERE group_id = ?1 AND source_parent = ?2 \
         UNION \
         SELECT source_path, author, incarnation, seq, stable_path \
         FROM native_stable_projection_binding WHERE group_id = ?1 AND stable_parent = ?2",
    )?;
    let mut out = BTreeMap::new();
    for parent in parents {
        let rows = stmt.query_map((group_id, parent), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (path, author, incarnation, seq, stable_path) = row?;
            count_binding_row_read();
            out.insert((path, author, as_array16(&incarnation)?, seq as u64), stable_path);
        }
    }
    Ok(out)
}

/// Reverse lookup: the native binding identity currently bound to
/// `stable_path` in `group_id`, if any.
pub fn native_binding_at_stable_path(
    conn: &Connection,
    group_id: &str,
    stable_path: &str,
) -> Result<Option<NativeHeadIdentity>, SyncSqliteError> {
    conn.query_row(
        "SELECT source_path, author, incarnation, seq FROM native_stable_projection_binding \
         WHERE group_id = ?1 AND stable_path = ?2",
        (group_id, stable_path),
        |row| {
            let path: String = row.get(0)?;
            let author: String = row.get(1)?;
            let incarnation: Vec<u8> = row.get(2)?;
            let seq: i64 = row.get(3)?;
            Ok((path, author, incarnation, seq))
        },
    )
    .optional()?
    .map(|(path, author, incarnation, seq)| {
        Ok((path, author, as_array16(&incarnation)?, seq as u64))
    })
    .transpose()
}

fn as_array16(bytes: &[u8]) -> Result<[u8; 16], SyncSqliteError> {
    bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!("expected 16 bytes, found {}", bytes.len()))
    })
}

/// One recorded physical placement: the exact head the index row at
/// `physical_path` shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePlacementRow {
    pub physical_path: String,
    pub source_path: String,
    pub author: String,
    pub incarnation: [u8; 16],
    pub seq: u64,
    pub provenance: [u8; 32],
    pub version: [u8; 32],
    pub origin: String,
}

/// The text a placement's origin is stored as.
pub(crate) fn origin_text(origin: PlacementOrigin) -> &'static str {
    match origin {
        PlacementOrigin::ConflictCopy => "conflict_copy",
        PlacementOrigin::TreeRelocation => "tree_relocation",
        PlacementOrigin::ReconciliationHold => "reconciliation_hold",
    }
}

/// The origin a stored placement's text names.
pub(crate) fn parse_origin(text: &str) -> Result<PlacementOrigin, SyncSqliteError> {
    match text {
        "conflict_copy" => Ok(PlacementOrigin::ConflictCopy),
        "tree_relocation" => Ok(PlacementOrigin::TreeRelocation),
        "reconciliation_hold" => Ok(PlacementOrigin::ReconciliationHold),
        other => Err(SyncSqliteError::CorruptState(format!("unknown placement origin {other:?}"))),
    }
}

const PLACEMENT_COLUMNS: &str =
    "physical_path, source_path, author, incarnation, seq, provenance, version, origin";

fn placement_from_row(row: &rusqlite::Row<'_>) -> Result<NativePlacementRow, SyncSqliteError> {
    let incarnation: Vec<u8> = row.get(3)?;
    let provenance: Vec<u8> = row.get(5)?;
    let version: Vec<u8> = row.get(6)?;
    Ok(NativePlacementRow {
        physical_path: row.get(0)?,
        source_path: row.get(1)?,
        author: row.get(2)?,
        incarnation: as_array16(&incarnation)?,
        seq: row.get::<_, i64>(4)? as u64,
        provenance: as_array32(&provenance)?,
        version: as_array32(&version)?,
        origin: row.get(7)?,
    })
}

/// Records `placement`, replacing whatever placement `physical_path` had.
pub fn native_placement_put(
    conn: &Connection,
    group_id: &str,
    placement: &NativePlacementRow,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR REPLACE INTO native_physical_placement \
         (group_id, physical_path, source_path, author, incarnation, seq, provenance, version, \
          origin, physical_parent, source_parent) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            group_id,
            placement.physical_path,
            placement.source_path,
            placement.author,
            placement.incarnation.as_slice(),
            placement.seq as i64,
            placement.provenance.as_slice(),
            placement.version.as_slice(),
            placement.origin,
            parent_of(&placement.physical_path),
            parent_of(&placement.source_path),
        ],
    )?;
    Ok(())
}

/// The placement recorded at `physical_path`, if any.
pub fn native_placement_at(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
) -> Result<Option<NativePlacementRow>, SyncSqliteError> {
    conn.prepare_cached(&format!(
        "SELECT {PLACEMENT_COLUMNS} FROM native_physical_placement \
         WHERE group_id = ?1 AND physical_path = ?2"
    ))?
    .query_row((group_id, physical_path), |row| Ok(placement_from_row(row)))
    .optional()?
    .transpose()
}

/// Every placement recorded for `group_id`.
pub fn native_placements(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<NativePlacementRow>, SyncSqliteError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {PLACEMENT_COLUMNS} FROM native_physical_placement WHERE group_id = ?1"
    ))?;
    let rows = stmt.query_map([group_id], |row| Ok(placement_from_row(row)))?;
    rows.map(|row| row?).collect()
}

/// The placements of `group_id` whose physical name or source is on one of the
/// levels `parents`: what a plan of those levels can be affected by.
pub fn native_placements_in_levels(
    conn: &Connection,
    group_id: &str,
    parents: &BTreeSet<String>,
) -> Result<Vec<NativePlacementRow>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {PLACEMENT_COLUMNS} FROM native_physical_placement \
         WHERE group_id = ?1 AND physical_parent = ?2 \
         UNION \
         SELECT {PLACEMENT_COLUMNS} FROM native_physical_placement \
         WHERE group_id = ?1 AND source_parent = ?2"
    ))?;
    let mut out = Vec::new();
    for parent in parents {
        let rows = stmt.query_map((group_id, parent), |row| Ok(placement_from_row(row)))?;
        for row in rows {
            out.push(row??);
            count_placement_row_read();
        }
    }
    out.sort_by(|a, b| a.physical_path.cmp(&b.physical_path));
    out.dedup_by(|a, b| a.physical_path == b.physical_path);
    Ok(out)
}

/// Every placement recorded for `group_id` whose source is `source_path`.
pub fn native_placements_for_source(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
) -> Result<Vec<NativePlacementRow>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {PLACEMENT_COLUMNS} FROM native_physical_placement \
         WHERE group_id = ?1 AND source_path = ?2"
    ))?;
    let rows = stmt.query_map((group_id, source_path), |row| Ok(placement_from_row(row)))?;
    rows.map(|row| row?).collect()
}

/// Records that a delta declared the head `(source_path, author, incarnation,
/// seq)` with this `provenance` a kept copy. Only a live head with exactly
/// that provenance can be kept: for anything else (retired, or not that head)
/// nothing is recorded, which is what keeps every row naming a live head.
/// Returns whether a row now exists.
pub fn native_keep_head(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
    author: &str,
    incarnation: &[u8; 16],
    seq: u64,
    provenance: &[u8; 32],
) -> Result<bool, SyncSqliteError> {
    conn.prepare_cached(
        "INSERT OR IGNORE INTO native_head_keep \
             (group_id, path, author, incarnation, seq, provenance) \
         SELECT group_id, path, author, incarnation, seq, provenance FROM native_heads \
         WHERE group_id = ?1 AND path = ?2 AND author = ?3 AND incarnation = ?4 \
           AND seq = ?5 AND provenance = ?6",
    )?
    .execute((
        group_id,
        source_path,
        author,
        incarnation.as_slice(),
        seq as i64,
        provenance.as_slice(),
    ))?;
    let kept: bool = conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM native_head_keep \
             WHERE group_id = ?1 AND path = ?2 AND author = ?3 AND incarnation = ?4 AND seq = ?5 \
               AND provenance = ?6)",
        )?
        .query_row(
            (
                group_id,
                source_path,
                author,
                incarnation.as_slice(),
                seq as i64,
                provenance.as_slice(),
            ),
            |row| row.get(0),
        )?;
    Ok(kept)
}

/// Test seeding: keeps every live head at `source_path` whose version is
/// `version`, as an author that observed that whole same-version cohort and
/// declared it would.
#[cfg(test)]
pub(crate) fn native_keep_heads_of_version(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
    version: &[u8; 32],
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO native_head_keep \
             (group_id, path, author, incarnation, seq, provenance) \
         SELECT group_id, path, author, incarnation, seq, provenance FROM native_heads \
         WHERE group_id = ?1 AND path = ?2 AND version = ?3",
        (group_id, source_path, version.as_slice()),
    )?;
    Ok(())
}

/// Forgets the keep of one head, whichever provenance it was recorded with.
pub fn native_unkeep_head(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
    author: &str,
    incarnation: &[u8; 16],
    seq: u64,
) -> Result<(), SyncSqliteError> {
    conn.prepare_cached(
        "DELETE FROM native_head_keep \
         WHERE group_id = ?1 AND path = ?2 AND author = ?3 AND incarnation = ?4 AND seq = ?5",
    )?
    .execute((group_id, source_path, author, incarnation.as_slice(), seq as i64))?;
    Ok(())
}

/// The versions of the kept heads at `source_path`: what the planner treats as
/// kept copies there.
///
/// The class is derived from live kept heads, so a kept head's version applies
/// to its same-version siblings while it lives: an unkept sibling shows at the
/// copy name until the kept head retires, and is then promoted. Every replica
/// derives the same.
pub fn native_kept_versions(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
) -> Result<Vec<[u8; 32]>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT h.version FROM native_heads h \
         WHERE h.group_id = ?1 AND h.path = ?2 AND EXISTS ( \
             SELECT 1 FROM native_head_keep k \
             WHERE k.group_id = h.group_id AND k.path = h.path AND k.author = h.author \
               AND k.incarnation = h.incarnation AND k.seq = h.seq \
               AND k.provenance = h.provenance)",
    )?;
    let rows = stmt.query_map((group_id, source_path), |row| row.get::<_, Vec<u8>>(0))?;
    // Deduplicated here, not with DISTINCT: DISTINCT lets the planner walk the
    // by-version index of the whole group instead of the path's own heads.
    let versions: BTreeSet<[u8; 32]> =
        rows.map(|row| as_array32(&row?)).collect::<Result<_, _>>()?;
    Ok(versions.into_iter().collect())
}

/// Whether any head at `source_path` is kept (the path is named by a kept
/// copy, whatever the version).
pub fn native_has_kept_head(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM native_head_keep WHERE group_id = ?1 AND path = ?2)",
        )?
        .query_row((group_id, source_path), |row| row.get(0))?)
}

/// Every kept head of `group_id`, in a canonical order.
pub fn native_kept_heads_of_group(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<NativeKeptHead>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, author, incarnation, seq, provenance FROM native_head_keep \
         WHERE group_id = ?1 ORDER BY path, author, incarnation, seq",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    rows.map(|row| {
        let (source_path, author, incarnation, seq, provenance) = row?;
        Ok(NativeKeptHead {
            source_path,
            author,
            incarnation: as_array16(&incarnation)?,
            seq: seq as u64,
            provenance: as_array32(&provenance)?,
        })
    })
    .collect()
}

/// Deletes every keep of `group_id` whose head is not a live head with the
/// recorded provenance, returning how many went. A whole-state install can
/// drop heads without going through a removal.
pub fn native_prune_orphan_keeps(
    conn: &Connection,
    group_id: &str,
) -> Result<usize, SyncSqliteError> {
    Ok(conn.execute(
        "DELETE FROM native_head_keep WHERE group_id = ?1 AND NOT EXISTS ( \
             SELECT 1 FROM native_heads h \
             WHERE h.group_id = native_head_keep.group_id AND h.path = native_head_keep.path \
               AND h.author = native_head_keep.author \
               AND h.incarnation = native_head_keep.incarnation \
               AND h.seq = native_head_keep.seq AND h.provenance = native_head_keep.provenance)",
        [group_id],
    )?)
}

/// Forgets the placement at `physical_path`.
pub fn native_placement_delete(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM native_physical_placement WHERE group_id = ?1 AND physical_path = ?2",
        (group_id, physical_path),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
