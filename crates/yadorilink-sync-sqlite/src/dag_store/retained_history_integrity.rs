//! The `changes` table: durable, admitted change history, and the
//! `change_parents` ancestry index derived from it. Every row here is trusted
//! as fact by the rest of the DAG -- [`repair`] re-verifies that trust against
//! each row's own signed canonical bytes at startup, fail-closed on any
//! disagreement, since (unlike `orphan_changes`) there is no safe way to
//! silently drop durable history.
//!
//! Compaction deliberately removes Change bodies, so an absent parent cannot
//! be classified as "pruned" merely because it is absent from `changes`.
//! `pruned_changes` and `pruned_change_parents` are the compact proof of an
//! intentional prune: the exact deleted hash, its Lamport clock, and every
//! ancestry edge touching it are captured atomically while `commit_prune`
//! deletes the row. Startup accepts a missing retained parent only when both
//! the parent tombstone and the exact child->parent pruned-edge proof exist.

use rusqlite::{Connection, OptionalExtension};

use super::serving_authorization_index::record_change_file_versions;
use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::{Change, Op, PRUNED_STUB_ENCODING_VERSION};
use yadorilink_replica_domain::ids::ChangeHash;

/// Installs the compact proof tables used to distinguish intentional pruning
/// from arbitrary history loss. `commit_prune` already has one stable sequence:
/// insert checkpoint, delete pruned Change rows, then run the version sweep.
/// The triggers observe only that window: checkpoint insertion opens a
/// per-group prune context, Change deletion records tombstones/edge skeletons,
/// and `serving_authorization_index::sweep_unreferenced_file_versions` closes
/// the context at its start.
///
/// Creating the checkpoint table here is intentional and idempotent. The main
/// schema orchestrator historically created it after retained-history repair;
/// the trigger must exist before a future prune, and the later identical
/// migration remains a no-op.
fn ensure_prune_tombstone_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(super::CHECKPOINT_TABLE_MIGRATION)?;
    conn.execute_batch(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS pruned_changes (
            group_id             TEXT NOT NULL,
            change_hash          BLOB NOT NULL,
            checkpoint_hash      BLOB NOT NULL,
            lamport              INTEGER NOT NULL,
            -- The pruned change's `device_id`, so a pruned change stays
            -- attributable to its author without retaining its body. Copied
            -- verbatim from `changes.device_id` by the trigger below, same as
            -- `lamport` already is. NULL only for a boundary ancestor
            -- installed from a re-bootstrap snapshot, whose compact
            -- `BoundaryParentAuth` wire record never carried the parent's
            -- full identity to begin with (see
            -- `index::rebootstrap_store::base::install_snapshot_frontier`).
            author_identity      BLOB,
            -- `Change::authenticated_header_encoding()` for the pruned
            -- change: every signed field except `ops` plus the original
            -- signature. Copied verbatim from `changes.authenticated_header`
            -- (computed once at append time -- see `append_change`) for a
            -- change THIS replica actually pruned, so it remains a valid,
            -- attributable explicit parent without retaining its operations,
            -- file version or block payload. NULL for the same
            -- re-bootstrap-boundary case as `author_identity` above -- this
            -- replica never held that ancestor's full body to derive a
            -- header from in the first place.
            authenticated_header BLOB,
            encoding_version     INTEGER NOT NULL,
            PRIMARY KEY (group_id, change_hash)
        );
        CREATE TABLE IF NOT EXISTS pruned_change_parents (
            group_id        TEXT NOT NULL,
            child_hash      BLOB NOT NULL,
            parent_hash     BLOB NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, child_hash, parent_hash)
        );
        CREATE INDEX IF NOT EXISTS pruned_change_parents_by_parent
            ON pruned_change_parents(group_id, parent_hash);
        CREATE TABLE IF NOT EXISTS active_prune_context (
            group_id        TEXT PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS dag_prune_context_begin
        AFTER INSERT ON change_checkpoints
        BEGIN
            INSERT OR REPLACE INTO active_prune_context (group_id, checkpoint_hash)
            VALUES (NEW.group_id, NEW.checkpoint_hash);
        END;

        CREATE TRIGGER IF NOT EXISTS dag_record_pruned_change
        BEFORE DELETE ON changes
        WHEN EXISTS (
            SELECT 1 FROM active_prune_context ctx WHERE ctx.group_id = OLD.group_id
        )
        BEGIN
            INSERT OR IGNORE INTO pruned_changes
                (group_id, change_hash, checkpoint_hash, lamport, author_identity,
                 authenticated_header, encoding_version)
            SELECT OLD.group_id, OLD.change_hash, ctx.checkpoint_hash, OLD.lamport,
                   CAST(OLD.device_id AS BLOB), OLD.authenticated_header, {PRUNED_STUB_ENCODING_VERSION}
            FROM active_prune_context ctx
            WHERE ctx.group_id = OLD.group_id;

            INSERT OR IGNORE INTO pruned_change_parents
                (group_id, child_hash, parent_hash, checkpoint_hash)
            SELECT OLD.group_id, cp.child_hash, cp.parent_hash, ctx.checkpoint_hash
            FROM change_parents cp
            JOIN active_prune_context ctx ON ctx.group_id = OLD.group_id
            WHERE cp.child_hash = OLD.change_hash OR cp.parent_hash = OLD.change_hash;
        END;
        "#
    ))?;
    Ok(())
}

/// Fail closed when the compact prune proof tables cannot actually be tied to
/// the checkpoint transaction they claim authorized them. These rows are not
/// ordinary caches: retained-history repair relies on them to accept a parent
/// body that no longer exists. A forged/orphaned tombstone must therefore never
/// turn arbitrary history loss into a valid compaction boundary.
fn validate_prune_proofs(conn: &Connection) -> Result<(), SyncSqliteError> {
    super::checkpoint_store::validate_all(conn)?;

    let invalid_tombstones: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM pruned_changes pc \
             WHERE length(pc.change_hash) != 32 \
                OR length(pc.checkpoint_hash) != 32 \
                OR pc.lamport < 1 \
                -- `author_identity`/`authenticated_header` are NULL together
                -- only for a re-bootstrap-boundary ancestor (see the
                -- `pruned_changes` column comments); a present-but-empty
                -- value, or exactly one of the pair NULL, is corrupt.
                OR (pc.author_identity IS NOT NULL AND length(pc.author_identity) = 0) \
                OR (pc.authenticated_header IS NOT NULL AND length(pc.authenticated_header) = 0) \
                OR ((pc.author_identity IS NULL) != (pc.authenticated_header IS NULL)) \
                OR pc.encoding_version != {PRUNED_STUB_ENCODING_VERSION} \
                OR EXISTS (SELECT 1 FROM changes c WHERE c.change_hash = pc.change_hash) \
                OR NOT EXISTS (\
                    SELECT 1 FROM change_checkpoints cp \
                    WHERE cp.checkpoint_hash = pc.checkpoint_hash AND cp.group_id = pc.group_id)"
        ),
        [],
        |row| row.get(0),
    )?;
    if invalid_tombstones != 0 {
        return Err(SyncSqliteError::CorruptState(format!(
            "retained prune history contains {invalid_tombstones} invalid or unanchored change tombstone(s)"
        )));
    }

    let invalid_edges: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pruned_change_parents pcp \
         WHERE length(pcp.child_hash) != 32 \
            OR length(pcp.parent_hash) != 32 \
            OR length(pcp.checkpoint_hash) != 32 \
            OR NOT EXISTS (\
                SELECT 1 FROM change_checkpoints cp \
                WHERE cp.checkpoint_hash = pcp.checkpoint_hash AND cp.group_id = pcp.group_id) \
            OR NOT EXISTS (\
                SELECT 1 FROM pruned_changes pc \
                WHERE pc.group_id = pcp.group_id \
                  AND pc.checkpoint_hash = pcp.checkpoint_hash \
                  AND (pc.change_hash = pcp.child_hash OR pc.change_hash = pcp.parent_hash))",
        [],
        |row| row.get(0),
    )?;
    if invalid_edges != 0 {
        return Err(SyncSqliteError::CorruptState(format!(
            "retained prune history contains {invalid_edges} parent-edge proof(s) not owned by the checkpoint prune they claim"
        )));
    }
    Ok(())
}

/// Closes the short-lived prune context opened by checkpoint insertion. Called
/// at the start of the sweep that `commit_prune` invokes after all Change
/// deletions, so any later unrelated deletion cannot be mistaken for pruning.
pub(crate) fn finish_prune_context(
    conn: &Connection,
    group_id: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM active_prune_context WHERE group_id = ?1", [group_id])?;
    Ok(())
}

pub fn is_pruned_change(
    conn: &Connection,
    group_id: &str,
    hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    let present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = ?1 AND change_hash = ?2)",
        rusqlite::params![group_id, &hash.0[..]],
        |row| row.get(0),
    )?;
    Ok(present)
}

/// Visible to `dag_store` and its submodules (notably `frontier_index`, which
/// needs this to make live-signing Lamport computation agree with
/// [`validate_present_parent_shape`]'s pruned-aware one below) as well as to
/// this module's own repair/validation callers.
pub(super) fn pruned_lamport(
    conn: &Connection,
    group_id: &str,
    hash: &ChangeHash,
) -> Result<Option<u64>, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT lamport FROM pruned_changes WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| value as u64))
}

/// Whether a change is already present in the admitted store (not the orphan
/// buffer). Used to make append idempotent and to decide ancestry completeness.
pub fn has_change(conn: &Connection, hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
    let present: Option<i64> = conn
        .query_row("SELECT 1 FROM changes WHERE change_hash = ?1", [&hash.0[..]], |r| r.get(0))
        .optional()?;
    Ok(present.is_some())
}

/// The full encoded bytes (canonical + signature) of a stored change, for
/// serving it onward to another peer without re-signing.
pub fn get_encoded(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    Ok(conn
        .query_row("SELECT encoded FROM changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
            r.get(0)
        })
        .optional()?)
}

/// Every path mentioned by retained change history for `group_id`.
pub fn group_history_paths(
    conn: &Connection,
    group_id: &str,
) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
    let mut paths = std::collections::HashSet::new();
    let mut stmt = conn.prepare("SELECT encoded FROM changes WHERE group_id = ?1")?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    for row in rows {
        let change = Change::from_wire_bytes(&row?)
            .map_err(|e| SyncSqliteError::CorruptState(format!("corrupt stored change: {e}")))?;
        for op in change.ops {
            match op {
                Op::Put { path, .. } | Op::Delete { path } => {
                    paths.insert(path.0);
                }
                Op::Move { from, to, .. } => {
                    paths.insert(from.0);
                    paths.insert(to.0);
                }
            }
        }
    }
    Ok(paths)
}

/// The logical clock value of a stored change, if present.
pub fn lamport_of(conn: &Connection, hash: &ChangeHash) -> Result<Option<u64>, SyncSqliteError> {
    Ok(conn
        .query_row("SELECT lamport FROM changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?
        .map(|v| v as u64))
}

fn parent_meta(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<Option<(String, u64)>, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT group_id, lamport FROM changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)),
        )
        .optional()?)
}

/// Verifies the store-dependent parent invariants for every parent still
/// known locally, live admission's own counterpart to
/// [`validate_retained_parent_shape`] below (repair's, at startup). Returns
/// whether all parents are present. A parent whose full body this replica
/// itself compacted is a valid explicit parent here exactly as it is for
/// startup repair -- the pruned-change tombstone (`lamport`, group,
/// `author_identity`, `authenticated_header`) is only ever written when THIS
/// replica committed the prune, so it is exactly as trustworthy as the live
/// parent row it replaced. Only a parent this replica has genuinely never
/// seen (no live row, no prune tombstone) counts as "not present" and holds
/// the change back as an orphan -- see `pruned_changes`'s own module doc
/// comment.
pub(crate) fn validate_present_parent_shape(
    conn: &Connection,
    change: &Change,
) -> Result<bool, SyncSqliteError> {
    validate_present_parent_shape_parts(
        conn,
        change.group_id.as_str(),
        &change.parents,
        change.lamport,
    )
}

/// The body of [`validate_present_parent_shape`], expressed over the three
/// fields it actually reads rather than over a whole [`Change`]. Exists so
/// local emission can run this check on a change it has not signed *yet* --
/// see `dag_store::prepare_emission`: everything a signature would have to
/// be re-derived over must be settled before an authorization coordinate is
/// acquired, so that nothing but signing and appending happens after it.
/// Neither the signature nor the authorization stamp is consulted here, so
/// validating before signing is exactly the same check, run earlier.
pub(crate) fn validate_present_parent_shape_parts(
    conn: &Connection,
    group_id: &str,
    parents: &[ChangeHash],
    lamport: u64,
) -> Result<bool, SyncSqliteError> {
    let mut max_parent_lamport = 0u64;
    let mut all_parents_present = true;
    for parent in parents {
        match parent_meta(conn, parent)? {
            Some((parent_group, parent_lamport)) => {
                if parent_group != group_id {
                    return Err(SyncSqliteError::NotFound(format!(
                        "change parent {} belongs to group {} while child belongs to {}",
                        parent.to_hex(),
                        parent_group,
                        group_id
                    )));
                }
                max_parent_lamport = max_parent_lamport.max(parent_lamport);
            }
            None => match pruned_lamport(conn, group_id, parent)? {
                Some(parent_lamport) => {
                    max_parent_lamport = max_parent_lamport.max(parent_lamport);
                }
                None => all_parents_present = false,
            },
        }
    }
    if all_parents_present {
        let expected = if parents.is_empty() {
            1
        } else {
            max_parent_lamport.checked_add(1).ok_or_else(|| {
                SyncSqliteError::NotFound("change parent lamport would overflow".into())
            })?
        };
        if lamport != expected {
            return Err(SyncSqliteError::NotFound(format!(
                "change lamport {lamport} does not match expected {expected}"
            )));
        }
    }
    Ok(all_parents_present)
}

/// Re-checks the same parent-group/Lamport invariant for durable retained
/// history, but permits a parent body to have been compacted when the exact
/// prune tombstone exists. This preserves the logical clock relation across a
/// pruning boundary instead of skipping Lamport validation merely because one
/// parent row is gone.
fn validate_retained_parent_shape(
    conn: &Connection,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    let mut max_parent_lamport = 0u64;
    for parent in &change.parents {
        if let Some((parent_group, parent_lamport)) = parent_meta(conn, parent)? {
            if parent_group != change.group_id.as_str() {
                return Err(SyncSqliteError::CorruptState(format!(
                    "retained parent {} belongs to group {} while child belongs to {}",
                    parent.to_hex(),
                    parent_group,
                    change.group_id.as_str()
                )));
            }
            max_parent_lamport = max_parent_lamport.max(parent_lamport);
            continue;
        }
        let Some(parent_lamport) = pruned_lamport(conn, change.group_id.as_str(), parent)? else {
            return Err(SyncSqliteError::CorruptState(format!(
                "retained change {} references missing parent {} with no prune tombstone",
                change.compute_hash().to_hex(),
                parent.to_hex()
            )));
        };
        max_parent_lamport = max_parent_lamport.max(parent_lamport);
    }

    let expected = if change.parents.is_empty() {
        1
    } else {
        max_parent_lamport.checked_add(1).ok_or_else(|| {
            SyncSqliteError::CorruptState("retained parent lamport would overflow".into())
        })?
    };
    if change.lamport != expected {
        return Err(SyncSqliteError::CorruptState(format!(
            "retained change {} has lamport {}, expected {} from retained/pruned parents",
            change.compute_hash().to_hex(),
            change.lamport,
            expected
        )));
    }
    Ok(())
}

/// The stored parent edges of a change.
pub fn parents_of(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT parent_hash FROM change_parents WHERE child_hash = ?1")?;
    let rows = stmt.query_map([&hash.0[..]], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_from_blob(row?)?);
    }
    Ok(out)
}

/// Whether a hash is backed by either a retained verified Change or the
/// durable tombstone written when that verified Change was compacted —
/// **in this group**. The group scope is load-bearing, not cosmetic: this
/// is the verification gate authoring-identity causality stands on
/// (`compare_authoring_on_conn`, `apply_locked_record`), and a hash that
/// exists only under a *different* group must read as unverified here, or
/// a peer can smuggle a foreign group's change in as a causal identity for
/// this one.
pub fn has_change_or_pruned(
    conn: &Connection,
    group_id: &str,
    hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    let retained: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM changes WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(retained.is_some() || is_pruned_change(conn, group_id, hash)?)
}

/// Whether `ancestor` is a strict ancestor of `descendant` — reachable by
/// walking retained parent edges upward from `descendant`, never equal to it.
pub fn is_ancestor(
    conn: &Connection,
    ancestor: &ChangeHash,
    descendant: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    // Run the graph walk inside SQLite instead of issuing one query per
    // visited node. Reconciliation invokes this in a hot per-record loop;
    // the recursive UNION both deduplicates/cycle-bounds the traversal and
    // keeps retained + compacted edges in one database round-trip.
    let found: bool = conn.query_row(
        "WITH RECURSIVE
           edges(child_hash, parent_hash) AS (
             SELECT child_hash, parent_hash FROM change_parents
             UNION
             SELECT child_hash, parent_hash FROM pruned_change_parents
           ),
           ancestry(hash) AS (
             SELECT parent_hash FROM edges WHERE child_hash = ?1
             UNION
             SELECT edges.parent_hash
             FROM edges JOIN ancestry ON edges.child_hash = ancestry.hash
           )
         SELECT EXISTS(SELECT 1 FROM ancestry WHERE hash = ?2)",
        rusqlite::params![&descendant.0[..], &ancestor.0[..]],
        |row| row.get(0),
    )?;
    Ok(found)
}

/// Marks a stored change as materialized into the file index.
pub fn mark_applied(conn: &Connection, hash: &ChangeHash) -> Result<(), SyncSqliteError> {
    conn.execute("UPDATE changes SET applied = 1 WHERE change_hash = ?1", [&hash.0[..]])?;
    Ok(())
}

/// Every admitted-but-not-yet-projected change for `group_id`, decoded and
/// ordered by Lamport timestamp (oldest-first).
pub fn list_unapplied(conn: &Connection, group_id: &str) -> Result<Vec<Change>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT encoded FROM changes WHERE group_id = ?1 AND applied = 0 ORDER BY lamport, change_hash",
    )?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let change = Change::from_wire_bytes(&row?).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "cannot list unapplied changes for group {group_id}: retained change is corrupt: {error}"
            ))
        })?;
        out.push(change);
    }
    Ok(out)
}

/// Whether every parent of a change is present in the admitted store.
pub fn has_all_parents(conn: &Connection, change: &Change) -> Result<bool, SyncSqliteError> {
    for parent in &change.parents {
        // A parent this replica itself pruned is still a known, valid
        // explicit parent -- see `has_change_or_pruned`'s own doc comment and
        // `validate_present_parent_shape`, whose completeness decision this
        // must agree with (`promote_orphans` gates on this fn first, then
        // that one).
        if !has_change_or_pruned(conn, change.group_id.as_str(), parent)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Inserts a change into the admitted store and maintains the group's head set.
/// Idempotent for an already-retained change. A hash that this replica already
/// compacted is deliberately rejected rather than reinserted: a stale peer may
/// replay old history after reconnecting, but pruning must be monotonic.
pub(crate) fn append_change(
    conn: &Connection,
    change: &Change,
    applied: bool,
) -> Result<bool, SyncSqliteError> {
    let hash = change.compute_hash();
    if is_pruned_change(conn, change.group_id.as_str(), &hash)? {
        return Err(SyncSqliteError::NotFound(format!(
            "change {} was already pruned by a committed checkpoint",
            hash.to_hex()
        )));
    }
    if has_change(conn, &hash)? {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied, authenticated_header) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &hash.0[..],
            change.group_id.as_str(),
            change.device_id.as_str(),
            change.lamport as i64,
            change.to_wire_bytes(),
            applied as i64,
            change.authenticated_header_encoding(),
        ],
    )?;
    record_change_file_versions(conn, change)?;
    for parent in &change.parents {
        conn.execute(
            "INSERT OR IGNORE INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
            rusqlite::params![&hash.0[..], &parent.0[..]],
        )?;
        conn.execute(
            "DELETE FROM group_heads WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![change.group_id.as_str(), &parent.0[..]],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO group_heads (group_id, change_hash) VALUES (?1, ?2)",
        rusqlite::params![change.group_id.as_str(), &hash.0[..]],
    )?;
    Ok(true)
}

/// Confirms a retained row's storage key and denormalized SQL columns agree
/// with the signed canonical Change decoded from its `encoded` bytes.
pub(crate) fn verify_retained_change_identity(
    change: &Change,
    stored_hash: &[u8],
    stored_group: &str,
    stored_device: &str,
    stored_lamport: i64,
) -> Result<(), String> {
    if change.compute_hash().0[..] != *stored_hash {
        return Err("is stored under a key that does not match its encoded hash".into());
    }
    if change.group_id.as_str() != stored_group
        || change.device_id.as_str() != stored_device
        || change.lamport != stored_lamport as u64
    {
        return Err(
            "has row metadata (group_id/device_id/lamport) that disagrees with its encoded body"
                .into(),
        );
    }
    Ok(())
}

/// Exact ancestry-index check used by buffered orphans. Orphan ancestry has not
/// been compacted, so its SQL edge set must equal the signed parent set exactly.
pub(crate) fn parent_edges_match(
    conn: &Connection,
    change_hash: &ChangeHash,
    declared_parents: &[ChangeHash],
) -> Result<bool, SyncSqliteError> {
    let recorded: std::collections::HashSet<[u8; 32]> = {
        let mut stmt =
            conn.prepare("SELECT parent_hash FROM change_parents WHERE child_hash = ?1")?;
        let rows = stmt.query_map([&change_hash.0[..]], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|r| hash_from_blob(r?).map(|h| h.0)).collect::<Result<_, _>>()?
    };
    let declared: std::collections::HashSet<[u8; 32]> =
        declared_parents.iter().map(|p| p.0).collect();
    Ok(recorded == declared)
}

/// Verifies the retained ancestry index against the signed parent list across
/// compaction boundaries. A live parent requires the ordinary live edge. A
/// missing parent requires both an exact `pruned_changes` tombstone and the
/// exact `(child,parent)` relation captured in `pruned_change_parents` when the
/// prune removed that edge. This accepts concurrent surviving branches whose
/// common ancestor was pruned even when the child is not itself a checkpoint
/// frontier member, while still refusing arbitrary missing history.
fn retained_parent_edges_match(
    conn: &Connection,
    group_id: &str,
    change_hash: &ChangeHash,
    declared_parents: &[ChangeHash],
) -> Result<bool, SyncSqliteError> {
    let live_edges: std::collections::HashSet<[u8; 32]> = {
        let mut stmt =
            conn.prepare("SELECT parent_hash FROM change_parents WHERE child_hash = ?1")?;
        let rows = stmt.query_map([&change_hash.0[..]], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|r| hash_from_blob(r?).map(|h| h.0)).collect::<Result<_, _>>()?
    };
    let pruned_edges: std::collections::HashSet<[u8; 32]> = {
        let mut stmt = conn.prepare(
            "SELECT parent_hash FROM pruned_change_parents WHERE group_id = ?1 AND child_hash = ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![group_id, &change_hash.0[..]], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|r| hash_from_blob(r?).map(|h| h.0)).collect::<Result<_, _>>()?
    };
    let declared: std::collections::HashSet<[u8; 32]> =
        declared_parents.iter().map(|p| p.0).collect();
    if !live_edges.is_subset(&declared) || !pruned_edges.is_subset(&declared) {
        return Ok(false);
    }

    for parent in declared_parents {
        if has_change(conn, parent)? {
            if !live_edges.contains(&parent.0) || pruned_edges.contains(&parent.0) {
                return Ok(false);
            }
        } else if !is_pruned_change(conn, group_id, parent)?
            || !pruned_edges.contains(&parent.0)
            || live_edges.contains(&parent.0)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn hash_from_blob(v: Vec<u8>) -> Result<ChangeHash, SyncSqliteError> {
    let array: [u8; 32] = v
        .try_into()
        .map_err(|_| SyncSqliteError::NotFound("change hash column is not 32 bytes".into()))?;
    Ok(ChangeHash(array))
}

/// Runs the startup repair pass for admitted history. The compact prune proof
/// tables are authoritative only for deletions that occurred inside the short
/// checkpoint->delete->sweep window; a stale context from an interrupted or
/// externally-manipulated connection is cleared before validation.
pub(crate) fn repair(conn: &Connection) -> Result<(), SyncSqliteError> {
    ensure_prune_tombstone_schema(conn)?;
    conn.execute("DELETE FROM active_prune_context", [])?;
    validate_prune_proofs(conn)?;

    let tx = conn.unchecked_transaction()?;
    // One admitted `changes` row: `(change_hash, group_id, device_id, lamport,
    // applied, encoded, authenticated_header)`.
    type AdmittedRow = (Vec<u8>, String, String, i64, i64, Vec<u8>, Vec<u8>);
    let admitted_rows: Vec<AdmittedRow> = {
        let mut stmt = tx.prepare(
            "SELECT change_hash, group_id, device_id, lamport, applied, encoded, \
             authenticated_header FROM changes",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?;
        rows.collect::<Result<_, _>>()?
    };

    for (
        stored_hash,
        stored_group,
        stored_device,
        stored_lamport,
        stored_applied,
        encoded,
        stored_authenticated_header,
    ) in admitted_rows
    {
        if stored_applied != 0 && stored_applied != 1 {
            return Err(SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: change {} has an invalid applied value {} (must be 0 or 1)",
                hex::encode(&stored_hash), stored_applied,
            )));
        }
        let change = Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: retained change is corrupt: {error}"
            ))
        })?;
        let change_hash = change.compute_hash();
        change.validate_structure(&change_hash).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: retained change {} is structurally invalid: {error}",
                hex::encode(&stored_hash),
            ))
        })?;
        verify_retained_change_identity(
            &change,
            &stored_hash,
            &stored_group,
            &stored_device,
            stored_lamport,
        )
        .map_err(|reason| {
            SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: retained change {} {reason}",
                hex::encode(&stored_hash),
            ))
        })?;
        // The retained header is what a future prune hands straight to this
        // change's `pruned_changes` tombstone (see `ensure_prune_tombstone_
        // schema`'s trigger) with no re-derivation from `encoded` at prune
        // time -- if it ever silently drifted from what the change's own
        // signed bytes actually authenticate, a pruned stub would carry a
        // wrong (but structurally valid-looking) header forever, after the
        // one moment (right here) it could still be checked against the
        // full body.
        if change.authenticated_header_encoding() != stored_authenticated_header {
            return Err(SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: retained change {} has an authenticated_header \
                 column that disagrees with its own encoded body",
                hex::encode(&stored_hash),
            )));
        }
        validate_retained_parent_shape(&tx, &change)?;
        if !retained_parent_edges_match(
            &tx,
            change.group_id.as_str(),
            &change_hash,
            &change.parents,
        )? {
            return Err(SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: change {}'s live/pruned parent-edge proofs disagree with its signed ancestry",
                hex::encode(change_hash.0),
            )));
        }
        // Re-validates every `ConflictCopy` put's claim against this change's
        // own parent frontier -- a signature only proves who signed a claim,
        // not that the claim was true, so an authorized-but-malicious device
        // signing a bogus `ConflictCopy` origin is only caught here, not by
        // signature verification alone.
        super::conflict_authoring::validate_carrier_conflict_copy_ops(
            &tx,
            change.group_id.as_str(),
            &change,
        )
        .map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "cannot repair retained history: retained change {} has an invalid conflict-copy \
                 put: {error}",
                hex::encode(&stored_hash),
            ))
        })?;

        super::serving_authorization_index::repair_change_file_versions(&tx, &change, true)?;
        super::serving_authorization_index::prune_unjustified_change_file_versions(
            &tx,
            &change,
            &change_hash,
        )?;
    }
    tx.commit()?;
    Ok(())
}
