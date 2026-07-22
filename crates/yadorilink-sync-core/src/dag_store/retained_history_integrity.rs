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
use crate::change::{Change, ChangeHash, Op};
use crate::error::SyncError;

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
fn ensure_prune_tombstone_schema(conn: &Connection) -> Result<(), SyncError> {
    conn.execute_batch(crate::compaction::CHECKPOINT_TABLE_MIGRATION)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS pruned_changes (
            group_id        TEXT NOT NULL,
            change_hash     BLOB NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            lamport         INTEGER NOT NULL,
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
                (group_id, change_hash, checkpoint_hash, lamport)
            SELECT OLD.group_id, OLD.change_hash, ctx.checkpoint_hash, OLD.lamport
            FROM active_prune_context ctx
            WHERE ctx.group_id = OLD.group_id;

            INSERT OR IGNORE INTO pruned_change_parents
                (group_id, child_hash, parent_hash, checkpoint_hash)
            SELECT OLD.group_id, cp.child_hash, cp.parent_hash, ctx.checkpoint_hash
            FROM change_parents cp
            JOIN active_prune_context ctx ON ctx.group_id = OLD.group_id
            WHERE cp.child_hash = OLD.change_hash OR cp.parent_hash = OLD.change_hash;
        END;
        "#,
    )?;
    Ok(())
}

/// Fail closed when the compact prune proof tables cannot actually be tied to
/// the checkpoint transaction they claim authorized them. These rows are not
/// ordinary caches: retained-history repair relies on them to accept a parent
/// body that no longer exists. A forged/orphaned tombstone must therefore never
/// turn arbitrary history loss into a valid compaction boundary.
fn validate_prune_proofs(conn: &Connection) -> Result<(), SyncError> {
    super::checkpoint_store::validate_all(conn)?;

    let invalid_tombstones: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pruned_changes pc \
         WHERE length(pc.change_hash) != 32 \
            OR length(pc.checkpoint_hash) != 32 \
            OR pc.lamport < 1 \
            OR EXISTS (SELECT 1 FROM changes c WHERE c.change_hash = pc.change_hash) \
            OR NOT EXISTS (\
                SELECT 1 FROM change_checkpoints cp \
                WHERE cp.checkpoint_hash = pc.checkpoint_hash AND cp.group_id = pc.group_id)",
        [],
        |row| row.get(0),
    )?;
    if invalid_tombstones != 0 {
        return Err(SyncError::CorruptState(format!(
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
        return Err(SyncError::CorruptState(format!(
            "retained prune history contains {invalid_edges} parent-edge proof(s) not owned by the checkpoint prune they claim"
        )));
    }
    Ok(())
}

/// Closes the short-lived prune context opened by checkpoint insertion. Called
/// at the start of the sweep that `commit_prune` invokes after all Change
/// deletions, so any later unrelated deletion cannot be mistaken for pruning.
pub(crate) fn finish_prune_context(conn: &Connection, group_id: &str) -> Result<(), SyncError> {
    conn.execute("DELETE FROM active_prune_context WHERE group_id = ?1", [group_id])?;
    Ok(())
}

pub(crate) fn is_pruned_change(
    conn: &Connection,
    group_id: &str,
    hash: &ChangeHash,
) -> Result<bool, SyncError> {
    let present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = ?1 AND change_hash = ?2)",
        rusqlite::params![group_id, &hash.0[..]],
        |row| row.get(0),
    )?;
    Ok(present)
}

fn pruned_lamport(
    conn: &Connection,
    group_id: &str,
    hash: &ChangeHash,
) -> Result<Option<u64>, SyncError> {
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
pub fn has_change(conn: &Connection, hash: &ChangeHash) -> Result<bool, SyncError> {
    let present: Option<i64> = conn
        .query_row("SELECT 1 FROM changes WHERE change_hash = ?1", [&hash.0[..]], |r| r.get(0))
        .optional()?;
    Ok(present.is_some())
}

/// The full encoded bytes (canonical + signature) of a stored change, for
/// serving it onward to another peer without re-signing.
pub fn get_encoded(conn: &Connection, hash: &ChangeHash) -> Result<Option<Vec<u8>>, SyncError> {
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
) -> Result<std::collections::HashSet<String>, SyncError> {
    let mut paths = std::collections::HashSet::new();
    let mut stmt = conn.prepare("SELECT encoded FROM changes WHERE group_id = ?1")?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    for row in rows {
        let change = Change::from_wire_bytes(&row?)
            .map_err(|e| SyncError::CorruptState(format!("corrupt stored change: {e}")))?;
        for op in change.ops {
            match op {
                Op::Create { path, .. } | Op::Update { path, .. } | Op::Delete { path } => {
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
pub fn lamport_of(conn: &Connection, hash: &ChangeHash) -> Result<Option<u64>, SyncError> {
    Ok(conn
        .query_row("SELECT lamport FROM changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?
        .map(|v| v as u64))
}

fn parent_meta(conn: &Connection, hash: &ChangeHash) -> Result<Option<(String, u64)>, SyncError> {
    Ok(conn
        .query_row(
            "SELECT group_id, lamport FROM changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)),
        )
        .optional()?)
}

/// Verifies the store-dependent parent invariants for every parent still
/// retained locally. Returns whether all parents are present. Live admission
/// uses this to decide admitted-vs-orphan; a pruned parent therefore remains
/// "not present" here rather than silently making a new offline descendant
/// admissible without the separate authorization/merge rules that case needs.
pub(crate) fn validate_present_parent_shape(
    conn: &Connection,
    change: &Change,
) -> Result<bool, SyncError> {
    let mut max_parent_lamport = 0u64;
    let mut all_parents_present = true;
    for parent in &change.parents {
        match parent_meta(conn, parent)? {
            Some((parent_group, parent_lamport)) => {
                if parent_group != change.group_id.as_str() {
                    return Err(SyncError::NotFound(format!(
                        "change parent {} belongs to group {} while child belongs to {}",
                        parent.to_hex(),
                        parent_group,
                        change.group_id.as_str()
                    )));
                }
                max_parent_lamport = max_parent_lamport.max(parent_lamport);
            }
            None => all_parents_present = false,
        }
    }
    if all_parents_present {
        let expected = if change.parents.is_empty() {
            1
        } else {
            max_parent_lamport
                .checked_add(1)
                .ok_or_else(|| SyncError::NotFound("change parent lamport would overflow".into()))?
        };
        if change.lamport != expected {
            return Err(SyncError::NotFound(format!(
                "change lamport {} does not match expected {}",
                change.lamport, expected
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
fn validate_retained_parent_shape(conn: &Connection, change: &Change) -> Result<(), SyncError> {
    let mut max_parent_lamport = 0u64;
    for parent in &change.parents {
        if let Some((parent_group, parent_lamport)) = parent_meta(conn, parent)? {
            if parent_group != change.group_id.as_str() {
                return Err(SyncError::CorruptState(format!(
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
            return Err(SyncError::CorruptState(format!(
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
            SyncError::CorruptState("retained parent lamport would overflow".into())
        })?
    };
    if change.lamport != expected {
        return Err(SyncError::CorruptState(format!(
            "retained change {} has lamport {}, expected {} from retained/pruned parents",
            change.compute_hash().to_hex(),
            change.lamport,
            expected
        )));
    }
    Ok(())
}

/// The stored parent edges of a change.
pub fn parents_of(conn: &Connection, hash: &ChangeHash) -> Result<Vec<ChangeHash>, SyncError> {
    let mut stmt = conn.prepare("SELECT parent_hash FROM change_parents WHERE child_hash = ?1")?;
    let rows = stmt.query_map([&hash.0[..]], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_from_blob(row?)?);
    }
    Ok(out)
}

/// Whether `ancestor` is a strict ancestor of `descendant` — reachable by
/// walking retained parent edges upward from `descendant`, never equal to it.
pub fn is_ancestor(
    conn: &Connection,
    ancestor: &ChangeHash,
    descendant: &ChangeHash,
) -> Result<bool, SyncError> {
    use std::collections::HashSet;
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut stack: Vec<ChangeHash> = parents_of(conn, descendant)?;
    while let Some(node) = stack.pop() {
        if &node == ancestor {
            return Ok(true);
        }
        if !visited.insert(node.0) {
            continue;
        }
        stack.extend(parents_of(conn, &node)?);
    }
    Ok(false)
}

/// Marks a stored change as materialized into the file index.
pub fn mark_applied(conn: &Connection, hash: &ChangeHash) -> Result<(), SyncError> {
    conn.execute("UPDATE changes SET applied = 1 WHERE change_hash = ?1", [&hash.0[..]])?;
    Ok(())
}

/// Every admitted-but-not-yet-projected change for `group_id`, decoded and
/// ordered by Lamport timestamp (oldest-first).
pub fn list_unapplied(conn: &Connection, group_id: &str) -> Result<Vec<Change>, SyncError> {
    let mut stmt = conn.prepare(
        "SELECT encoded FROM changes WHERE group_id = ?1 AND applied = 0 ORDER BY lamport, change_hash",
    )?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let change = Change::from_wire_bytes(&row?).map_err(|error| {
            SyncError::CorruptState(format!(
                "cannot list unapplied changes for group {group_id}: retained change is corrupt: {error}"
            ))
        })?;
        out.push(change);
    }
    Ok(out)
}

/// Whether every parent of a change is present in the admitted store.
pub fn has_all_parents(conn: &Connection, change: &Change) -> Result<bool, SyncError> {
    for parent in &change.parents {
        if !has_change(conn, parent)? {
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
) -> Result<bool, SyncError> {
    let hash = change.compute_hash();
    if is_pruned_change(conn, change.group_id.as_str(), &hash)? {
        return Err(SyncError::NotFound(format!(
            "change {} was already pruned by a committed checkpoint",
            hash.to_hex()
        )));
    }
    if has_change(conn, &hash)? {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO changes (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            &hash.0[..],
            change.group_id.as_str(),
            change.device_id.as_str(),
            change.lamport as i64,
            change.to_wire_bytes(),
            applied as i64,
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
) -> Result<bool, SyncError> {
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
) -> Result<bool, SyncError> {
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

pub(crate) fn hash_from_blob(v: Vec<u8>) -> Result<ChangeHash, SyncError> {
    let array: [u8; 32] = v
        .try_into()
        .map_err(|_| SyncError::NotFound("change hash column is not 32 bytes".into()))?;
    Ok(ChangeHash(array))
}

/// Runs the startup repair pass for admitted history. The compact prune proof
/// tables are authoritative only for deletions that occurred inside the short
/// checkpoint->delete->sweep window; a stale context from an interrupted or
/// externally-manipulated connection is cleared before validation.
pub(crate) fn repair(conn: &Connection) -> Result<(), SyncError> {
    ensure_prune_tombstone_schema(conn)?;
    conn.execute("DELETE FROM active_prune_context", [])?;
    validate_prune_proofs(conn)?;

    let tx = conn.unchecked_transaction()?;
    // One admitted `changes` row: `(change_hash, group_id, device_id, lamport,
    // applied, encoded)`.
    type AdmittedRow = (Vec<u8>, String, String, i64, i64, Vec<u8>);
    let admitted_rows: Vec<AdmittedRow> = {
        let mut stmt = tx.prepare(
            "SELECT change_hash, group_id, device_id, lamport, applied, encoded FROM changes",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        })?;
        rows.collect::<Result<_, _>>()?
    };

    for (stored_hash, stored_group, stored_device, stored_lamport, stored_applied, encoded) in
        admitted_rows
    {
        if stored_applied != 0 && stored_applied != 1 {
            return Err(SyncError::CorruptState(format!(
                "cannot repair retained history: change {} has an invalid applied value {} (must be 0 or 1)",
                hex::encode(&stored_hash), stored_applied,
            )));
        }
        let change = Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncError::CorruptState(format!(
                "cannot repair retained history: retained change is corrupt: {error}"
            ))
        })?;
        let change_hash = change.compute_hash();
        change.validate_structure(&change_hash).map_err(|error| {
            SyncError::CorruptState(format!(
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
            SyncError::CorruptState(format!(
                "cannot repair retained history: retained change {} {reason}",
                hex::encode(&stored_hash),
            ))
        })?;
        validate_retained_parent_shape(&tx, &change)?;
        if !retained_parent_edges_match(
            &tx,
            change.group_id.as_str(),
            &change_hash,
            &change.parents,
        )? {
            return Err(SyncError::CorruptState(format!(
                "cannot repair retained history: change {}'s live/pruned parent-edge proofs disagree with its signed ancestry",
                hex::encode(change_hash.0),
            )));
        }

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
