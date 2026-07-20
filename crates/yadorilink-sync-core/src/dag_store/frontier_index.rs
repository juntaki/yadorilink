//! The DAG frontier: `group_heads` (the current non-superseded leaf set per
//! group, which local emission signs a new change's parents from) and
//! `device_frontier` (each device's last-acknowledged head set, used to
//! decide what history is safe to compact). `group_heads` is a derived
//! index of `changes`/`change_parents`, not independent fact -- [`repair`]
//! reconstructs it from that source rather than trusting it, since local
//! emission otherwise trusts whatever it finds unconditionally.

use rusqlite::Connection;

use super::retained_history_integrity::{hash_from_blob, lamport_of};
use crate::change::ChangeHash;
use crate::error::SyncError;

/// The largest logical clock among those of `parents` that are present.
/// Missing parents contribute nothing; an empty/rootless set yields 0, so a
/// root change gets `lamport = 1`.
pub fn max_parent_lamport(conn: &Connection, parents: &[ChangeHash]) -> Result<u64, SyncError> {
    let mut max = 0u64;
    for p in parents {
        if let Some(l) = lamport_of(conn, p)? {
            max = max.max(l);
        }
    }
    Ok(max)
}

/// The current non-superseded heads for a group.
pub fn group_heads(conn: &Connection, group_id: &str) -> Result<Vec<ChangeHash>, SyncError> {
    let mut stmt = conn
        .prepare("SELECT change_hash FROM group_heads WHERE group_id = ?1 ORDER BY change_hash")?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_from_blob(row?)?);
    }
    Ok(out)
}

/// The device's acknowledged frontier for a group: every head it last reported,
/// ascending by hash. Empty if the device has never reported one.
pub fn get_device_frontier(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
) -> Result<Vec<ChangeHash>, SyncError> {
    let mut stmt = conn.prepare(
        "SELECT change_hash FROM device_frontier \
         WHERE group_id = ?1 AND device_id = ?2 ORDER BY change_hash",
    )?;
    let rows =
        stmt.query_map(rusqlite::params![group_id, device_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_from_blob(row?)?);
    }
    Ok(out)
}

/// Replaces a device's acknowledged frontier for a group with `heads` (one row
/// per head). The delete+insert must share a transaction to be atomic — the
/// store methods that call this run it inside one.
pub fn set_device_frontier(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
    heads: &[ChangeHash],
) -> Result<(), SyncError> {
    conn.execute(
        "DELETE FROM device_frontier WHERE group_id = ?1 AND device_id = ?2",
        rusqlite::params![group_id, device_id],
    )?;
    for head in heads {
        conn.execute(
            "INSERT OR IGNORE INTO device_frontier (group_id, device_id, change_hash) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![group_id, device_id, &head.0[..]],
        )?;
    }
    Ok(())
}

/// Drops a device's recorded frontier for a group — the un-enrollment hook, so
/// a removed device no longer constrains what history is prunable.
pub fn remove_device_frontier(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
) -> Result<(), SyncError> {
    conn.execute(
        "DELETE FROM device_frontier WHERE group_id = ?1 AND device_id = ?2",
        rusqlite::params![group_id, device_id],
    )?;
    Ok(())
}

/// Reconstructs `group_heads` from the admitted DAG's exact leaf set.
///
/// This is a derived index, so startup replaces the table wholesale rather
/// than iterating only groups currently present in `changes`. The latter leaves
/// a subtle poison state behind when a group's durable history is empty but a
/// stale/forged `group_heads` row survives: no `changes` row names that group,
/// so a per-`changes` repair never visits it and the next local emission treats
/// the ghost hash as a parent. A full rebuild also keeps the ownership rule
/// simple: admitted `changes` + admitted-child `change_parents` are the sole
/// source of truth.
///
/// The child side is joined to `changes` because buffered (or historically
/// evicted) orphans may have `change_parents` rows before they are admitted;
/// those edges must not make a genuine admitted leaf look superseded.
pub(crate) fn repair(conn: &Connection) -> Result<(), SyncError> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM group_heads", [])?;
    tx.execute(
        "INSERT INTO group_heads (group_id, change_hash) \
         SELECT c.group_id, c.change_hash FROM changes c \
         WHERE NOT EXISTS (\
             SELECT 1 FROM change_parents cp \
             JOIN changes cc ON cc.change_hash = cp.child_hash \
             WHERE cp.parent_hash = c.change_hash)",
        [],
    )?;
    tx.commit()?;
    Ok(())
}
