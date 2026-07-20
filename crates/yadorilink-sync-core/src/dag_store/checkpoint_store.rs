//! `change_checkpoints`: condensed pruned prefixes, one row per committed
//! compaction checkpoint, newest-wins by `seq` per group. Re-bootstrap logic
//! needs exactly one authoritative snapshot identity per group, so `encoded`
//! is re-verified against the row's own `checkpoint_hash`/`group_id`/
//! `snapshot_hash` columns rather than trusted at face value.

use rusqlite::Connection;

use crate::error::SyncError;

fn decode_verified_row(
    stored_hash: &[u8],
    stored_group: &str,
    stored_snapshot_hash: &[u8],
    encoded: &[u8],
) -> Result<crate::compaction::Checkpoint, SyncError> {
    let checkpoint = crate::compaction::Checkpoint::decode(encoded)?;
    if checkpoint.checkpoint_hash().0[..] != *stored_hash {
        return Err(SyncError::CorruptState(format!(
            "retained checkpoint for group {stored_group} is stored under a key that does not \
             match its encoded hash"
        )));
    }
    if checkpoint.group_id.as_str() != stored_group {
        return Err(SyncError::CorruptState(format!(
            "retained checkpoint row for group {stored_group} does not match the group_id encoded \
             in its body"
        )));
    }
    if checkpoint.snapshot_hash[..] != *stored_snapshot_hash {
        return Err(SyncError::CorruptState(format!(
            "retained checkpoint for group {stored_group} has a snapshot_hash column that disagrees \
             with its encoded body"
        )));
    }
    Ok(checkpoint)
}

/// Re-verifies every retained checkpoint row, not only whichever row currently
/// wins the latest-sequence query. Prune tombstones name the checkpoint that
/// authorized their deletion, so an older checkpoint is still part of the
/// integrity boundary after a newer one is committed and cannot be left as an
/// unchecked blob that tombstone validation merely joins against by key.
pub(crate) fn validate_all(conn: &Connection) -> Result<(), SyncError> {
    let rows: Vec<(Vec<u8>, String, Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT checkpoint_hash, group_id, snapshot_hash, encoded FROM change_checkpoints",
        )?;
        let rows =
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (stored_hash, stored_group, stored_snapshot_hash, encoded) in rows {
        decode_verified_row(&stored_hash, &stored_group, &stored_snapshot_hash, &encoded)?;
    }
    Ok(())
}

/// The latest checkpoint for a group, decoded from its stored bytes, or `None`.
/// "Latest" is the highest `seq` — the most recently committed prune. More
/// than one row at that highest sequence is corrupt state: re-bootstrap needs
/// one authoritative snapshot identity and must never let SQLite's row order
/// choose between two competing latest checkpoints.
pub fn latest_checkpoint(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<crate::compaction::Checkpoint>, SyncError> {
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT checkpoint_hash, snapshot_hash, encoded FROM change_checkpoints \
             WHERE group_id = ?1 \
               AND seq = (SELECT MAX(seq) FROM change_checkpoints WHERE group_id = ?1) \
             ORDER BY checkpoint_hash LIMIT 2",
        )?;
        let rows = stmt.query_map([group_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    if rows.len() > 1 {
        return Err(SyncError::CorruptState(format!(
            "retained checkpoints for group {group_id} contain more than one row at the latest sequence"
        )));
    }
    let Some((stored_hash, stored_snapshot_hash, encoded)) = rows.into_iter().next() else {
        return Ok(None);
    };
    decode_verified_row(&stored_hash, group_id, &stored_snapshot_hash, &encoded).map(Some)
}
