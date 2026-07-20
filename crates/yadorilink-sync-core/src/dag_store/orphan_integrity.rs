//! The `orphan_changes` table: a bounded, best-effort holding buffer for
//! changes that arrived before their ancestry. A row here is never treated as
//! durable history -- corrupt, structurally invalid, or ancestry-inconsistent
//! rows are dropped rather than fail-closed, and [`promote_orphans`] moves a
//! ready row into `super::retained_history_integrity`'s `changes` table once
//! its parents are present.

use rusqlite::Connection;

use crate::change::{Change, ChangeHash};
use crate::error::SyncError;

/// Upper bound on the orphan buffer. A change whose parents never arrive
/// cannot grow the store without limit: once this many orphans are held, the
/// oldest are evicted (and would be re-requested by a later heads exchange).
pub const ORPHAN_BOUND: usize = 4096;

/// Buffers a change whose ancestry is not yet complete. Evicts the oldest
/// orphans once the bound is exceeded (see `ORPHAN_BOUND`).
pub(crate) fn insert_orphan(
    conn: &Connection,
    change: &Change,
    applied: bool,
) -> Result<(), SyncError> {
    let hash = change.compute_hash();
    let next_seq: i64 =
        conn.query_row("SELECT COALESCE(MAX(received_seq), 0) + 1 FROM orphan_changes", [], |r| {
            r.get(0)
        })?;
    conn.execute(
        "INSERT OR IGNORE INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, applied, received_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &hash.0[..],
            change.group_id.as_str(),
            change.device_id.as_str(),
            change.lamport as i64,
            change.to_wire_bytes(),
            applied as i64,
            next_seq,
        ],
    )?;
    // Bound the buffer: keep the newest `ORPHAN_BOUND`, evict older ones. The
    // `change_parents` edges recorded for an evicted orphan's declared
    // parents must go with it -- left behind, a ghost edge under a hash no
    // longer in `orphan_changes` (and never in `changes` either) would make
    // `frontier_index::repair` think that parent still has a child and drop
    // it out of `group_heads`. Deleted first, while the eviction set is
    // still computable from the still-present `orphan_changes` rows.
    conn.execute(
        "DELETE FROM change_parents WHERE child_hash IN (\
             SELECT change_hash FROM orphan_changes ORDER BY received_seq DESC LIMIT -1 OFFSET ?1)",
        [ORPHAN_BOUND as i64],
    )?;
    conn.execute(
        "DELETE FROM orphan_changes WHERE change_hash IN (\
             SELECT change_hash FROM orphan_changes ORDER BY received_seq DESC LIMIT -1 OFFSET ?1)",
        [ORPHAN_BOUND as i64],
    )?;
    Ok(())
}

/// Promotes every orphan whose ancestry is now complete into the applied
/// store, repeating until no orphan can be promoted (promoting one may
/// unblock another). Returns the hashes of the changes that were promoted, in
/// the order they were appended — the caller projects each promoted orphan's
/// paths, so it needs the identities, not just a count.
pub fn promote_orphans(conn: &Connection) -> Result<Vec<ChangeHash>, SyncError> {
    let mut promoted: Vec<ChangeHash> = Vec::new();
    loop {
        // Orphans with no still-missing parent.
        let ready: Vec<(Vec<u8>, Vec<u8>, bool)> = {
            let mut stmt = conn.prepare(
                "SELECT o.change_hash, o.encoded, o.applied FROM orphan_changes o \
                 WHERE NOT EXISTS (\
                     SELECT 1 FROM change_parents cp \
                     WHERE cp.child_hash = o.change_hash \
                       AND NOT EXISTS (SELECT 1 FROM changes c WHERE c.change_hash = cp.parent_hash))\
                 ORDER BY o.received_seq",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, i64>(2)? != 0))
            })?;
            let mut v = Vec::new();
            for row in rows {
                v.push(row?);
            }
            v
        };
        // An orphan whose parent edges were never recorded (its parents were
        // unknown at insert) still needs checking against the decoded change.
        let mut made_progress = false;
        for (hash_blob, encoded, applied) in ready {
            let change = match Change::from_wire_bytes(&encoded) {
                Ok(c) => c,
                Err(_) => {
                    // Corrupt buffered bytes: drop it rather than wedge the loop.
                    drop_orphan_change(conn, &hash_blob)?;
                    continue;
                }
            };
            if !super::retained_history_integrity::has_all_parents(conn, &change)? {
                continue;
            }
            super::serving_authorization_index::validate_referenced_versions(conn, &change)?;
            super::retained_history_integrity::validate_present_parent_shape(conn, &change)?;
            conn.execute("DELETE FROM orphan_changes WHERE change_hash = ?1", [&hash_blob[..]])?;
            let real_hash = change.compute_hash();
            if real_hash.0[..] != hash_blob[..] {
                // Stored under a key that disagrees with its own encoded
                // hash (corrupted/tampered storage key, not the content
                // itself, which is otherwise valid and admissible under its
                // real hash below): the row's own `change_parents` edges are
                // keyed by that bogus hash, not the real one `append_change`
                // is about to use, so they would become permanently
                // unreachable ghost ancestry once the row above is gone.
                conn.execute("DELETE FROM change_parents WHERE child_hash = ?1", [&hash_blob[..]])?;
            }
            if super::retained_history_integrity::append_change(conn, &change, applied)? {
                promoted.push(real_hash);
            }
            made_progress = true;
        }
        if !made_progress {
            break;
        }
    }
    Ok(promoted)
}

/// Evicts an orphan repair could not give a verifiable version to (or whose
/// storage key, row metadata, ancestry edges, or structure disagree with its
/// own decoded body), along with the parent edges recorded for it. An
/// unrepairable or inconsistent orphan can never pass
/// `validate_referenced_versions`/`validate_present_parent_shape`, so
/// leaving it buffered would make `promote_orphans` error -- via `?`, not a
/// skip -- every time its parent becomes ready, poisoning that call (and the
/// admission transaction it runs inside) instead of just this one change.
/// Matches `promote_orphans`'s own handling of corrupt buffered bytes:
/// dropped, not fatal, since an orphan is a re-sendable best-effort buffer,
/// not durable history.
fn drop_orphan_change(conn: &Connection, change_hash: &[u8]) -> Result<(), SyncError> {
    conn.execute("DELETE FROM change_parents WHERE child_hash = ?1", [change_hash])?;
    conn.execute("DELETE FROM change_file_versions WHERE change_hash = ?1", [change_hash])?;
    conn.execute("DELETE FROM orphan_changes WHERE change_hash = ?1", [change_hash])?;
    Ok(())
}

/// Runs the startup repair pass for `orphan_changes`: every buffered row must
/// decode, be structurally valid, agree with its own storage key/row
/// metadata, and have `change_parents` edges matching its declared ancestry
/// -- otherwise it is dropped (never fail-closed; see the module doc). A row
/// that passes all of those still needs a verifiable `file_versions` entry
/// for every version its ops reference; `repair_change_file_versions`
/// resolves or clones that, and reports `false` (also dropped) when it
/// cannot.
/// One buffered `orphan_changes` row: `(change_hash, group_id, device_id,
/// lamport, encoded)`.
type OrphanRow = (Vec<u8>, String, String, i64, Vec<u8>);

pub(crate) fn repair(conn: &Connection) -> Result<(), SyncError> {
    let tx = conn.unchecked_transaction()?;
    let buffered_rows: Vec<OrphanRow> = {
        let mut stmt = tx.prepare(
            "SELECT change_hash, group_id, device_id, lamport, encoded FROM orphan_changes",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?;
        rows.collect::<Result<_, _>>()?
    };
    for (stored_hash, stored_group, stored_device, stored_lamport, encoded) in buffered_rows {
        let change = match Change::from_wire_bytes(&encoded) {
            Ok(change) => change,
            Err(_) => {
                drop_orphan_change(&tx, &stored_hash)?;
                continue;
            }
        };
        let change_hash = change.compute_hash();
        if change.validate_structure(&change_hash).is_err() {
            drop_orphan_change(&tx, &stored_hash)?;
            continue;
        }
        if super::retained_history_integrity::verify_retained_change_identity(
            &change,
            &stored_hash,
            &stored_group,
            &stored_device,
            stored_lamport,
        )
        .is_err()
        {
            drop_orphan_change(&tx, &stored_hash)?;
            continue;
        }
        if !super::retained_history_integrity::parent_edges_match(
            &tx,
            &change_hash,
            &change.parents,
        )? {
            drop_orphan_change(&tx, &stored_hash)?;
            continue;
        }
        if !super::serving_authorization_index::repair_change_file_versions(&tx, &change, false)? {
            drop_orphan_change(&tx, &stored_hash)?;
        }
    }
    tx.commit()?;
    Ok(())
}
