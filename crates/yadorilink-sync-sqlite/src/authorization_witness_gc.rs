//! Collection of authorization witnesses nothing retained still needs.
//!
//! A change's authorization evidence -- its `change_authorization` row and
//! the `authorization_checkpoints` row that row cites -- is what lets this
//! replica show a peer that the change was authorized, and what lets it
//! carry a version's authorization forward once the change that wrote the
//! version is gone. `pruned_published_change_versions` is the link that
//! does the carrying: it ties a version the replica still holds to the
//! change whose evidence authorized it.
//!
//! Nothing else ever deletes these rows, so without collection they grow
//! with every change the group has ever published, however much of that
//! history a seal has since replaced. What this module keeps instead is
//! bounded by what the replica retains: the witness of every version it
//! still holds, not of every change it ever admitted.
//!
//! Collection removes a row only when nothing here can still ask for it.
//! Evidence stays for a change that is
//!
//! * held as history: in the active DAG, waiting as an orphan, or kept as
//!   a pruned stub. Serving, the seal's "every change is published" check
//!   and a later admission all read it. The seal, the only caller today,
//!   collects after `reset_group_epoch` has emptied `changes`,
//!   `orphan_changes` and `pruned_changes`, so on that path these clauses
//!   match nothing; they are defensive, for a caller that collects without
//!   sealing, and their tests call collection directly;
//! * the author of any file row, current or not, a trashed or superseded
//!   version included. A snapshot carries every such row and must carry
//!   its evidence with it, and serving a retained version reads it;
//! * the author a version link names. The link may name another change
//!   than the row holding the version does -- a version keeps the first
//!   link it got -- and serving the version reads the link's author;
//! * a part of the recursive operation that trashed a retained row: the
//!   row's deletion is that operation's, and restoring the row answers from
//!   the operation;
//! * a head, a carried row's author or an author's tip in the summary of
//!   the base this group stands on, or an author's current tip. These are
//!   what a merge of this base with a returning branch verifies and joins,
//!   and a head the base carries is content still to be projected here
//!   even before a row holds it.
//!
//! A version link goes only when no file row of the group and no head the
//! base carries holds its version any more: it then authorizes serving
//! content this replica no longer retains.
//!
//! Evidence is scoped to its group through the checkpoint that covers it,
//! so collecting one group never touches another's. A checkpoint goes once
//! no evidence cites it.
//!
//! Collection never touches an author's watermark or tip, the summary a
//! base carries, or the snapshot and witness formats. It changes only what
//! evidence is kept, never what a kept witness says.

use std::collections::HashSet;

use rusqlite::{params, Connection};
use yadorilink_replica_domain::file::{BlockInfo, FileVersion, RecordKind};

use crate::error::SyncSqliteError;

/// What one collection removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WitnessCollection {
    /// Version links whose version nothing retained holds.
    pub version_links: usize,
    /// `change_authorization` rows nothing retained needs.
    pub change_evidence: usize,
    /// `authorization_checkpoints` rows no remaining evidence cites.
    pub checkpoints: usize,
}

/// Each query yields change hashes of group `?1` whose evidence something
/// retained still needs. The label says what needs it.
const EVIDENCE_NEEDED_BY: &[(&str, &str)] = &[
    ("the active history", "SELECT change_hash FROM changes WHERE group_id = ?1"),
    ("an orphan", "SELECT change_hash FROM orphan_changes WHERE group_id = ?1"),
    ("a pruned stub", "SELECT change_hash FROM pruned_changes WHERE group_id = ?1"),
    (
        "a file row",
        "SELECT authoring_change_hash FROM files \
         WHERE group_id = ?1 AND authoring_change_hash IS NOT NULL",
    ),
    (
        "a version link",
        "SELECT authoring_change_hash FROM pruned_published_change_versions WHERE group_id = ?1",
    ),
    (
        "the operation that trashed a row",
        "SELECT p.change_hash FROM recursive_operation_parts p \
         JOIN files f ON f.group_id = p.group_id \
                     AND f.trashed_by_operation_author = p.author_device_id \
                     AND f.trashed_by_operation_id = p.operation_id \
         WHERE p.group_id = ?1",
    ),
    (
        "a head the base carries",
        "SELECT change_hash FROM history_base_path_heads WHERE group_id = ?1",
    ),
    (
        "a row the base carries",
        "SELECT change_hash FROM history_base_carried_authors WHERE group_id = ?1",
    ),
    (
        "an author tip the base carries",
        "SELECT tip_change_hash FROM history_base_author_state WHERE group_id = ?1",
    ),
    ("an author's tip", "SELECT tip_change_hash FROM author_chain_state WHERE group_id = ?1"),
];

/// Removes every authorization witness of `group_id` nothing retained still
/// needs: version links to versions no longer held, then the evidence no
/// retained row, link, history or summary names, then the checkpoints left
/// uncited. Runs on the caller's connection, so inside the caller's
/// transaction when there is one.
pub fn collect_authorization_witnesses(
    conn: &Connection,
    group_id: &str,
) -> Result<WitnessCollection, SyncSqliteError> {
    let version_links = collect_version_links(conn, group_id)?;

    let needed =
        EVIDENCE_NEEDED_BY.iter().map(|(_, query)| *query).collect::<Vec<_>>().join(" UNION ");
    // `NOT IN` over a list holding NULL is never true, so a needed-set
    // query that ever yielded NULL would keep everything rather than
    // delete anything.
    let change_evidence = conn.execute(
        &format!(
            "DELETE FROM change_authorization \
             WHERE checkpoint_hash IN \
                   (SELECT checkpoint_hash FROM authorization_checkpoints WHERE group_id = ?1) \
               AND change_hash NOT IN ({needed})"
        ),
        params![group_id],
    )?;

    let checkpoints = conn.execute(
        "DELETE FROM authorization_checkpoints \
         WHERE group_id = ?1 \
           AND NOT EXISTS (SELECT 1 FROM change_authorization ca \
                           WHERE ca.checkpoint_hash = authorization_checkpoints.checkpoint_hash)",
        params![group_id],
    )?;

    Ok(WitnessCollection { version_links, change_evidence, checkpoints })
}

/// Drops every version link of `group_id` whose version no file row of the
/// group and no head its base carries holds.
fn collect_version_links(conn: &Connection, group_id: &str) -> Result<usize, SyncSqliteError> {
    let held = held_versions(conn, group_id)?;
    let linked: Vec<Vec<u8>> = {
        let mut stmt = conn.prepare(
            "SELECT version_hash FROM pruned_published_change_versions WHERE group_id = ?1",
        )?;
        let rows = stmt.query_map([group_id], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut removed = 0;
    for version in linked {
        if held.contains(&version) {
            continue;
        }
        removed += conn.execute(
            "DELETE FROM pruned_published_change_versions \
             WHERE group_id = ?1 AND version_hash = ?2",
            params![group_id, &version[..]],
        )?;
    }
    Ok(removed)
}

/// Every version a file row of `group_id` holds, whatever its state, and
/// every version a head its base carries holds. A row's version is derived
/// exactly as a seal derives it when it links the row's version.
fn held_versions(conn: &Connection, group_id: &str) -> Result<HashSet<Vec<u8>>, SyncSqliteError> {
    let mut held = HashSet::new();
    {
        let mut stmt = conn.prepare(
            "SELECT blocks_json, size, mtime_unix_nanos, record_kind, unix_mode, symlink_target, \
                    xattrs_json \
             FROM files WHERE group_id = ?1",
        )?;
        let mut rows = stmt.query([group_id])?;
        while let Some(row) = rows.next()? {
            let blocks_json: String = row.get(0)?;
            let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json)?;
            let xattrs_json: String = row.get(6)?;
            let version = FileVersion::from_index_row(
                blocks,
                row.get::<_, i64>(1)? as u64,
                row.get(2)?,
                RecordKind::from_db_str(&row.get::<_, String>(3)?),
                crate::file_index::decode_unix_mode_column(row.get(4)?),
                row.get(5)?,
                crate::file_index::decode_xattrs_column(&xattrs_json)?,
            );
            held.insert(version.version_hash.0.to_vec());
        }
    }
    let mut stmt =
        conn.prepare("SELECT version_hash FROM history_base_path_heads WHERE group_id = ?1")?;
    let rows = stmt.query_map([group_id], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        held.insert(row?);
    }
    Ok(held)
}

#[cfg(test)]
mod tests;
