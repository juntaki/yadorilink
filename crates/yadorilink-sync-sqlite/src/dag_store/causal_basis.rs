//! Canonical causal bases: a content-addressed, deduplicated encoding of an
//! arbitrary causal frontier -- a set of change hashes -- shared across every
//! path that frontier backs.
//!
//! A materialized generation -- a stable on-disk file -- is derived from a specific
//! DAG frontier, not from one path in isolation. Interning that frontier once
//! and referencing it by `basis_id` means a million paths that happen to
//! share the same frontier -- the ordinary case right after any batch of
//! changes lands -- store one frontier, not a million copies of it. The
//! encoding is canonical (ascending, deduped) in the same style as
//! `yadorilink_replica_domain::rebootstrap::Checkpoint::canonical_encoding`, so the same logical
//! frontier always produces the same `basis_id` regardless of the order its
//! members were discovered in.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::ids::ChangeHash;

const CAUSAL_BASIS_DOMAIN_TAG: &[u8; 8] = b"YLNKbas\x01";

/// Version stamp for [`canonical_basis_encoding`]'s layout, stored alongside
/// each interned basis so a future layout change is detectable rather than
/// silently misread.
pub const CAUSAL_BASIS_ENCODING_VERSION: i32 = 1;

pub(crate) fn init_causal_basis_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS causal_basis_sets (
            basis_id         TEXT NOT NULL PRIMARY KEY,
            group_id         TEXT NOT NULL,
            frontier_hash    BLOB NOT NULL,
            encoding_version INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS causal_basis_sets_by_group
            ON causal_basis_sets(group_id);

        CREATE TABLE IF NOT EXISTS causal_basis_members (
            basis_id    TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (basis_id, change_hash)
        );
        "#,
    )?;
    Ok(())
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, value: &str) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
}

/// The canonical, ascending, deduplicated encoding of `group_id`'s frontier
/// `members` -- the bytes hashed to form the frontier's content-addressed
/// identity. `members` need not already be sorted or deduped; this
/// normalizes them, exactly like `Checkpoint::new`.
fn canonical_basis_encoding(group_id: &str, members: &[ChangeHash]) -> Vec<u8> {
    let mut normalized = members.to_vec();
    normalized.sort();
    normalized.dedup();
    let mut buf = Vec::new();
    buf.extend_from_slice(CAUSAL_BASIS_DOMAIN_TAG);
    put_str(&mut buf, group_id);
    put_u32(&mut buf, normalized.len() as u32);
    for hash in &normalized {
        buf.extend_from_slice(&hash.0);
    }
    buf
}

fn frontier_hash(group_id: &str, members: &[ChangeHash]) -> [u8; 32] {
    Sha256::digest(canonical_basis_encoding(group_id, members)).into()
}

/// The `basis_id` a frontier interns under: the group scope followed by the
/// hex-encoded frontier hash. Scoping by group inside the id itself (rather
/// than relying on callers to always join by `group_id` too) means a
/// `causal_basis_members` lookup by `basis_id` alone can never be handed a
/// frontier from a different group.
fn basis_id_for(group_id: &str, hash: &[u8; 32]) -> String {
    format!("{group_id}:{}", hex::encode(hash))
}

/// Interns `group_id`'s causal frontier `members` (an arbitrary set of
/// change hashes -- typically a change's own `parents`, or a materialized
/// generation's basis), returning its content-addressed `basis_id`.
/// Idempotent and deduplicated: interning the same frontier twice (from the
/// same or a different caller) is a no-op past the first call, and produces
/// the identical `basis_id` both times.
pub fn intern_causal_basis(
    conn: &Connection,
    group_id: &str,
    members: &[ChangeHash],
) -> Result<String, SyncSqliteError> {
    let mut normalized = members.to_vec();
    normalized.sort();
    normalized.dedup();
    let hash = frontier_hash(group_id, &normalized);
    let basis_id = basis_id_for(group_id, &hash);
    conn.execute(
        "INSERT OR IGNORE INTO causal_basis_sets \
         (basis_id, group_id, frontier_hash, encoding_version) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![basis_id, group_id, &hash[..], CAUSAL_BASIS_ENCODING_VERSION],
    )?;
    for member in &normalized {
        conn.execute(
            "INSERT OR IGNORE INTO causal_basis_members (basis_id, change_hash) VALUES (?1, ?2)",
            rusqlite::params![basis_id, &member.0[..]],
        )?;
    }
    Ok(basis_id)
}

/// The exact member set a previously interned `basis_id` names, ascending by
/// hash, or `None` if this basis was never interned (or has since been
/// removed -- basis rows are otherwise permanent, this crate never deletes
/// one on its own).
pub fn lookup_causal_basis_members(
    conn: &Connection,
    basis_id: &str,
) -> Result<Option<Vec<ChangeHash>>, SyncSqliteError> {
    let known: Option<i64> = conn
        .query_row("SELECT 1 FROM causal_basis_sets WHERE basis_id = ?1", [basis_id], |row| {
            row.get(0)
        })
        .optional()?;
    if known.is_none() {
        return Ok(None);
    }
    let mut stmt = conn.prepare(
        "SELECT change_hash FROM causal_basis_members WHERE basis_id = ?1 ORDER BY change_hash",
    )?;
    let rows = stmt.query_map([basis_id], |row| row.get::<_, Vec<u8>>(0))?;
    let mut members = Vec::new();
    for row in rows {
        members.push(super::retained_history_integrity::hash_from_blob(row?)?);
    }
    Ok(Some(members))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_causal_basis_schema(&conn).unwrap();
        conn
    }

    fn h(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    #[test]
    fn same_frontier_interns_to_the_same_basis_id_regardless_of_input_order() {
        let conn = open();
        let a = intern_causal_basis(&conn, "g", &[h(1), h(2), h(3)]).unwrap();
        let b = intern_causal_basis(&conn, "g", &[h(3), h(1), h(2)]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn duplicate_members_in_the_input_do_not_change_the_basis_id() {
        let conn = open();
        let a = intern_causal_basis(&conn, "g", &[h(1), h(2)]).unwrap();
        let b = intern_causal_basis(&conn, "g", &[h(1), h(1), h(2), h(2)]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_million_paths_sharing_one_frontier_create_one_basis_row() {
        let conn = open();
        let frontier = [h(1), h(2), h(3)];
        for _ in 0..1000 {
            intern_causal_basis(&conn, "g", &frontier).unwrap();
        }
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM causal_basis_sets", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "interning the same frontier repeatedly must dedup to one row");
    }

    #[test]
    fn different_groups_with_the_same_member_hashes_intern_separately() {
        let conn = open();
        let a = intern_causal_basis(&conn, "g1", &[h(1)]).unwrap();
        let b = intern_causal_basis(&conn, "g2", &[h(1)]).unwrap();
        assert_ne!(a, b, "the same change hash under a different group must be a distinct basis");
    }

    #[test]
    fn lookup_returns_the_exact_ascending_member_set() {
        let conn = open();
        let basis_id = intern_causal_basis(&conn, "g", &[h(3), h(1), h(2)]).unwrap();
        let members = lookup_causal_basis_members(&conn, &basis_id).unwrap().unwrap();
        assert_eq!(members, vec![h(1), h(2), h(3)]);
    }

    #[test]
    fn lookup_of_an_unknown_basis_id_is_none() {
        let conn = open();
        assert!(lookup_causal_basis_members(&conn, "g:deadbeef").unwrap().is_none());
    }

    #[test]
    fn an_empty_frontier_interns_to_a_stable_basis_with_no_members() {
        let conn = open();
        let basis_id = intern_causal_basis(&conn, "g", &[]).unwrap();
        let members = lookup_causal_basis_members(&conn, &basis_id).unwrap().unwrap();
        assert!(members.is_empty());
    }
}
