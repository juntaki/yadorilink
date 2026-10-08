//! Which model authorizes a group's rows (`group_authority`).
//!
//! Absent means the group has no recorded authority, and the native authoring
//! gate does not apply to it. A group is native only through
//! [`adopt_native_if_fresh`], which refuses to infer the authority of a group
//! that already has indexed rows. The authoring gate in the schema reads
//! this table, so the trigger and the unauthored-row query share one rule.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;

/// The authority recorded for `group_id`: `None` when none is recorded.
pub fn recorded_authority(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<String>, SyncSqliteError> {
    Ok(conn
        .query_row("SELECT authority FROM group_authority WHERE group_id = ?1", [group_id], |row| {
            row.get(0)
        })
        .optional()?)
}

/// Records `group_id` as native when it has no indexed row yet: rows that
/// pre-date the authority are not native. Idempotent, and
/// never changes an authority already recorded. Returns whether the group is
/// native afterwards.
pub fn adopt_native_if_fresh(conn: &Connection, group_id: &str) -> Result<bool, SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO group_authority (group_id, authority) \
         SELECT ?1, 'native' \
          WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND version_seq > 0)",
        [group_id],
    )?;
    Ok(recorded_authority(conn, group_id)?.as_deref() == Some("native"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    #[test]
    fn a_fresh_group_is_adopted_once_and_stays_native() {
        let c = conn();
        assert_eq!(recorded_authority(&c, "g").unwrap(), None);
        assert!(adopt_native_if_fresh(&c, "g").unwrap());
        assert!(adopt_native_if_fresh(&c, "g").unwrap(), "idempotent");
        assert_eq!(recorded_authority(&c, "g").unwrap().as_deref(), Some("native"));
    }

    #[test]
    fn a_group_with_indexed_rows_is_never_inferred_native() {
        let c = conn();
        c.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json) \
             VALUES ('g', 'a', 0, 0, '[]')",
            [],
        )
        .unwrap();
        assert!(!adopt_native_if_fresh(&c, "g").unwrap());
        assert_eq!(recorded_authority(&c, "g").unwrap(), None);
    }

    /// Once native, the gate refuses a current row that names no native head,
    /// but only when the group has native history: before that the initial
    /// scan may write rows the import has not bound yet.
    #[test]
    fn a_native_group_refuses_an_identity_less_row_once_it_has_native_history() {
        let c = conn();
        adopt_native_if_fresh(&c, "g").unwrap();
        let insert = |path: &str| {
            c.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                                    version_seq, state) VALUES ('g', ?1, 0, 0, '[]', 1, 'current')",
                [path],
            )
        };
        insert("before-history").expect("no native history yet: rows may be unbound");
        c.execute(
            "INSERT INTO native_authoring_witness (group_id, identity, version) \
             VALUES ('g', X'01', X'01')",
            [],
        )
        .unwrap();
        let error = insert("after-history").unwrap_err();
        assert!(error.to_string().contains("verified authoring identity"), "{error}");
        // A tombstone names no content and needs no identity.
        c.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                                version_seq, state) VALUES ('g', 'gone', 0, 0, '[]', 1, 1, 'current')",
            [],
        )
        .unwrap();
        // A group with no recorded authority is untouched by the native rule:
        // no gate.
        c.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                                version_seq, state) VALUES ('other', 'p', 0, 0, '[]', 1, 'current')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn authority_is_one_of_the_two_models() {
        let c = conn();
        assert!(c
            .execute("INSERT INTO group_authority (group_id, authority) VALUES ('g', 'other')", [])
            .is_err());
    }
}
