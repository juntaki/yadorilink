//! Durable record of a change hash `admit_change` refused for a reason that
//! cannot resolve itself on retry — today, two: a change naming a
//! reserved-namespace artefact path, or a change naming a path that cannot
//! be faithfully, unambiguously stored on every platform this group may
//! sync to (see `yadorilink_root_authority::reserved_namespace`).
//!
//! Without this, a permanently-rejected hash is indistinguishable, to every
//! caller downstream of `admit_change`, from one this device simply hasn't
//! received yet: `admit_change` writes nothing on that error path (unlike a
//! successful admission or a buffered orphan, both of which land a row
//! somewhere), so the hash is neither in `changes` nor `orphan_changes`.
//! `missing_ancestor_frontier`/`has_change_or_buffered_orphan` — the only
//! two places anything decides whether to keep asking a peer for a hash —
//! then treat it as still missing forever, and every future heads-announce
//! re-requests it. This table is what lets those two functions instead
//! recognize "already decided, permanently, not just still in flight."
//!
//! Deliberately narrow: this is NOT a general-purpose "why did admission
//! fail" log. A transient admission failure (the referenced file version
//! hasn't arrived in this batch yet, a parent is still missing) must keep
//! being retried — recording one of those here would be the same bug this
//! table exists to fix, aimed the other way. Only a rejection whose cause is
//! a fixed property of the change's own content — one that re-admitting the
//! identical bytes can never resolve — belongs here.
//!
//! # A verdict is only as permanent as the rules that produced it
//!
//! "Permanent" above means "this exact change, under today's reserved-
//! namespace rules, will always be refused" — it does NOT mean the rules
//! themselves are permanent. They have already changed multiple times in
//! this module's own early history (the legacy/artefact predicate split,
//! Windows trailing-dot/space normalization, ADS-suffix and dual-separator
//! wire canonicalization), each one changing which paths are considered
//! reserved. A row recorded under an older rule set can be exactly the kind
//! of false positive a newer rule set would no longer produce — and without
//! tracking which rules produced it, nothing would ever notice: the row
//! would sit here treated as settled forever, permanently excluding content
//! a corrected predicate would happily admit. That is the same silent,
//! permanent-exclusion failure mode the reserved-namespace exclusion sites
//! were fixed to avoid, arriving through this table instead.
//!
//! Every row is therefore stamped with the [`reserved_namespace::
//! RULES_VERSION`] that produced it. [`is_change_rejected`] only trusts a
//! row stamped with the CURRENT version; an older-stamped row is treated as
//! not settled, which lets `missing_ancestor_frontier` report the hash as
//! missing again and the ordinary heads-announce protocol naturally
//! re-request and re-evaluate it under the current rules — no separate
//! sweep or migration needed. This is exactly why bumping
//! `RULES_VERSION` is mandatory whenever the rules change: it is the only
//! thing that makes re-evaluation happen.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::ids::ChangeHash;
use crate::error::SyncSqliteError;
use yadorilink_root_authority::reserved_namespace;

/// Records that `hash` was permanently rejected at admission, under the
/// reserved-namespace rules as they exist right now
/// ([`reserved_namespace::RULES_VERSION`]), so
/// `missing_ancestor_frontier`/`has_change_or_buffered_orphan` stop
/// treating it as still-missing and it is never re-requested from a peer —
/// until, if ever, the rules change and this row's stamped version falls
/// behind (see the module doc comment). Idempotent: re-recording the same
/// hash (e.g. a peer resending the exact same rejected change) just
/// overwrites the row, which is always identical for the same content and
/// the same rules version anyway (rejection is a pure function of the
/// change's own bytes plus the rules that evaluated them).
pub(crate) fn record_rejected_change(
    conn: &Connection,
    hash: &ChangeHash,
    group_id: &str,
    reason: &str,
    rejected_at_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO rejected_changes (change_hash, group_id, reason, rejected_at, rules_version) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (change_hash) DO UPDATE SET \
             group_id = excluded.group_id, \
             reason = excluded.reason, \
             rejected_at = excluded.rejected_at, \
             rules_version = excluded.rules_version",
        rusqlite::params![
            &hash.0[..],
            group_id,
            reason,
            rejected_at_unix_nanos,
            reserved_namespace::RULES_VERSION,
        ],
    )?;
    Ok(())
}

/// Whether `hash` is durably recorded as a permanent rejection **under the
/// current reserved-namespace rules**. A row stamped with an older
/// [`reserved_namespace::RULES_VERSION`] is deliberately NOT trusted as
/// settled — see the module doc comment — so this returns `false` for it,
/// exactly as if the hash had never been rejected at all: the caller's
/// normal "still missing" handling then naturally drives a fresh
/// re-request and re-evaluation under the current rules.
pub(crate) fn is_change_rejected(conn: &Connection, hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
    let stamped_version: Option<u32> = conn
        .query_row(
            "SELECT rules_version FROM rejected_changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(stamped_version == Some(reserved_namespace::RULES_VERSION))
}

/// Every hash for `group_id` durably rejected **under the current
/// reserved-namespace rules**, most recent first — the data a status
/// surface (CLI, control-socket diagnostics) would read to show a user
/// which of their own paths are stuck behind a reserved-namespace
/// collision or non-portable-path rejection and will never resolve
/// without intervention. As of this writing nothing actually calls this
/// function outside its own tests: there is no CLI command, daemon status
/// field, or `/metrics` counter that surfaces a durable rejection's exact
/// path or reason today (`SyncSqliteError::category()`'s coarse, path-free
/// category is the only thing that ever reaches
/// `yadorilink-daemon::recent_errors`, and admission rejection doesn't
/// even reach that — see the rejection-handling match arms in
/// `PeerSyncSession`'s peer-receive loop, `peer_session.rs`, which only
/// `tracing::error!` and never touch `recent_errors`). This function is
/// the reader half of the missing wiring, not a currently-used one; a
/// caller wanting to build that surface should start here rather than
/// re-deriving this query. A row stamped with an older rules version is
/// excluded, matching [`is_change_rejected`]'s own verdict — it is no
/// longer a settled rejection, only a historical one, pending
/// re-evaluation the next time the hash is offered. Read-only; never
/// consulted by any admission or projection path (those only ever need the
/// single-hash question `is_change_rejected` answers).
pub fn list_rejected_changes(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<(ChangeHash, String, i64)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT change_hash, reason, rejected_at FROM rejected_changes \
         WHERE group_id = ?1 AND rules_version = ?2 ORDER BY rejected_at DESC",
    )?;
    let rows =
        stmt.query_map(rusqlite::params![group_id, reserved_namespace::RULES_VERSION], |row| {
            let hash_blob: Vec<u8> = row.get(0)?;
            let reason: String = row.get(1)?;
            let rejected_at: i64 = row.get(2)?;
            Ok((hash_blob, reason, rejected_at))
        })?;
    let mut out = Vec::new();
    for row in rows {
        let (hash_blob, reason, rejected_at) = row?;
        let hash = crate::dag_store::retained_history_integrity::hash_from_blob(hash_blob)?;
        out.push((hash, reason, rejected_at));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_store::init_dag_schema;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_dag_schema(&c).unwrap();
        c
    }

    fn hash(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    #[test]
    fn records_and_queries_a_rejection() {
        let c = conn();
        assert!(!is_change_rejected(&c, &hash(1)).unwrap());
        record_rejected_change(&c, &hash(1), "g", "reserved namespace: foo", 100).unwrap();
        assert!(is_change_rejected(&c, &hash(1)).unwrap());
        assert!(!is_change_rejected(&c, &hash(2)).unwrap());
    }

    #[test]
    fn re_recording_the_same_hash_overwrites_rather_than_errors() {
        let c = conn();
        record_rejected_change(&c, &hash(1), "g", "first reason", 100).unwrap();
        record_rejected_change(&c, &hash(1), "g", "second reason", 200).unwrap();
        let listed = list_rejected_changes(&c, "g").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, "second reason");
        assert_eq!(listed[0].2, 200);
    }

    #[test]
    fn lists_only_the_requested_group_most_recent_first() {
        let c = conn();
        record_rejected_change(&c, &hash(1), "g1", "first", 100).unwrap();
        record_rejected_change(&c, &hash(2), "g1", "second", 200).unwrap();
        record_rejected_change(&c, &hash(3), "g2", "other group", 300).unwrap();

        let g1 = list_rejected_changes(&c, "g1").unwrap();
        assert_eq!(g1.len(), 2);
        assert_eq!(g1[0].0, hash(2), "most recent first");
        assert_eq!(g1[1].0, hash(1));

        let g2 = list_rejected_changes(&c, "g2").unwrap();
        assert_eq!(g2.len(), 1);
        assert_eq!(g2[0].0, hash(3));
    }

    /// The whole point of the version stamp: a row recorded under a rules
    /// version older than the one running right now must NOT be trusted as
    /// a settled rejection — a corrected predicate might have accepted the
    /// same change, and nothing may ever re-evaluate it if this row is
    /// allowed to stand in for that judgment forever.
    #[test]
    fn a_rejection_stamped_with_an_older_rules_version_is_not_trusted() {
        let c = conn();
        // Simulate a row recorded by a hypothetical earlier build, before
        // rewriting it through `record_rejected_change` (which always
        // stamps the CURRENT version) would defeat the point of this test.
        c.execute(
            "INSERT INTO rejected_changes (change_hash, group_id, reason, rejected_at, rules_version) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &hash(1).0[..],
                "g",
                "an old build's verdict",
                100,
                reserved_namespace::RULES_VERSION.saturating_sub(1),
            ],
        )
        .unwrap();

        assert!(
            !is_change_rejected(&c, &hash(1)).unwrap(),
            "a rejection stamped with an older rules version must not be trusted as settled"
        );
        assert!(
            list_rejected_changes(&c, "g").unwrap().is_empty(),
            "a stale-versioned row must not appear as a currently-settled rejection"
        );
    }

    /// Converse of the test above: a row stamped with the CURRENT version
    /// (what every real call through `record_rejected_change` produces) is
    /// trusted exactly as before — the version check must not make every
    /// rejection stale by accident.
    #[test]
    fn a_rejection_stamped_with_the_current_rules_version_is_trusted() {
        let c = conn();
        record_rejected_change(&c, &hash(1), "g", "current rules", 100).unwrap();
        assert!(is_change_rejected(&c, &hash(1)).unwrap());
        assert_eq!(list_rejected_changes(&c, "g").unwrap().len(), 1);
    }
}
