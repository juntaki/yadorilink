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
//! Every row is therefore stamped with the rules that produced it, and a
//! row is only trusted as a settled verdict while that stamp still matches
//! the rules running now. An older-stamped row is treated as not settled,
//! which lets `missing_ancestor_frontier` report the hash as missing again
//! and the ordinary heads-announce protocol naturally re-request and
//! re-evaluate it under the current rules — no separate sweep or migration
//! needed. Bumping a rules version is therefore mandatory whenever those
//! rules change: it is the only thing that makes re-evaluation happen.
//!
//! # Rules from different domains are versioned separately
//!
//! The stamp is a [`RejectionDomain`] plus that domain's own version, not
//! one number for everything. Path admissibility and the author chain are
//! different rule sets that change for different reasons and on different
//! days. Stamping an author-chain rejection with the reserved-namespace
//! version means a change to the author chain leaves every old
//! author-chain rejection still looking current — permanently excluding
//! changes the new rules would admit, which is precisely the silent
//! stranding the versioning exists to prevent — while a reserved-namespace
//! bump needlessly re-opens every author-chain verdict, asking peers for
//! changes whose verdict cannot have changed. One version per domain, and
//! each domain answers only for its own rules.
//!
//! # A verdict that follows from another one stands only while that one does
//!
//! A change refused because a change it depends on can never be held here —
//! a DAG parent, or the previous change of its own author — has no verdict
//! of its own. It carries its basis's `(domain, version)` stamp, so a rules
//! move that re-opens the basis re-opens it too, and it also names the
//! basis in `rests_on`. It is trusted as settled only while its own stamp is
//! current AND the change it rests on is still refused under current rules
//! and still not held here, re-derived on every read by following
//! `rests_on` to a verdict of its own. The stamp alone would not be enough:
//! a basis can stop being refused without its domain's rules moving — a
//! change refused as coming from another history becomes admissible once
//! this replica re-bootstraps onto that history — and a dependent that kept
//! its copy of the old stamp would stay excluded on a verdict nobody holds.
//!
//! # A verdict measured against this replica's history stands only on it
//!
//! "Written on another history" is decided against the history this replica
//! is on, which is local state that a re-bootstrap moves. Such a row names
//! that history in `refused_on_epoch`, and is trusted as settled only while
//! the group is still on it. Once the replica installs the history the
//! change was written on, the row lapses, the change is asked for again,
//! and every refusal resting on it lapses with it.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::rebootstrap::HistoryEpoch;
use yadorilink_root_authority::reserved_namespace;

/// Which body of rules produced a durable rejection, and therefore which
/// version stamp decides whether that rejection is still current.
///
/// A row is re-opened for re-evaluation when ITS domain's rules move, and
/// left alone when some unrelated domain's do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectionDomain {
    /// The change names a path that cannot be stored faithfully and
    /// unambiguously everywhere this group may sync to, or that collides
    /// with the reserved artefact namespace. Versioned by
    /// [`reserved_namespace::RULES_VERSION`], which moves whenever the set
    /// of paths this project considers reserved or non-portable moves.
    Path,
    /// The change's own author's chain cannot take it: the wrong position,
    /// a second change at one position, or a position that names a
    /// different previous change of its own than this replica holds.
    ///
    /// Versioned separately from `Path` because it changes for entirely
    /// unrelated reasons. The current version dates from author ordering
    /// being separated from DAG causality: before that, a change at the
    /// right sequence had to DESCEND its author's tip in the DAG, and an
    /// ordinary local edit authored onto the basis its own bytes came from
    /// was refused by that rule. Every rejection recorded under it is
    /// suspect, so the bump re-opens all of them.
    AuthorChain,
}

/// The author-chain rules' own version. Bump whenever what the author
/// chain admits changes at all, exactly as
/// [`reserved_namespace::RULES_VERSION`] is bumped for path rules: a
/// rejection recorded under superseded rules must stop looking settled, or
/// a change the new rules would admit stays excluded forever with nothing
/// to notice.
const AUTHOR_CHAIN_RULES_VERSION: u32 = 1;

impl RejectionDomain {
    /// The stable string stored in `rejected_changes.rejection_domain`.
    /// Spelled out rather than an integer so a row read by a human says
    /// what it is; never reused for a different meaning.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::AuthorChain => "author-chain",
        }
    }

    /// This domain's rules version as it stands in this build.
    pub(crate) fn rules_version(self) -> u32 {
        match self {
            Self::Path => reserved_namespace::RULES_VERSION,
            Self::AuthorChain => AUTHOR_CHAIN_RULES_VERSION,
        }
    }
}

/// Records that `hash` was permanently rejected at admission, under
/// `domain`'s rules as they exist right now, so
/// `missing_ancestor_frontier`/`has_change_or_buffered_orphan` stop
/// treating it as still-missing and it is never re-requested from a peer —
/// until, if ever, THOSE rules change and this row's stamped version falls
/// behind (see the module doc comment). Idempotent: re-recording the same
/// hash (e.g. a peer resending the exact same rejected change) just
/// overwrites the row, which is always identical for the same content and
/// the same rules anyway (rejection is a pure function of the change's own
/// bytes plus the rules that evaluated them).
#[cfg(test)]
pub(crate) fn record_rejected_change(
    conn: &Connection,
    hash: &ChangeHash,
    group_id: &str,
    domain: RejectionDomain,
    reason: &str,
    rejected_at_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    record_rejected_change_resting_on(
        conn,
        hash,
        group_id,
        domain,
        None,
        None,
        reason,
        rejected_at_unix_nanos,
    )
}

/// [`record_rejected_change`] for a verdict that follows from another
/// change's refusal: `domain` is the domain that refused `rests_on`, and the
/// row stands only while `rests_on` stays refused and unheld (see the module
/// doc comment). `None` records a verdict of the change's own.
///
/// `refused_on` is the history this replica was on when a verdict measured
/// against it was reached; the row then stands only while the group stays on
/// that history. `None` for a verdict independent of the local history.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_rejected_change_resting_on(
    conn: &Connection,
    hash: &ChangeHash,
    group_id: &str,
    domain: RejectionDomain,
    rests_on: Option<&ChangeHash>,
    refused_on: Option<HistoryEpoch>,
    reason: &str,
    rejected_at_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO rejected_changes \
             (change_hash, group_id, reason, rejected_at, rejection_domain, rules_version, \
              rests_on, refused_on_epoch) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT (change_hash) DO UPDATE SET \
             group_id = excluded.group_id, \
             reason = excluded.reason, \
             rejected_at = excluded.rejected_at, \
             rejection_domain = excluded.rejection_domain, \
             rules_version = excluded.rules_version, \
             rests_on = excluded.rests_on, \
             refused_on_epoch = excluded.refused_on_epoch",
        rusqlite::params![
            &hash.0[..],
            group_id,
            reason,
            rejected_at_unix_nanos,
            domain.as_str(),
            domain.rules_version(),
            rests_on.map(|basis| basis.0.to_vec()),
            refused_on.map(epoch_column),
        ],
    )?;
    Ok(())
}

/// The `refused_on_epoch` value for `epoch`: empty for genesis, the base's
/// bytes above one. Distinct from NULL, which marks a row not scoped to any
/// history.
fn epoch_column(epoch: HistoryEpoch) -> Vec<u8> {
    epoch.base().map(|base| base.0.to_vec()).unwrap_or_default()
}

/// The `(domain, version)` stamps this build stands behind, for a query
/// that must preselect rows by stamp in SQL. Such a query still has to
/// confirm each row with [`current_rejection_domain`], which also follows
/// `rests_on`.
pub(crate) fn current_rules_stamps() -> [(&'static str, u32); 2] {
    [RejectionDomain::Path, RejectionDomain::AuthorChain]
        .map(|domain| (domain.as_str(), domain.rules_version()))
}

/// The domain a stored `(domain, version)` stamp names, when this build
/// still stands behind it. An unrecognized domain string is not current — a
/// row written by a build whose domains this one does not know is exactly
/// the case for re-evaluating rather than trusting.
fn current_domain(domain: &str, version: u32) -> Option<RejectionDomain> {
    [RejectionDomain::Path, RejectionDomain::AuthorChain]
        .into_iter()
        .find(|known| known.as_str() == domain && known.rules_version() == version)
}

/// The domain whose current rules durably rejected `hash`, or `None` when
/// it is not rejected under current rules — including a row stamped with a
/// superseded version of its own domain, which is deliberately NOT trusted
/// as settled (see the module doc comment): the caller's normal "still
/// missing" handling then drives a fresh re-request and re-evaluation.
///
/// A verdict that rests on this rejection — a change refused because the
/// change it names can never be held here — is exactly as settled as this
/// one, so it is recorded under the domain this returns, naming this hash.
///
/// A row that rests on another change is followed to a verdict of its own,
/// and is current only if every link on the way is: stamped under current
/// rules, and resting on a change that is not held here.
pub(crate) fn current_rejection_domain(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<Option<RejectionDomain>, SyncSqliteError> {
    let mut own_domain = None;
    let mut at = *hash;
    let mut followed = std::collections::HashSet::new();
    loop {
        type Row = (String, u32, String, Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<Row> = conn
            .query_row(
                "SELECT rejection_domain, rules_version, group_id, rests_on, refused_on_epoch \
                   FROM rejected_changes WHERE change_hash = ?1",
                [&at.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((domain, version, group_id, rests_on, refused_on)) = row else {
            return Ok(None);
        };
        let Some(domain) = current_domain(&domain, version) else {
            return Ok(None);
        };
        if let Some(refused_on) = refused_on {
            let now = crate::rebootstrap_store::current_history_epoch(conn, &group_id)?;
            if refused_on != epoch_column(now) {
                return Ok(None);
            }
        }
        let own_domain = *own_domain.get_or_insert(domain);
        let Some(basis) = rests_on else {
            return Ok(Some(own_domain));
        };
        let basis = crate::dag_store::retained_history_integrity::hash_from_blob(basis)?;
        if crate::dag_store::retained_history_integrity::has_change_or_pruned(
            conn, &group_id, &basis,
        )? {
            return Ok(None);
        }
        // Content addressing makes a cycle impossible for rows this crate
        // wrote; one here is corruption, not a verdict.
        if !followed.insert(at) {
            return Err(SyncSqliteError::CorruptState(format!(
                "rejected change {hash:?} rests on a cycle through {at:?}"
            )));
        }
        at = basis;
    }
}

/// Whether `hash` is durably recorded as a permanent rejection **under the
/// current rules of the domain that rejected it** (see
/// [`current_rejection_domain`]).
pub(crate) fn is_change_rejected(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    Ok(current_rejection_domain(conn, hash)?.is_some())
}

/// Every hash for `group_id` durably rejected **under the current rules of
/// whichever domain rejected it**, most recent first — the data a status
/// surface (CLI, control-socket diagnostics) would read to show a user
/// which of their own content is stuck behind a verdict that will never
/// resolve without intervention. As of this writing nothing actually calls this
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
/// re-deriving this query. A row whose domain's rules have moved past its
/// stamp is excluded, matching [`is_change_rejected`]'s own verdict — it is no
/// longer a settled rejection, only a historical one, pending
/// re-evaluation the next time the hash is offered. Read-only; never
/// consulted by any admission or projection path (those only ever need the
/// single-hash question `is_change_rejected` answers).
pub fn list_rejected_changes(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<(ChangeHash, String, i64)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT change_hash, reason, rejected_at \
         FROM rejected_changes WHERE group_id = ?1 ORDER BY rejected_at DESC",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id], |row| {
        let hash_blob: Vec<u8> = row.get(0)?;
        let reason: String = row.get(1)?;
        let rejected_at: i64 = row.get(2)?;
        Ok((hash_blob, reason, rejected_at))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (hash_blob, reason, rejected_at) = row?;
        let hash = crate::dag_store::retained_history_integrity::hash_from_blob(hash_blob)?;
        if !is_change_rejected(conn, &hash)? {
            continue;
        }
        out.push((hash, reason, rejected_at));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
