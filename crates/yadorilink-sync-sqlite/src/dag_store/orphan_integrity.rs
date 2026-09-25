//! The `orphan_changes` table: a bounded, best-effort holding buffer for
//! changes that arrived before something they name. A row here is never
//! treated as durable history -- corrupt, structurally invalid, or
//! ancestry-inconsistent rows are dropped rather than fail-closed, and
//! [`promote_orphans`] moves a ready row into
//! `super::retained_history_integrity`'s `changes` table once everything it
//! waits on is present.
//!
//! A row waits on two kinds of name, and both are ordinary waiting rather
//! than two mechanisms. Its DAG parents, recorded as `change_parents`
//! edges, are the causal basis it was written on. Its `author_prev` --
//! recorded in this table's own column -- is the previous change of its own
//! author. The second is not implied by the first: author ordering is not
//! causality, so an author's previous change is routinely not an ancestor
//! of its next one and can arrive after it.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::ChangeHash;

/// Upper bound on the orphan buffer. A change whose parents never arrive
/// cannot grow the store without limit: once this many orphans are held, the
/// oldest are evicted (and would be re-requested by a later heads exchange).
pub const ORPHAN_BOUND: usize = 4096;

/// Buffers a change that is still waiting on something it names. Evicts the
/// oldest orphans once the bound is exceeded (see `ORPHAN_BOUND`).
///
/// `author_prev_hash` is written from the change's own signed field, so the
/// row records the author link it may be waiting on as well as the parent
/// edges its caller records.
///
/// `relay_admitted`/`relay_vouched_by` are always written as their inert
/// defaults (`0`/`''`) -- the columns remain in the schema (dropping them
/// is a separate, non-security-relevant cleanup) but nothing in this crate
/// reads them for a decision anymore: under `AuthorizationCheckpoint`
/// admission, a buffered orphan's
/// eventual promotion depends only on its ancestry becoming complete, never
/// on who delivered it or a re-checked freshness window -- see
/// [`promote_orphans`]'s own doc comment.
pub(crate) fn insert_orphan(conn: &Connection, change: &Change) -> Result<(), SyncSqliteError> {
    let hash = change.compute_hash();
    let next_seq: i64 =
        conn.query_row("SELECT COALESCE(MAX(received_seq), 0) + 1 FROM orphan_changes", [], |r| {
            r.get(0)
        })?;
    conn.execute(
        "INSERT OR IGNORE INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, received_seq, \
          relay_admitted, relay_vouched_by, author_prev_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, '', ?7)",
        rusqlite::params![
            &hash.0[..],
            change.group_id.as_str(),
            change.device_id.as_str(),
            change.lamport as i64,
            change.to_wire_bytes(),
            next_seq,
            change.author_prev.map(|prev| prev.0.to_vec()),
        ],
    )?;
    // Bound the buffer: keep the newest `ORPHAN_BOUND`, evict older ones.
    // Skipped entirely in the ordinary case (buffer well under the bound) --
    // this function runs once per buffered change, potentially hundreds of
    // times in one anti-entropy round (a cold catch-up beyond the wire
    // batch cap buffers its whole response as orphans), and the eviction
    // queries below have to walk past `ORPHAN_BOUND` rows every time they
    // actually run; skipping that walk when it could not possibly find
    // anything to evict turns what would otherwise be a full-buffer cost
    // paid on every single insert into a cheap `COUNT(*)`.
    let orphan_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM orphan_changes", [], |r| r.get(0))?;
    if orphan_count as usize > ORPHAN_BOUND {
        // The `change_parents` edges recorded for an evicted orphan's
        // declared parents must go with it -- left behind, a ghost edge
        // under a hash no longer in `orphan_changes` (and never in
        // `changes` either) would make `frontier_index::repair` think that
        // parent still has a child and drop it out of `group_heads`.
        // Deleted first, while the eviction set is still computable from
        // the still-present `orphan_changes` rows.
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
    }
    Ok(())
}

/// Promotes every orphan that is now ready into the applied store, seeded
/// from the change hashes that just became durable (`seeds`).
/// A currently-buffered orphan can only become promotable when one of the
/// changes it names lands — one of its own parents, or its author's
/// previous change — so walking outward from exactly those hashes (via the
/// `change_parents_by_parent` and `orphan_changes_by_author_prev` indexes)
/// finds every newly-promotable orphan in work proportional to what
/// actually got unblocked. A prior
/// version re-scanned the *entire* orphan buffer once per promotion, which
/// is quadratic for a long chain of orphans that each unblock exactly one
/// more (received out of order, then promoted one generation at a time).
/// Returns the hashes of the changes that were promoted, oldest-first — the
/// caller projects each promoted orphan's paths, so it needs the identities,
/// not just a count.
///
/// There is no freshness/writer re-check here anymore: under
/// `AuthorizationCheckpoint` admission, a Change's admissibility is a static,
/// content-addressed fact (does a validly-signed checkpoint cover its
/// hash?), never a time-varying "is the author still a writer right now"
/// question -- there is no window for it to go stale between original
/// receipt and this promotion, so nothing needs re-checking. An orphan
/// buffers purely because something it names is not here; it promotes
/// purely because everything it names arrived.
pub fn promote_orphans(
    conn: &Connection,
    seeds: &[ChangeHash],
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut promoted: Vec<ChangeHash> = Vec::new();
    let mut queue: std::collections::VecDeque<ChangeHash> = seeds.iter().copied().collect();
    while let Some(parent_hash) = queue.pop_front() {
        // Orphans that declare `parent_hash` as one of their own parents and
        // are still buffered, oldest-arrived first.
        //
        // Plus the orphans waiting on `parent_hash` as their AUTHOR's
        // previous change rather than as a DAG parent. That is a different
        // relation and a different column, and it has to be woken here or
        // not at all: an author's previous change is routinely not an
        // ancestor of its next one, so nothing in the parent walk would
        // ever reach such a row. A single `UNION` keeps both kinds in one
        // `received_seq` order, and a hash that qualifies under both is
        // returned once.
        let candidates: Vec<Vec<u8>> = {
            let mut stmt = conn.prepare_cached(
                "SELECT child_hash FROM ( \
                   SELECT cp.child_hash AS child_hash, o.received_seq AS received_seq \
                   FROM change_parents cp \
                   JOIN orphan_changes o ON o.change_hash = cp.child_hash \
                   WHERE cp.parent_hash = ?1 \
                   UNION \
                   SELECT o.change_hash AS child_hash, o.received_seq AS received_seq \
                   FROM orphan_changes o \
                   WHERE o.author_prev_hash = ?1 \
                 ) ORDER BY received_seq",
            )?;
            let rows = stmt.query_map([&parent_hash.0[..]], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for child_hash_blob in candidates {
            // Re-fetch fresh rather than trust the query snapshot above: an
            // earlier candidate processed in this same pass may already have
            // promoted or dropped this exact row (e.g. two of its parents
            // both land within the same seed set).
            let encoded: Option<Vec<u8>> = conn
                .prepare_cached("SELECT encoded FROM orphan_changes WHERE change_hash = ?1")?
                .query_row([&child_hash_blob[..]], |r| r.get::<_, Vec<u8>>(0))
                .optional()?;
            let Some(encoded) = encoded else { continue };
            let change = match Change::from_wire_bytes(&encoded) {
                Ok(c) => c,
                Err(_) => {
                    // Corrupt buffered bytes: drop it rather than wedge the loop.
                    drop_orphan_subtree(conn, &child_hash_blob)?;
                    continue;
                }
            };
            if !super::retained_history_integrity::has_all_parents(conn, &change)? {
                continue;
            }
            // NOT given the same drop-and-continue treatment as the checks
            // below, deliberately: `validate_referenced_versions`'s
            // `NotFound` cannot currently distinguish "this version will
            // never arrive" (a genuine, permanent defect) from "this
            // version just hasn't been delivered yet via the separate
            // version-transfer path" (the ordinary, expected, retriable
            // case `admit_change`'s own re-request flow already handles) --
            // treating it as poison here would risk discarding legitimate,
            // still-pending orphans. Treating it as poison would first
            // require `validate_referenced_versions` to make that
            // distinction itself (e.g. a version hash that resolves to a
            // DIFFERENT group is unambiguously foreign/invalid, vs. one
            // absent everywhere).
            super::serving_authorization_index::validate_referenced_versions(conn, &change)?;
            // Same reasoning as the carrier-conflict-copy check below: once
            // `has_all_parents` confirms every parent hash structurally
            // exists, `validate_present_parent_shape`'s only remaining
            // failure modes are its OWN explicit `SyncSqliteError::NotFound`
            // checks (a parent from a different group, or a Lamport value
            // that doesn't match what its now-present parents dictate) --
            // both unambiguous, permanent semantic defects in THIS child,
            // not a transient/local-infrastructure problem. An authorized
            // device could otherwise send a real parent P plus a
            // Lamport-wrong (or cross-group-parent) child C referencing P;
            // C buffers as an orphan, and when P later arrives, promoting C
            // would fail here and (via `?`) roll back P's own just-appended
            // admission too, permanently blocking P and every descendant.
            match super::retained_history_integrity::validate_present_parent_shape(conn, &change) {
                Ok(_) => {}
                Err(SyncSqliteError::NotFound(reason)) => {
                    tracing::warn!(
                        change_hash = %hex::encode(&child_hash_blob),
                        reason,
                        "dropping a buffered orphan with an invalid parent-group or lamport claim"
                    );
                    drop_orphan_subtree(conn, &child_hash_blob)?;
                    continue;
                }
                Err(error) => return Err(error),
            }
            // The full admission verdict -- the history the change was
            // written on, then its own author's chain -- checked here for
            // the same reason and in the same position as on the direct
            // admission path: an orphan's parents are only confirmed
            // present at this point, and both rules are only meaningful
            // once they are. Promotion is an admission, so it gets the
            // identical verdict rather than a relaxed one — the whole
            // point of a single rule is that a change cannot slip in by
            // arriving early.
            //
            // A refusal is final and specific to this one orphan, so it is
            // dropped rather than propagated: propagating would roll back
            // the parent's own just-appended admission. The verdict itself
            // records the hash as permanently rejected, so a peer that
            // keeps re-sending a change this replica can never accept
            // stops being asked for it -- and releases whatever was
            // waiting on it. The drop below is the same drop repeated for
            // this one row, kept because it is this loop's own contract
            // that a refused candidate leaves the buffer here.
            match super::admission_verdict(conn, &change)? {
                super::AdmissionVerdict::Admit => {}
                // Woken by a DAG parent, but still waiting on its own
                // author's previous change (or the reverse). Left exactly
                // where it is, with nothing recorded: the row is already
                // buffered against both names, and whichever of them lands
                // next wakes it again.
                super::AdmissionVerdict::AwaitAuthorPredecessor { .. } => continue,
                super::AdmissionVerdict::Refuse(refusal) => {
                    tracing::warn!(
                        change_hash = %hex::encode(&child_hash_blob),
                        reason = %refusal,
                        "dropping a buffered orphan admission refuses"
                    );
                    drop_orphan_subtree(conn, &child_hash_blob)?;
                    continue;
                }
            }
            // Same reasoning as `admit_change`: an orphan's parents are only
            // confirmed present right here, so this is the first point its
            // `ConflictCopy` puts (which claim things about that parent
            // frontier) can be checked. A `SyncSqliteError::InvalidInput` here
            // means the carrier ITSELF is semantically invalid (an
            // authorized-but-malicious or buggy peer's claim), not a local
            // DB/infrastructure problem -- treated like the decode failure
            // above: drop this one orphan and continue, rather than
            // propagating via `?` and rolling back the whole promotion
            // pass (including its own parent's just-appended admission,
            // since this runs inside `admit_change`'s transaction). Without
            // this, a single poisoned orphan referencing a real parent
            // could permanently block that parent -- and every one of its
            // descendants -- from ever being admitted: each retry of the
            // parent would re-run this exact same failing promotion and
            // roll back again. Any OTHER error variant (Db, CorruptState,
            // Pool, ...) still propagates and fails closed, unchanged.
            match super::conflict_authoring::validate_carrier_conflict_copy_ops(
                conn,
                change.group_id.as_str(),
                &change,
            ) {
                Ok(()) => {}
                Err(SyncSqliteError::InvalidInput(reason)) => {
                    tracing::warn!(
                        change_hash = %hex::encode(&child_hash_blob),
                        reason,
                        "dropping a buffered orphan whose conflict-copy claims are invalid"
                    );
                    drop_orphan_subtree(conn, &child_hash_blob)?;
                    continue;
                }
                Err(error) => return Err(error),
            }
            conn.prepare_cached("DELETE FROM orphan_changes WHERE change_hash = ?1")?
                .execute([&child_hash_blob[..]])?;
            let real_hash = change.compute_hash();
            if real_hash.0[..] != child_hash_blob[..] {
                // Stored under a key that disagrees with its own encoded
                // hash (corrupted/tampered storage key, not the content
                // itself, which is otherwise valid and admissible under its
                // real hash below): the row's own `change_parents` edges are
                // keyed by that bogus hash, not the real one `append_change`
                // is about to use, so they would become permanently
                // unreachable ghost ancestry once the row above is gone.
                conn.prepare_cached("DELETE FROM change_parents WHERE child_hash = ?1")?
                    .execute([&child_hash_blob[..]])?;
            }
            if super::retained_history_integrity::append_change(
                conn,
                &change,
                super::now_unix_nanos(),
            )? {
                super::conflict_authoring::record_conflict_copy_ops_provenance(
                    conn,
                    change.group_id.as_str(),
                    &change,
                )?;
                super::recursive_operations::record_recursive_operation_part(conn, &change)?;
                promoted.push(real_hash);
                queue.push_back(real_hash);
            }
        }
    }
    Ok(promoted)
}

/// The seeds for a startup self-heal pass: every hash that is durably
/// admitted and still named by a buffered orphan as something it waits on —
/// a DAG parent, or its own author's previous change. Ordinary operation
/// always promotes an orphan in the same call that admits what it was
/// waiting for (see `promote_orphans`'s `seeds` argument), but a crash
/// between those two steps — or an orphan buffered directly out of band —
/// can leave a promotable orphan with nothing left to seed a promotion
/// pass. Schema init calls this once so restart self-heals any such gap; it
/// is not used on the hot admission path, where the seed is already known
/// from the change that was just admitted.
///
/// Both names have to be swept, not just the parents: a change held only
/// because its author's previous change had not arrived is reachable
/// through no parent edge at all, so a parents-only sweep would leave it
/// buffered forever — and buffered means never re-requested.
pub(crate) fn already_satisfied_parents(
    conn: &Connection,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT cp.parent_hash FROM change_parents cp \
         JOIN changes c ON c.change_hash = cp.parent_hash \
         JOIN orphan_changes o ON o.change_hash = cp.child_hash \
         UNION \
         SELECT DISTINCT o.author_prev_hash FROM orphan_changes o \
         JOIN changes c ON c.change_hash = o.author_prev_hash",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(super::retained_history_integrity::hash_from_blob(row?)?);
    }
    Ok(out)
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
fn drop_orphan_change(conn: &Connection, change_hash: &[u8]) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM change_parents WHERE child_hash = ?1", [change_hash])?;
    conn.execute("DELETE FROM change_file_versions WHERE change_hash = ?1", [change_hash])?;
    conn.execute("DELETE FROM orphan_changes WHERE change_hash = ?1", [change_hash])?;
    Ok(())
}

/// Like [`drop_orphan_change`], but also drops every OTHER still-buffered
/// orphan that (transitively) names `change_hash` -- as a DAG parent, or as
/// its own author's previous change. Both names are followed because both
/// are names a row waits on, and the author link is not implied by the
/// parent edges: an author's previous change is routinely not an ancestor
/// of its next one, so a parents-only walk reaches a row waiting on it
/// never. `change_hash`
/// itself need not be a buffered orphan -- `admit_change`'s own top-level
/// causal-auth rejection (a change whose parent was already live, so it was
/// never buffered at all) calls this too, purely to clean up any
/// descendants that arrived and buffered before the rejection was
/// discovered; `drop_orphan_change`'s own deletes are harmless no-ops for a
/// hash that was never in `orphan_changes` to begin with.
///
/// Every permanent-drop case (corrupt bytes, an invalid parent-group/
/// Lamport claim, invalid conflict-copy ops, a causal-auth-monotonicity
/// violation, or a final admission refusal recorded by
/// `dag_store::record_final_refusal`) means
/// `change_hash` can never be promoted -- so any buffered orphan waiting on
/// it can never be promoted either, no matter how many times
/// its own bytes are re-delivered: it will keep re-evaluating cleanly on
/// its OWN terms (referenced versions, its own parent shape, its own
/// causal-auth coordinate) but `has_all_parents` will never see
/// `change_hash` become present, because it never will. Left buffered,
/// such a descendant would sit until `ORPHAN_BOUND` eviction happens to
/// reach it -- possibly never, if newer orphans keep landing elsewhere in
/// the buffer first -- all the while its own hash keeps showing up in
/// `missing_ancestor_frontier` walks and getting re-requested every
/// anti-entropy round for no reason that redelivery could ever fix.
/// Dropping the whole dependent subtree now is what actually closes that
/// loop.
pub(crate) fn drop_orphan_subtree(
    conn: &Connection,
    change_hash: &[u8],
) -> Result<(), SyncSqliteError> {
    let mut queue: std::collections::VecDeque<Vec<u8>> = [change_hash.to_vec()].into();
    while let Some(hash) = queue.pop_front() {
        // Both kinds of dependent, for the same reason `promote_orphans`
        // wakes both: a buffered row waits on its DAG parents AND on its
        // author's previous change, and the second is reachable through no
        // parent edge at all. A parents-only walk would leave a row waiting
        // on a hash that is now permanently unreachable exactly where it
        // is -- and buffered means counted as known, so never re-requested
        // and never asked about again.
        let dependents: Vec<Vec<u8>> = {
            let mut stmt = conn.prepare(
                "SELECT cp.child_hash FROM change_parents cp \
                 JOIN orphan_changes o ON o.change_hash = cp.child_hash \
                 WHERE cp.parent_hash = ?1 \
                 UNION \
                 SELECT o.change_hash FROM orphan_changes o \
                 WHERE o.author_prev_hash = ?1",
            )?;
            let rows = stmt.query_map([&hash[..]], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        queue.extend(dependents);
        drop_orphan_change(conn, &hash)?;
    }
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

pub(crate) fn repair(conn: &Connection) -> Result<(), SyncSqliteError> {
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
