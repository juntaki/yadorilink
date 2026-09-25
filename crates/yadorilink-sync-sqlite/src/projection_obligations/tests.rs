#![cfg(test)]

use super::*;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_projection_obligations_schema(&c).unwrap();
    c
}

#[test]
fn a_first_bump_creates_a_row_at_generation_one() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.invalidation_generation, 1);
    assert_eq!(row.state, "pending");
}

#[test]
fn a_second_bump_increments_the_existing_generation_rather_than_resetting_it() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.invalidation_generation, 2);
    assert_eq!(row.updated_at, 2000);
}

/// the
/// incarnation allocator used to leave its `INSERT`ed row in place,
/// growing `projection_obligation_incarnations` by one permanent row
/// per touched-path event -- unbounded storage growth proportional to
/// total admitted mutations over a replica's lifetime, not to live
/// obligations. The allocator row is now deleted immediately after its
/// id is captured; this proves the table stays empty across many
/// bumps, and that incarnation values assigned to genuinely distinct
/// rows still never collide (`AUTOINCREMENT`'s `sqlite_sequence`
/// high-water mark is independent of which rows currently exist).
#[test]
fn the_incarnation_allocator_table_never_accumulates_rows() {
    let conn = conn();
    for i in 0..50 {
        let path = format!("path-{i}.txt");
        bump_projection_obligations_for_touched_paths(&conn, "g", &[&path], 1000).unwrap();
        // A second bump of the SAME path (the common ON CONFLICT
        // bump-in-place case) also allocates-and-discards an unused id.
        bump_projection_obligations_for_touched_paths(&conn, "g", &[&path], 2000).unwrap();
    }
    let allocator_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM projection_obligation_incarnations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        allocator_rows, 0,
        "the allocator table must never accumulate rows regardless of how many paths were bumped"
    );

    // Every one of the 50 distinct rows must still have a genuinely
    // unique incarnation -- deleting the allocator row must not have
    // let any of them collide.
    let mut incarnations = std::collections::HashSet::new();
    for i in 0..50 {
        let path = format!("path-{i}.txt");
        let obligation = lookup_projection_obligation(&conn, "g", &path).unwrap().unwrap();
        assert!(
            incarnations.insert(obligation.obligation_incarnation),
            "incarnation {} for {path} collided with an earlier path's incarnation",
            obligation.obligation_incarnation
        );
    }
}

#[test]
fn bumping_one_path_never_touches_an_unrelated_path() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["b.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
    let a = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let b = lookup_projection_obligation(&conn, "g", "b.txt").unwrap().unwrap();
    assert_eq!(a.invalidation_generation, 2, "a.txt was bumped twice");
    assert_eq!(b.invalidation_generation, 1, "b.txt must be unaffected by a.txt's second bump");
}

#[test]
fn an_empty_touched_set_is_a_no_op() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &[], 1000).unwrap();
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM projection_obligations", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn a_path_with_no_admission_ever_has_no_obligation() {
    let conn = conn();
    assert!(lookup_projection_obligation(&conn, "g", "never.txt").unwrap().is_none());
}

#[test]
fn claim_returns_every_pending_obligation_with_its_current_generation() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 2);
    let a = claimed.iter().find(|c| c.path == "a.txt").unwrap();
    let b = claimed.iter().find(|c| c.path == "b.txt").unwrap();
    assert_eq!(a.invalidation_generation, 2);
    assert_eq!(b.invalidation_generation, 1);
    assert_eq!(a.group_id, "g");
}

#[test]
fn claim_with_no_obligations_returns_empty() {
    let conn = conn();
    assert!(claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap().is_empty());
}

#[test]
fn claim_respects_the_per_group_limit_taking_the_oldest_updated_first() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["b.txt"], 2000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["c.txt"], 3000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 2, 10).unwrap();
    assert_eq!(claimed.len(), 2);
    let paths: Vec<&str> = claimed.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(paths, vec!["a.txt", "b.txt"], "the two oldest-updated rows must win, in order");
}

#[test]
fn claim_respects_the_total_limit_across_groups() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g1", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g2", &["b.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 1).unwrap();
    assert_eq!(claimed.len(), 1);
}

#[test]
fn claim_gives_every_group_a_share_rather_than_letting_one_group_crowd_out_another() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "heavy", &["1", "2", "3"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "light", &["only"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 1, 10).unwrap();
    let groups: std::collections::BTreeSet<&str> =
        claimed.iter().map(|c| c.group_id.as_str()).collect();
    assert!(groups.contains("heavy") && groups.contains("light"));
}

#[test]
fn a_fresh_obligation_has_zero_attempt_count_and_is_immediately_claimable() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.attempt_count, 0);
    assert_eq!(row.next_attempt_at, 1000);
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt_count, 0);
}

#[test]
fn a_failed_attempt_is_not_reclaimable_until_its_backoff_deadline_passes() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    assert!(mark_obligation_attempt_failed(&conn, "g", "a.txt", claimed_g, claimed_i, 5000, 1000)
        .unwrap());

    assert!(
        claim_runnable_obligations(&conn, 2000, 10, 10).unwrap().is_empty(),
        "must not be reclaimable before its backoff deadline"
    );
    let reclaimed = claim_runnable_obligations(&conn, 5000, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1, "must be reclaimable once the backoff deadline passes");
    assert_eq!(reclaimed[0].attempt_count, 1, "the failed attempt must have incremented the count");
}

#[test]
fn a_fresh_admission_resets_attempt_count_and_backoff_even_after_repeated_failures() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;
    mark_obligation_attempt_failed(&conn, "g", "a.txt", claimed_g, claimed_i, 100_000, 1000)
        .unwrap();

    // A new DAG admission supersedes the old generation's backoff --
    // the new desired state must be runnable immediately, not delayed
    // by the old generation's failure history.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();

    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.invalidation_generation, 2);
    assert_eq!(row.attempt_count, 0, "a new generation must reset the attempt count");
    assert_eq!(row.next_attempt_at, 2000, "a new generation must be immediately runnable");

    let reclaimed = claim_runnable_obligations(&conn, 2000, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempt_count, 0);
}

#[test]
fn a_stale_failure_report_at_a_superseded_generation_is_a_no_op() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let stale_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    // A concurrent admission bumps the generation before this stale
    // attempt's own failure report lands -- an ordinary bump-in-place,
    // so the row's incarnation is unchanged; only its generation moves.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();

    assert!(
        !mark_obligation_attempt_failed(&conn, "g", "a.txt", stale_g, claimed_i, 100_000, 3000)
            .unwrap(),
        "a failure report at a superseded generation must affect zero rows, even with the \
         correct (unchanged) incarnation"
    );
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.attempt_count, 0, "the fresh generation's reset must survive the stale report");
    assert_eq!(row.next_attempt_at, 2000, "the fresh generation must stay immediately runnable");
}

/// **Obligation row-incarnation ABA**: `mark_obligation_attempt_failed`'s
/// WHERE clause must distinguish "the exact row incarnation this claim was issued
/// against" from "any current row that happens to carry the same
/// `(group_id, path, invalidation_generation)` key" -- a pure key match
/// is not a row identity match. `claim_runnable_obligations`'s own
/// doc comment already documents that two workers concurrently holding
/// a claim on the SAME still-outstanding obligation is expected,
/// tolerated behavior ("a performance question, never a correctness
/// one") -- but that reasoning implicitly assumed the row underneath
/// both claims stays the SAME row for the obligation's whole lifetime.
/// It does not: `complete_obligation_if_exact_proof_current` and the
/// `Placeholder`/`HazardHeld` arms of `complete_obligation_if_non_exact_
/// proof_current` all `DELETE` the row on success, and `bump_projection_
/// obligations_for_touched_paths` INSERTs a brand-new row at
/// `invalidation_generation = 1` (via `ON CONFLICT DO UPDATE`'s INSERT
/// arm) the next time ANY admission touches that path -- there is no
/// memory of what generation a deleted row was last at. A claimant
/// issued before the delete, still holding `G = 1` (the common case:
/// the very first admission for a path is always `G = 1`), could
/// therefore complete against a brand-new, entirely unrelated later
/// obligation for the same path that also happened to start at `G = 1`.
///
/// Confirmed genuinely RED against the pre-fix API (positional 6-arg
/// `mark_obligation_attempt_failed` with no incarnation parameter): the
/// stale `mark_obligation_attempt_failed(old_claim.invalidation_
/// generation, /* no incarnation */)` call matched and corrupted the
/// reincarnated row. `obligation_incarnation` (assigned fresh, from an
/// `AUTOINCREMENT` sequence that never repeats a value, only on a
/// genuine `INSERT`, never on the `ON CONFLICT` bump-in-place arm) now
/// makes OLD's full claim token strictly stale the moment its own row
/// is deleted, regardless of what generation number a later, unrelated
/// incarnation happens to reuse.
#[test]
fn stale_claimant_cannot_corrupt_a_reincarnated_obligation_row() {
    let conn = conn();

    // OLD claims the obligation for a.txt at its first-ever generation
    // and incarnation.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let old_claim = claim_runnable_obligations(&conn, 1000, 10, 10)
        .unwrap()
        .into_iter()
        .find(|c| c.path == "a.txt")
        .unwrap();
    assert_eq!(old_claim.invalidation_generation, 1);

    // A DIFFERENT worker successfully completes that SAME obligation --
    // standing in for a real `complete_obligation_if_exact_proof_current`
    // success, which performs exactly this DELETE once its own proof
    // check passes.
    conn.execute(
        "DELETE FROM projection_obligations
          WHERE group_id = 'g' AND path = 'a.txt' AND invalidation_generation = 1",
        [],
    )
    .unwrap();
    assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());

    // A genuinely NEW, unrelated DAG admission later touches the same
    // path -- a fresh incarnation, starting at G = 1 again (identical to
    // OLD's stale claim) since there is no surviving row to conflict
    // against, but with a NEW `obligation_incarnation` value.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 5000).unwrap();
    let reincarnated = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(
        reincarnated.invalidation_generation, 1,
        "sanity: the new admission's row starts fresh at G=1, identical to OLD's stale claim"
    );
    assert_ne!(
        reincarnated.obligation_incarnation, old_claim.obligation_incarnation,
        "sanity: the reincarnated row must get a genuinely different incarnation than OLD's"
    );

    // OLD, still holding its now-stale claim from the deleted
    // incarnation, reports a failed attempt against the generation AND
    // incarnation it originally claimed.
    let affected = mark_obligation_attempt_failed(
        &conn,
        "g",
        "a.txt",
        old_claim.invalidation_generation,
        old_claim.obligation_incarnation,
        99_999,
        5000,
    )
    .unwrap();

    // FIXED: OLD's stale attempt-failure report against a DELETED
    // incarnation must affect zero rows, even though its generation
    // number coincidentally matches the brand-new incarnation's own.
    assert!(
        !affected,
        "OLD's stale claim against a deleted incarnation must not match the new incarnation, \
         even at the same generation number"
    );
    let untouched = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(
        untouched.attempt_count, 0,
        "the new incarnation's attempt_count must be untouched by an attempt nobody made against it"
    );
    assert_eq!(
        untouched.next_attempt_at, 5000,
        "the new incarnation's backoff must be untouched by OLD's stale report"
    );
}

#[test]
fn defer_without_penalty_delays_reclaim_but_never_increments_attempt_count() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    assert!(defer_obligation_without_penalty(
        &conn, "g", "a.txt", claimed_g, claimed_i, 1200, 1000
    )
    .unwrap());
    assert!(claim_runnable_obligations(&conn, 1100, 10, 10).unwrap().is_empty());
    let reclaimed = claim_runnable_obligations(&conn, 1200, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(
        reclaimed[0].attempt_count, 0,
        "a no-trustworthy-audit reschedule must never count as a failed attempt"
    );
}

#[test]
fn earliest_pending_next_attempt_at_ignores_already_runnable_rows() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let a = claimed.iter().find(|c| c.path == "a.txt").unwrap();
    mark_obligation_attempt_failed(
        &conn,
        "g",
        "a.txt",
        a.invalidation_generation,
        a.obligation_incarnation,
        9000,
        1000,
    )
    .unwrap();

    // b.txt is still immediately runnable, so the earliest FUTURE
    // deadline must not be confused with it.
    assert_eq!(earliest_pending_next_attempt_at(&conn, 1000).unwrap(), Some(9000));
}

#[test]
fn earliest_pending_next_attempt_at_is_none_when_nothing_is_backed_off() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    assert_eq!(earliest_pending_next_attempt_at(&conn, 1000).unwrap(), None);
}

/// Nothing in this module ever moves a row's `state` out of `'pending'`
/// or otherwise marks it in-flight -- `claim_runnable_obligations` is a
/// plain `SELECT`, and a fresh admission's bump unconditionally resets
/// `state` back to `'pending'` regardless of what came before. A row a
/// worker never got to before a restart is therefore already sitting
/// exactly where a freshly claimable row needs to be: this is ordinary
/// durable SQLite state, not something that needs its own crash-
/// recovery primitive the way a scheduler with genuine in-flight states
/// (`Planning`/`Fetching`/`ReadyToCommit`) would. This test proves that
/// directly: it commits an admission, then closes and reopens the
/// SQLite connection with no claim or completion call in between --
/// simulating a daemon restart before any worker tick ever touched this
/// obligation -- and checks it survives with its generation intact and
/// is still claimable through the real claim entry point, not merely
/// visible to a diagnostic lookup.
///
/// Confirmed genuinely RED by temporarily changing this module's
/// `CREATE TABLE IF NOT EXISTS projection_obligations` to `CREATE TEMP
/// TABLE IF NOT EXISTS projection_obligations`: a `TEMP` table is
/// scoped to the connection that created it, so the reopened connection
/// got a fresh, empty table and this test failed (`unwrap()` on `None`)
/// exactly as it should for genuinely lost state. Restored and
/// reconfirmed GREEN.
#[test]
fn an_obligation_survives_a_connection_restart_with_no_worker_tick_and_stays_claimable() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("projection_obligations.sqlite");

    {
        let conn = Connection::open(&db_path).unwrap();
        init_projection_obligations_schema(&conn).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
        // `conn` is dropped here, simulating the process exiting before
        // any worker tick ever claims or completes this obligation.
    }

    // Simulated restart: a fresh connection to the same on-disk
    // database, re-running schema init exactly as daemon startup does.
    let conn = Connection::open(&db_path).unwrap();
    init_projection_obligations_schema(&conn).unwrap();

    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(
        row.invalidation_generation, 2,
        "the pre-restart generation must survive the restart untouched"
    );
    assert_eq!(row.state, "pending");

    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].path, "a.txt");
    assert_eq!(claimed[0].invalidation_generation, 2);
}
