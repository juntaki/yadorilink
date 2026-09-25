#![cfg(test)]

use super::*;
use crate::materialized_generation::lookup_materialized_generation;
use crate::materialized_generation::MaterializedObjectKind;

/// `init_schema` must run AFTER `init_dag_schema`, which it assumes
/// has already created `changes`/`pruned_changes` -- the same order
/// production initializes in.
fn conn() -> rusqlite::Connection {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    crate::dag_store::init_dag_schema(&c).unwrap();
    crate::materialized_generation::init_materialized_generation_schema(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    c
}

fn seed_current_file(conn: &rusqlite::Connection, group_id: &str, path: &str) {
    conn.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
         state, version_seq, materialization_state) \
         VALUES (?1, ?2, 0, 0, '[]', 0, 'current', 1, 'placeholder')",
        rusqlite::params![group_id, path],
    )
    .unwrap();
}

fn object(version: [u8; 32]) -> ExactMaterializedState {
    ExactMaterializedState::Object {
        kind: RecordKind::Symlink,
        version: VersionHash(version),
        identity: Box::new(None),
    }
}

fn materialization_state(conn: &rusqlite::Connection, group_id: &str, path: &str) -> String {
    conn.query_row(
        "SELECT materialization_state FROM files WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )
    .unwrap()
}

fn intent_open(conn: &rusqlite::Connection, group_id: &str, path: &str) -> bool {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM materialization_intents WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
            |r| r.get(0),
        )
        .unwrap();
    n > 0
}

fn open_intent(conn: &rusqlite::Connection, group_id: &str, path: &str) {
    conn.execute(
        "INSERT INTO materialization_intents \
         (group_id, path, target_version_hash, created_at_unix_nanos) VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![group_id, path, &[9u8; 32][..]],
    )
    .unwrap();
}

/// One `files` row whose content columns make its derived version
/// depend on `size` -- so a second call with a different size is a
/// genuine supersession, the same way an admission is.
fn seed_current_row_sized(conn: &rusqlite::Connection, path: &str, size: i64) {
    conn.execute("DELETE FROM files WHERE group_id = 'g' AND path = ?1", rusqlite::params![path])
        .unwrap();
    conn.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
         state, version_seq, materialization_state, record_kind) \
         VALUES ('g', ?1, ?2, 0, '[]', 0, 'current', 1, 'hydrated', 'file')",
        rusqlite::params![path, size],
    )
    .unwrap();
}

fn row_version(conn: &rusqlite::Connection, path: &str) -> VersionHash {
    crate::store::read_canonical_current_row(conn, "g", path).unwrap().unwrap().version_hash()
}

fn publish_proof_for(conn: &rusqlite::Connection, path: &str, version: &VersionHash) {
    crate::materialized_generation::record_materialized_generation(
        conn,
        "g",
        path,
        &[],
        MaterializedObjectKind::RegularFile,
        Some(version),
        None,
        0,
    )
    .unwrap();
}

/// A proof is published for ONE version, and the path moves on. An
/// admission supersedes the row without touching the mutation fence,
/// so the fence check -- the only thing the usability read used to do
/// -- still passes, and the proof reads back as current while
/// describing content the path no longer wants. Anything that treats
/// "a proof exists" as "this path is exactly materialized" then skips
/// the work that would have fetched the new version.
#[test]
fn a_proof_for_a_superseded_version_does_not_stand_for_the_row() {
    let c = conn();
    seed_current_row_sized(&c, "p", 1);
    let v1 = row_version(&c, "p");
    publish_proof_for(&c, "p", &v1);
    assert!(
        usable_proof_names_current_version(&c, "g", "p").unwrap(),
        "the proof must stand for the version it was published for"
    );

    // A newer version for the same path. Nothing physical happened, so
    // nothing bumped the fence and the proof stays usable by itself.
    seed_current_row_sized(&c, "p", 2);
    assert_ne!(row_version(&c, "p"), v1, "the supersession must really change the version");
    assert!(
        lookup_materialized_generation(&c, "g", "p").unwrap().is_some(),
        "the fence check alone still passes -- which is exactly the gap"
    );
    assert!(
        !usable_proof_names_current_version(&c, "g", "p").unwrap(),
        "the standing proof is about a version this path has moved off"
    );
}

/// Producers can no longer write a versionless present proof, but
/// databases written before that can still hold one, and it is worse
/// than no proof: it matches no desired resolution -- the resolved
/// path-state hash encodes version presence -- so it can close nothing
/// while reading back as healthy to anything that only checks for a
/// row. Treating it as absent puts the path back on the paths that can
/// repair it.
#[test]
fn a_versionless_present_generation_reads_as_absent() {
    let c = conn();
    seed_current_row_sized(&c, "p", 1);
    crate::materialized_generation::record_materialized_generation(
        &c,
        "g",
        "p",
        &[],
        MaterializedObjectKind::RegularFile,
        None,
        None,
        0,
    )
    .unwrap();

    assert!(
        lookup_materialized_generation(&c, "g", "p").unwrap().is_none(),
        "a present object with no version can settle nothing; it must not read as usable"
    );
    assert!(
        crate::materialized_generation::lookup_materialized_generation_diagnostic(&c, "g", "p")
            .unwrap()
            .is_some(),
        "the diagnostic read still sees it -- that is what the two readers are for"
    );
    assert!(!usable_proof_names_current_version(&c, "g", "p").unwrap());
}

/// Absence is a first-class materialized state and carries no version
/// by definition, so the versionless rule must not swallow it.
#[test]
fn an_absent_generation_is_still_usable_without_a_version() {
    let c = conn();
    crate::materialized_generation::record_materialized_generation(
        &c,
        "g",
        "gone",
        &[],
        MaterializedObjectKind::Absent,
        None,
        None,
        0,
    )
    .unwrap();
    let basis = lookup_materialized_generation(&c, "g", "gone")
        .unwrap()
        .expect("an absent generation is a proof like any other");
    assert_eq!(basis.object_kind, MaterializedObjectKind::Absent);
    assert_eq!(basis.version, None);
}

/// Repair verifies disk against a row it read in an EARLIER
/// transaction, so by the time it commits, the row may have moved.
/// The publish, the promotion and the intent clear used to be three
/// separate transactions with a guard on only the first; a
/// supersession landing between them stamped `Hydrated` on the new
/// version while the only proof described the old one. The path lock
/// does not help: it serializes daemon-internal work, and a
/// supersession comes from the DAG side.
#[test]
fn a_row_superseded_since_the_caller_verified_it_commits_nothing() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    let tx = c.transaction().unwrap();
    let stale =
        crate::store::read_canonical_current_row(&tx, "g", "p").unwrap().unwrap().version_hash();

    // The supersession: same path, different content, so the version
    // the row derives moves. Nothing physical happened, so the fence
    // is untouched and a fence-only guard would still pass.
    tx.execute("UPDATE files SET size = 41 WHERE group_id = 'g' AND path = 'p'", []).unwrap();

    let outcome = commit_recovered_materialized_state(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([4u8; 32]),
        ExpectedAuthoring {
            state: MaterializationState::Placeholder,
            authoring_change_hash: None,
            expected_version: Some(&stale),
        },
        0,
    )
    .unwrap();

    assert!(matches!(outcome, RecoveredMaterializedCommit::Superseded), "{outcome:?}");
    assert!(
        lookup_materialized_generation(&tx, "g", "p").unwrap().is_none(),
        "a superseded attempt must publish no proof"
    );
    assert_eq!(
        materialization_state(&tx, "g", "p"),
        "placeholder",
        "and must not stamp the claim on a version it never verified"
    );
    assert!(
        intent_open(&tx, "g", "p"),
        "the intent is the only record that a write was in flight; a refused commit keeps it"
    );
}

/// The whole point: on success all three land together, under the
/// LIVE fence, without bumping it -- nothing was mutated here, so
/// advancing the fence would supersede evidence a concurrent internal
/// mutator holds for a write that really did happen.
#[test]
fn a_verified_row_is_published_promoted_and_cleared_in_one_step() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    let tx = c.transaction().unwrap();
    let fence_before =
        crate::materialized_generation::snapshot_mutation_fence(&tx, "g", "p").unwrap();
    let version =
        crate::store::read_canonical_current_row(&tx, "g", "p").unwrap().unwrap().version_hash();

    let outcome = commit_recovered_materialized_state(
        &tx,
        "g",
        "p",
        Some(&[]),
        &ExactMaterializedState::Object {
            kind: RecordKind::File,
            version,
            identity: Box::new(None),
        },
        ExpectedAuthoring {
            state: MaterializationState::Placeholder,
            authoring_change_hash: None,
            expected_version: Some(&version),
        },
        0,
    )
    .unwrap();

    assert!(matches!(outcome, RecoveredMaterializedCommit::Published(_)), "{outcome:?}");
    let basis = lookup_materialized_generation(&tx, "g", "p")
        .unwrap()
        .expect("the proof must be usable immediately");
    assert_eq!(basis.version, Some(version), "and must name the version the row derives");
    assert_eq!(materialization_state(&tx, "g", "p"), "hydrated");
    assert!(!intent_open(&tx, "g", "p"), "a finished materialization clears its intent");
    assert_eq!(
        crate::materialized_generation::snapshot_mutation_fence(&tx, "g", "p").unwrap(),
        fence_before,
        "recovery mutated nothing, so it must not advance the fence"
    );
}

/// A caller that verified bytes against a version has to be guarded on
/// it. Letting the check be skipped would publish for content this
/// commit never compared.
#[test]
fn recovering_without_an_expected_version_is_refused() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    let tx = c.transaction().unwrap();
    let err = commit_recovered_materialized_state(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([5u8; 32]),
        ExpectedAuthoring {
            state: MaterializationState::Placeholder,
            authoring_change_hash: None,
            expected_version: None,
        },
        0,
    )
    .expect_err("an unguarded recovery commit must be refused");
    assert!(err.to_string().contains("expected version"), "{err}");
}

/// The three writes are one commit, and the proof names its version.
#[test]
fn an_internal_commit_publishes_stamps_and_clears_together() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    let tx = c.transaction().unwrap();
    let n = crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "test", 0).unwrap();

    let outcome = commit_internal_materialized_state_if_fence_current(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([4u8; 32]),
        n,
        None,
        0,
    )
    .unwrap();
    assert!(matches!(outcome, InternalMaterializedCommit::Published(_)));
    tx.commit().unwrap();

    let basis = lookup_materialized_generation(&c, "g", "p").unwrap().expect("usable proof");
    assert_eq!(
        basis.version,
        Some(VersionHash([4u8; 32])),
        "the proof must name the version that was written"
    );
    assert_eq!(materialization_state(&c, "g", "p"), "hydrated");
    assert!(!intent_open(&c, "g", "p"), "a landed proof settles its intent");
}

/// A lost CAS writes none of the three -- and in particular leaves the
/// intent open, since it is the only record that a write was in
/// flight.
#[test]
fn a_fence_lost_internal_commit_writes_nothing_at_all() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    let tx = c.transaction().unwrap();
    let n = crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "mine", 0).unwrap();
    // Someone else mutates the path between this writer's write and
    // its commit.
    crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "competing", 0).unwrap();

    let outcome = commit_internal_materialized_state_if_fence_current(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([5u8; 32]),
        n,
        None,
        0,
    )
    .unwrap();
    match outcome {
        InternalMaterializedCommit::FenceLost { live_mutation_generation } => {
            assert_eq!(live_mutation_generation, Some(n + 1))
        }
        other => {
            panic!("the competing bump must have cost this writer its publish, got {other:?}")
        }
    }
    tx.commit().unwrap();

    assert!(
        crate::materialized_generation::lookup_materialized_generation_diagnostic(&c, "g", "p")
            .unwrap()
            .is_none(),
        "a lost CAS must publish no proof, not even a stale one"
    );
    assert_eq!(
        materialization_state(&c, "g", "p"),
        "placeholder",
        "a lost CAS must not stamp a claim this writer cannot prove"
    );
    assert!(
        intent_open(&c, "g", "p"),
        "clearing the intent here would erase the only record that a write was in flight"
    );
}

/// A superseded attempt records nothing, even though its own fence is
/// still current.
///
/// The bytes this attempt wrote are for a version the path no longer
/// wants. Stamping `Hydrated` would claim exactness for content that
/// is already stale, which is the failure the authoring CAS has always
/// existed to prevent -- folding it into this transaction is what
/// keeps the check and the commit from being two steps.
/// The version guard's RED half. The row is still `Hydrating` and
/// still carries the same authoring hash, so the authoring check
/// alone passes -- but the content the version is derived from has
/// moved on. A caller whose version came from an earlier snapshot
/// must be refused, and must write nothing.
#[test]
fn a_current_row_that_no_longer_names_the_expected_version_refuses_the_commit() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    c.execute(
        "UPDATE files SET materialization_state = 'hydrating' WHERE group_id = 'g' AND path = 'p'",
        [],
    )
    .unwrap();
    let tx = c.transaction().unwrap();
    let n = crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "mine", 0).unwrap();
    let live_version =
        crate::store::read_canonical_current_row(&tx, "g", "p").unwrap().unwrap().version_hash();
    let stale_version = VersionHash([0xAB; 32]);
    assert_ne!(stale_version, live_version, "the fixture must actually differ");

    let outcome = commit_internal_materialized_state_if_fence_current(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([5u8; 32]),
        n,
        Some(ExpectedAuthoring {
            state: MaterializationState::Hydrating,
            authoring_change_hash: None,
            expected_version: Some(&stale_version),
        }),
        0,
    )
    .unwrap();

    match outcome {
        InternalMaterializedCommit::AuthoringSuperseded => {}
        other => panic!("a stale version must be refused, got {other:?}"),
    }
    assert!(
        lookup_materialized_generation(&tx, "g", "p").unwrap().is_none(),
        "a refused commit must publish nothing"
    );
    let still_open: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM materialization_intents WHERE group_id = 'g' AND path = 'p'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(still_open, 1, "a refused commit must leave the intent open");
}

/// The GREEN half: the same call with the version the row actually
/// names publishes normally, so the RED above is the guard firing and
/// not the fixture being unable to commit at all.
#[test]
fn a_current_row_that_still_names_the_expected_version_commits() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    c.execute(
        "UPDATE files SET materialization_state = 'hydrating' WHERE group_id = 'g' AND path = 'p'",
        [],
    )
    .unwrap();
    let tx = c.transaction().unwrap();
    let n = crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "mine", 0).unwrap();
    let live = crate::store::read_canonical_current_row(&tx, "g", "p").unwrap().unwrap();
    let live_version = live.version_hash();
    // The state published and the guard's version describe the SAME
    // row. This fixture used to publish an arbitrary version against
    // a live-version guard, so it never exercised the agreeing case
    // it is named for -- the commit now refuses that outright.
    let exact = ExactMaterializedState::Object {
        kind: live.snapshot.record_kind,
        version: live_version,
        identity: Box::new(None),
    };

    let outcome = commit_internal_materialized_state_if_fence_current(
        &tx,
        "g",
        "p",
        Some(&[]),
        &exact,
        n,
        Some(ExpectedAuthoring {
            state: MaterializationState::Hydrating,
            authoring_change_hash: None,
            expected_version: Some(&live_version),
        }),
        0,
    )
    .unwrap();

    match outcome {
        InternalMaterializedCommit::Published(_) => {}
        other => panic!("the matching version must commit, got {other:?}"),
    }
    assert!(lookup_materialized_generation(&tx, "g", "p").unwrap().is_some());
}

/// Recovery's own guard: a re-prove whose row was superseded since the
/// snapshot it verified against publishes nothing at all, rather than
/// restoring a proof for a version the path has moved off.
#[test]
fn a_reprove_whose_row_was_superseded_publishes_nothing() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    c.execute(
        "UPDATE files SET materialization_state = 'hydrated' WHERE group_id = 'g' AND path = 'p'",
        [],
    )
    .unwrap();
    let tx = c.transaction().unwrap();
    let stale_version = VersionHash([0xCD; 32]);

    let published = reprove_verified_hydrated_state(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([6u8; 32]),
        Some(ExpectedAuthoring {
            state: MaterializationState::Hydrated,
            authoring_change_hash: None,
            expected_version: Some(&stale_version),
        }),
        0,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert!(published.is_none(), "a superseded re-prove must publish nothing");
    assert!(
        lookup_materialized_generation(&tx, "g", "p").unwrap().is_none(),
        "and must leave no generation behind"
    );
}

#[test]
fn a_superseded_attempt_is_refused_even_with_a_current_fence() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    open_intent(&c, "g", "p");
    c.execute(
        "UPDATE files SET materialization_state = 'hydrating' WHERE group_id = 'g' AND path = 'p'",
        [],
    )
    .unwrap();
    let tx = c.transaction().unwrap();
    let n = crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "test", 0).unwrap();

    // The row carries no authoring hash, so a guard demanding one is
    // the supersession this attempt must lose to.
    let other = ChangeHash([7u8; 32]);
    let outcome = commit_internal_materialized_state_if_fence_current(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([8u8; 32]),
        n,
        Some(ExpectedAuthoring {
            state: MaterializationState::Hydrating,
            authoring_change_hash: Some(&other),
            expected_version: None,
        }),
        0,
    )
    .unwrap();
    assert!(matches!(outcome, InternalMaterializedCommit::AuthoringSuperseded));
    tx.commit().unwrap();

    assert!(
        crate::materialized_generation::lookup_materialized_generation_diagnostic(&c, "g", "p")
            .unwrap()
            .is_none(),
        "a superseded attempt must publish nothing"
    );
    assert_eq!(
        materialization_state(&c, "g", "p"),
        "hydrating",
        "the row must be left exactly as it was found"
    );
    assert!(intent_open(&c, "g", "p"), "a superseded attempt still had a write in flight");
}

/// The healing lane restores a usable proof without claiming a
/// mutation happened.
#[test]
fn re_proving_publishes_under_the_live_fence_without_bumping_it() {
    let mut c = conn();
    seed_current_file(&c, "g", "p");
    let tx = c.transaction().unwrap();
    let live =
        crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "earlier", 0).unwrap();

    let basis = reprove_verified_hydrated_state(
        &tx,
        "g",
        "p",
        Some(&[]),
        &object([6u8; 32]),
        None,
        0,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert_eq!(
        basis.expect("an unguarded re-prove must publish").version,
        Some(VersionHash([6u8; 32]))
    );
    tx.commit().unwrap();

    assert!(
        lookup_materialized_generation(&c, "g", "p").unwrap().is_some(),
        "the recovered proof must be usable immediately, which it can only be if it was \
         published under the live fence"
    );
    let after = crate::materialized_generation::snapshot_mutation_fence(&c, "g", "p").unwrap();
    assert_eq!(
        after, live,
        "re-proving must not advance the fence: it would be claiming a physical mutation that \
         never happened, and would invalidate a concurrent mutator's evidence"
    );
}

fn set_group_heads(conn: &rusqlite::Connection, heads: &[ChangeHash]) {
    conn.execute("DELETE FROM group_heads WHERE group_id = 'g'", []).unwrap();
    for head in heads {
        conn.execute(
            "INSERT INTO group_heads (group_id, change_hash) VALUES ('g', ?1)",
            rusqlite::params![&head.0[..]],
        )
        .unwrap();
    }
}

fn proof_basis(conn: &rusqlite::Connection, path: &str) -> Vec<ChangeHash> {
    let proof = lookup_materialized_generation(conn, "g", path).unwrap().expect("a usable proof");
    crate::dag_store::lookup_causal_basis_members(conn, &proof.causal_basis_id.0)
        .unwrap()
        .expect("an interned basis")
}

/// A peer re-puts bytes this device already has on disk -- a
/// conflict-copy merge resolution naming the copy this device wrote
/// itself -- and the zero-work pre-check closes the obligation without
/// touching disk. The proof's causal basis is what the next local edit of
/// the path is parented on, so it has to name the frontier the close just
/// accepted as reflected on disk. Left on the older frontier, a user
/// deleting that copy here signs the delete concurrent with the peer's
/// put, the put wins, and the copy comes back on every device.
#[test]
fn a_zero_work_close_re_anchors_the_proof_on_the_frontier_it_accepted() {
    let mut c = conn();
    let (old_a, old_b, resolution) =
        (ChangeHash([1; 32]), ChangeHash([2; 32]), ChangeHash([3; 32]));
    let version = VersionHash([7; 32]);
    // Placed from the concurrent frontier {A, B}.
    crate::materialized_generation::record_materialized_generation(
        &c,
        "g",
        "copy",
        &[old_a, old_b],
        MaterializedObjectKind::RegularFile,
        Some(&version),
        None,
        0,
    )
    .unwrap();
    let fence_before = snapshot_mutation_fence(&c, "g", "copy").unwrap();
    // The peer's resolution is admitted on top: a new head, and a fresh
    // obligation for the path.
    set_group_heads(&c, &[resolution]);
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &c,
        "g",
        &["copy"],
        0,
    )
    .unwrap();
    let obligation = crate::projection_obligations::lookup_projection_obligation(&c, "g", "copy")
        .unwrap()
        .unwrap();
    let desired = crate::materialized_generation::compute_resolved_path_state_hash(
        "g",
        "copy",
        MaterializedObjectKind::RegularFile,
        Some(&version),
    );

    let tx = c.transaction().unwrap();
    let closed = complete_zero_work_obligation_rebasing_proof(
        &tx,
        "g",
        "copy",
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &desired,
        1,
    )
    .unwrap();
    tx.commit().unwrap();

    assert!(closed, "disk already holds the resolved state, so the obligation closes");
    assert_eq!(
        proof_basis(&c, "copy"),
        vec![resolution],
        "the proof must name the frontier the close accepted, not the one the bytes were \
         first placed from"
    );
    let proof = lookup_materialized_generation(&c, "g", "copy").unwrap().unwrap();
    assert_eq!(proof.version, Some(version), "the same object stays proven");
    assert_eq!(
        snapshot_mutation_fence(&c, "g", "copy").unwrap(),
        fence_before,
        "nothing was mutated on disk, so the fence must not move"
    );
}

/// A close the CAS refuses -- here, the proof describes a different
/// version than the path now wants -- must leave the proof exactly as it
/// was: re-anchoring a proof for bytes the path has moved off would
/// parent the next local edit on changes disk never reflected.
#[test]
fn a_refused_zero_work_close_leaves_the_proof_on_its_own_frontier() {
    let mut c = conn();
    let (old_a, old_b, newer) = (ChangeHash([1; 32]), ChangeHash([2; 32]), ChangeHash([3; 32]));
    let placed = VersionHash([7; 32]);
    crate::materialized_generation::record_materialized_generation(
        &c,
        "g",
        "copy",
        &[old_a, old_b],
        MaterializedObjectKind::RegularFile,
        Some(&placed),
        None,
        0,
    )
    .unwrap();
    set_group_heads(&c, &[newer]);
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &c,
        "g",
        &["copy"],
        0,
    )
    .unwrap();
    let obligation = crate::projection_obligations::lookup_projection_obligation(&c, "g", "copy")
        .unwrap()
        .unwrap();
    let wanted = crate::materialized_generation::compute_resolved_path_state_hash(
        "g",
        "copy",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([8; 32])),
    );

    let tx = c.transaction().unwrap();
    let closed = complete_zero_work_obligation_rebasing_proof(
        &tx,
        "g",
        "copy",
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &wanted,
        1,
    )
    .unwrap();
    tx.commit().unwrap();

    assert!(!closed, "the proof does not describe the wanted state");
    let mut expected = vec![old_a, old_b];
    expected.sort();
    assert_eq!(proof_basis(&c, "copy"), expected);
}

/// A proof that already names the current frontier has nothing to
/// re-anchor: the close leaves it untouched, generation included.
#[test]
fn a_zero_work_close_on_the_current_frontier_keeps_the_proof_generation() {
    let mut c = conn();
    let head = ChangeHash([4; 32]);
    let version = VersionHash([7; 32]);
    set_group_heads(&c, &[head]);
    let before = crate::materialized_generation::record_materialized_generation(
        &c,
        "g",
        "copy",
        &[head],
        MaterializedObjectKind::RegularFile,
        Some(&version),
        None,
        0,
    )
    .unwrap();
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &c,
        "g",
        &["copy"],
        0,
    )
    .unwrap();
    let obligation = crate::projection_obligations::lookup_projection_obligation(&c, "g", "copy")
        .unwrap()
        .unwrap();
    let desired = crate::materialized_generation::compute_resolved_path_state_hash(
        "g",
        "copy",
        MaterializedObjectKind::RegularFile,
        Some(&version),
    );

    let tx = c.transaction().unwrap();
    let closed = complete_zero_work_obligation_rebasing_proof(
        &tx,
        "g",
        "copy",
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &desired,
        1,
    )
    .unwrap();
    tx.commit().unwrap();

    assert!(closed);
    let after = lookup_materialized_generation(&c, "g", "copy").unwrap().unwrap();
    assert_eq!(after.generation_id, before.generation_id);
}
