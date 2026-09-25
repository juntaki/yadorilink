#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_replica_domain::session_state::ChangeContent;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_dag_schema(&c).unwrap();
    c
}

/// Admits `change` expecting a refusal for a path it names, and returns it.
/// A path refusal is an outcome rather than an error so that the caller's
/// transaction commits the durable record written with it.
fn path_refusal(conn: &Connection, change: &Change) -> PathRefusal {
    match admit_change(conn, change).expect("a path refusal is an outcome, not an error").outcome {
        AdmitOutcome::RefusedPath(refusal) => refusal,
        other => panic!("expected a path refusal, got {other:?}"),
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn test_version() -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn seed_test_version(conn: &Connection, group_id: &str) {
    put_file_version(conn, group_id, &test_version()).unwrap();
}

/// A version whose block sizes do not add up to its declared size hashes
/// fine -- `FileVersion::new` derives the hash from whatever it is given --
/// but it is not a valid version, and storing it must be refused. The
/// refusal has to say so: reporting it as "not found" sends every reader
/// of the log looking for a missing row, and lets any caller that treats
/// `NotFound` as "not resolvable yet" mistake a malformed local capture
/// for an ordinary lookup miss.
#[test]
fn a_structurally_invalid_version_is_refused_as_invalid_not_as_not_found() {
    let c = conn();
    let content = b"the bytes the chunker actually read";
    let blocks = vec![VersionBlock { hash: BlockHash(vec![0xAB; 32]), size: content.len() as u32 }];
    // A file that grew between the chunker reaching EOF and the stat that
    // supplied the size: the size no longer matches the blocks.
    let version = FileVersion::new(
        blocks,
        content.len() as u64 + 4096,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );

    let error = put_file_version(&c, "group-a", &version)
        .expect_err("a version whose blocks do not sum to its size must be refused");

    assert!(
        !matches!(error, SyncSqliteError::NotFound(_)),
        "a malformed version is not a lookup miss; got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("block sizes do not sum to the declared total size"),
        "the refusal must name the real cause (the block-size mismatch); got {message:?}"
    );
    let stored: i64 =
        c.query_row("SELECT COUNT(*) FROM file_versions", [], |row| row.get(0)).unwrap();
    assert_eq!(stored, 0, "nothing may be stored for a refused version");
}

#[test]
fn already_group_scoped_database_missing_cross_group_ownership_is_repaired() {
    // A database in the current shape whose `change_file_versions`
    // ownership rows are nonetheless incomplete: one version reachable
    // from two groups' signed history, recorded as owned by only the
    // first. Nothing about the table shape signals the gap, so only the
    // unconditional `repair_missing_file_version_ownership` pass can
    // close it -- re-deriving ownership from the canonical signed
    // history that is the authority for it, rather than trusting the
    // derived index.
    let c = conn();
    let version = test_version();
    put_file_version(&c, "group-a", &version).unwrap();
    emit_local_change(
        &c,
        "group-a",
        vec![Op::Put {
            path: SyncPath("a".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    put_file_version(&c, "group-b", &version).unwrap();
    emit_local_change(
        &c,
        "group-b",
        vec![Op::Put {
            path: SyncPath("b".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    // Simulate the prior migration's bug directly: drop group-b's row
    // while leaving the table itself in the (already current)
    // group-scoped shape.
    c.execute(
        "DELETE FROM file_versions WHERE group_id = 'group-b' AND version_hash = ?1",
        [&version.version_hash.0[..]],
    )
    .unwrap();
    assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_none());

    init_dag_schema(&c).unwrap();

    assert!(get_file_version(&c, "group-a", &version.version_hash).unwrap().is_some());
    assert!(
        get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some(),
        "a database already in the group-scoped shape must still have \
         cross-group ownership repaired from retained Changes"
    );
}

#[test]
fn schema_init_repairs_file_version_ownership_referenced_only_by_a_buffered_orphan() {
    // The plain `changes`-table backfill cannot see a version referenced
    // only by a change still buffered in `orphan_changes` (arrived
    // before its parent). Left unrepaired, that group's later
    // `promote_orphans` would fail `validate_referenced_versions`
    // forever once the parent does arrive.
    let sender = conn();
    let version = test_version();
    put_file_version(&sender, "group-b", &version).unwrap();
    let orphan = emit_local_change(
        &sender,
        "group-b",
        vec![Op::Put {
            path: SyncPath("b".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();

    let c = conn();
    put_file_version(&c, "group-a", &version).unwrap();
    insert_orphan(&c, &orphan).unwrap();
    assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_none());

    init_dag_schema(&c).unwrap();

    assert!(
        get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some(),
        "a version referenced only by a buffered orphan must still be \
         repaired into that orphan's group"
    );
    // An orphan is not yet admitted, so repairing its group's version
    // ownership must not also grant it block-serving authorization.
    let relations: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM change_file_versions WHERE group_id = 'group-b'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(relations, 0);
}

#[test]
fn block_reference_authorization_is_group_scoped() {
    let c = conn();
    let block_hash = vec![0xabu8; 32];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
        7,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    put_file_version(&c, "group-a", &version).unwrap();

    assert!(
        !group_file_version_references_block(&c, "group-a", &block_hash).unwrap(),
        "an unreferenced version must not authorize block service"
    );
    emit_local_change(
        &c,
        "group-a",
        vec![Op::Put {
            path: SyncPath("a.bin".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    assert!(group_file_version_references_block(&c, "group-a", &block_hash).unwrap());
    assert!(!group_file_version_references_block(&c, "group-b", &block_hash).unwrap());
    assert!(!group_file_version_references_block(&c, "group-a", &[0xcdu8; 32]).unwrap());
}

#[test]
fn frontier_heads_at_or_before_reflects_real_admission_including_concurrent_branches() {
    let c = conn();
    let group_id = "group-a";

    // Nothing admitted yet: any query, even "at or before the far
    // future", must find nothing to rewind to.
    assert_eq!(
        frontier_heads_at_or_before(&c, group_id, i64::MAX).unwrap(),
        None,
        "an empty group has no frontier at any time"
    );

    let root = emit_local_change(
        &c,
        group_id,
        vec![Op::Put {
            path: SyncPath("a.bin".into()),
            version: yadorilink_replica_domain::ids::VersionHash([0x11u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    let root_hash = root.compute_hash();
    // `now_unix_nanos()` is this same module's real wall-clock read --
    // reused here (not a fixed sleep) so the boundary this test checks
    // is exactly the one `append_change` itself would have recorded,
    // whatever the actual clock granularity/monotonicity turns out to
    // be on the machine running the test.
    let after_root = now_unix_nanos();

    // Two changes emitted onto the SAME parent (the root) are
    // genuinely concurrent -- neither is an ancestor of the other, so
    // both are real live heads simultaneously. This is exactly the
    // case a single scalar (e.g. a max lamport) cannot represent, and
    // the reason `change_time_index` stores the real head SET rather
    // than deriving one number from it.
    let branch_a = emit_local_change_onto(
        &c,
        group_id,
        vec![root_hash],
        vec![Op::Put {
            path: SyncPath("b.bin".into()),
            version: yadorilink_replica_domain::ids::VersionHash([0x22u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    let branch_b = emit_local_change_onto(
        &c,
        group_id,
        vec![root_hash],
        vec![Op::Put {
            path: SyncPath("c.bin".into()),
            version: yadorilink_replica_domain::ids::VersionHash([0x33u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    let after_fork = now_unix_nanos();

    // A rewind target between root-admission and the fork must see
    // ONLY the root as the frontier -- proving the real `emit_local_
    // change` -> `append_change` path records a usable, correctly-
    // ordered time index, not just the synthetic direct-SQL seeding
    // the scale benchmark uses.
    assert_eq!(
        frontier_heads_at_or_before(&c, group_id, after_root).unwrap(),
        Some(vec![root_hash]),
        "a rewind target before the fork must resolve to the root alone"
    );

    // A rewind target after the fork must see BOTH concurrent
    // branches, sorted -- a scalar frontier could only ever report one
    // of these two.
    let mut expected_fork_heads = vec![branch_a.compute_hash(), branch_b.compute_hash()];
    expected_fork_heads.sort_by_key(|h| h.0);
    assert_eq!(
        frontier_heads_at_or_before(&c, group_id, after_fork).unwrap(),
        Some(expected_fork_heads.clone()),
        "a rewind target after the fork must include BOTH concurrent branches, not just one"
    );
    // Cross-check against the live `group_heads` table itself -- the
    // recorded snapshot must always agree with what the ordinary
    // frontier-index machinery reports at the same point, since it was
    // read from that exact table.
    let mut live_heads = frontier_index::group_heads(&c, group_id).unwrap();
    live_heads.sort_by_key(|h| h.0);
    assert_eq!(
        live_heads, expected_fork_heads,
        "sanity: the live group_heads table must agree with the recorded snapshot"
    );

    // An unrelated group must never see this group's frontier.
    assert_eq!(
        frontier_heads_at_or_before(&c, "group-b", now_unix_nanos()).unwrap(),
        None,
        "group scoping must hold: an unrelated, never-admitted-to group has no frontier"
    );
}

/// Two admissions that landed on the same `observed_at_unix_nanos` --
/// routine whenever the local clock's granularity is coarser than the
/// gap between two writes -- must resolve to the LATER one. Seeded
/// directly so the collision is guaranteed rather than left to whatever
/// the host clock happens to do; the real-admission path is covered by
/// `frontier_heads_at_or_before_reflects_real_admission_including_
/// concurrent_branches` above.
#[test]
fn a_timestamp_tie_resolves_to_the_later_admission_not_an_arbitrary_one() {
    let c = conn();
    let earlier = [0xEEu8; 32];
    let later = [0x11u8; 32];
    for (admission_seq, head) in [(1i64, earlier), (2, later)] {
        c.execute(
            "INSERT INTO change_time_index \
             (group_id, admission_seq, observed_at_unix_nanos, heads_snapshot) \
             VALUES ('g', ?1, 5000, ?2)",
            rusqlite::params![admission_seq, &head[..]],
        )
        .unwrap();
    }
    // Deliberately NOT distinguishable by the ordering column alone:
    // both rows share `observed_at_unix_nanos`, and the earlier
    // admission's head sorts HIGHER by raw bytes, so a query that fell
    // back to any incidental order would be very likely to return it.
    assert_eq!(
        frontier_heads_at_or_before(&c, "g", 5000).unwrap(),
        Some(vec![ChangeHash(later)]),
        "a tie on the timestamp must resolve by admission_seq to the later admission"
    );
    assert_eq!(
        frontier_heads_at_or_before(&c, "g", 4999).unwrap(),
        None,
        "sanity: the boundary is still inclusive-at-or-before, not fuzzy"
    );
}

/// The tie-break above must not have cost the query its bounded shape:
/// `ORDER BY a DESC, b DESC LIMIT 1` over an index on `(group_id, a)`
/// alone would make SQLite sort the whole matching range in a temporary
/// b-tree -- cost proportional to the group's entire admission history,
/// which is precisely the collapse shape this table exists to avoid.
/// Asserted against the real statement, not a copy of it.
#[test]
fn frontier_query_is_answered_by_a_reverse_index_seek() {
    let c = conn();
    let plan: Vec<String> = {
        let mut stmt = c
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                retained_history_integrity::FRONTIER_AT_OR_BEFORE_SQL
            ))
            .unwrap();
        let rows = stmt.query_map(rusqlite::params!["g", 0i64], |row| row.get::<_, String>(3));
        rows.unwrap().collect::<Result<_, _>>().unwrap()
    };
    let plan = plan.join("\n");
    assert!(
        plan.contains("change_time_index_by_time"),
        "the frontier query must use its own index; plan was:\n{plan}"
    );
    assert!(
        !plan.to_uppercase().contains("TEMP B-TREE"),
        "the frontier query must never sort a range to satisfy its ORDER BY; plan was:\n{plan}"
    );
}

fn time_index_snapshots(conn: &Connection, group_id: &str) -> Vec<(i64, Vec<u8>)> {
    let mut stmt = conn
        .prepare(
            "SELECT admission_seq, heads_snapshot FROM change_time_index \
             WHERE group_id = ?1 ORDER BY admission_seq",
        )
        .unwrap();
    let rows = stmt
        .query_map([group_id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// The time index is derived from `group_heads`, so compaction has to
/// cut it back too. Without this, a pruned group accumulates snapshots
/// naming changes whose bodies are gone -- unbounded stale rows that
/// `frontier_heads_at_or_before` would hand back as an answer.
#[test]
fn pruning_history_removes_the_time_index_snapshots_that_named_it() {
    let c = conn();
    let em = emitter();

    let prior = emit_local_change(&c, "g", vec![create_op("prior.txt")], &em).unwrap();
    let prior_hash = prior.compute_hash();
    let child = emit_local_change(&c, "g", vec![create_op("child.txt")], &em).unwrap();
    let child_hash = child.compute_hash();
    // An unrelated group's own history must be untouched by all of this.
    emit_local_change(&c, "other", vec![create_op("theirs.txt")], &em).unwrap();

    let before = time_index_snapshots(&c, "g");
    assert_eq!(before.len(), 2, "each admission records one snapshot");
    assert_eq!(before[0].1, prior_hash.0.to_vec());
    assert_eq!(before[1].1, child_hash.0.to_vec());

    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![child_hash],
        [0u8; 32],
    );
    {
        let tx = c.unchecked_transaction().unwrap();
        commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
        tx.commit().unwrap();
    }
    assert!(!has_change(&c, &prior_hash).unwrap());

    let after = time_index_snapshots(&c, "g");
    assert_eq!(after.len(), 1, "the snapshot naming the pruned change must go with it, not linger");
    assert_eq!(
        after[0].1,
        child_hash.0.to_vec(),
        "the snapshot naming only retained history must survive"
    );
    assert_eq!(
        frontier_heads_at_or_before(&c, "g", i64::MAX).unwrap(),
        Some(vec![child_hash]),
        "the surviving snapshot must still be readable"
    );
    assert_eq!(
        time_index_snapshots(&c, "other").len(),
        1,
        "an unrelated group's time index must not be touched by this group's prune"
    );

    // `admission_seq` must keep increasing across a prune: the tie-break
    // in `frontier_heads_at_or_before` treats a higher value as strictly
    // later, so a post-prune admission may never reuse a surviving row's
    // sequence number.
    emit_local_change(&c, "g", vec![create_op("later.txt")], &em).unwrap();
    let seqs: Vec<i64> = time_index_snapshots(&c, "g").iter().map(|(seq, _)| *seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "admission_seq must stay strictly increasing after a prune, got {seqs:?}"
    );
    assert!(
        seqs.last().copied() > Some(after[0].0),
        "the post-prune admission must sort after every surviving row, got {seqs:?}"
    );
}

#[test]
fn admitted_metadata_does_not_forge_block_provenance() {
    let c = conn();
    let block_hash = vec![0xabu8; 32];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
        7,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    put_file_version(&c, "group-a", &version).unwrap();
    emit_local_change(
        &c,
        "group-a",
        vec![Op::Put {
            path: SyncPath("attacker-controlled.bin".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();

    assert!(group_file_version_references_block(&c, "group-a", &block_hash).unwrap());
    assert!(
        !group_has_block_provenance(&c, "group-a", &block_hash).unwrap(),
        "even admitted, correctly signed metadata must not prove byte ownership"
    );

    record_group_block_provenance(&c, "group-b", std::slice::from_ref(&block_hash)).unwrap();
    assert!(group_has_block_provenance(&c, "group-b", &block_hash).unwrap());
    assert!(
        !group_has_block_provenance(&c, "group-a", &block_hash).unwrap(),
        "physical dedup must not leak provenance across groups"
    );

    record_group_block_provenance(&c, "group-a", std::slice::from_ref(&block_hash)).unwrap();
    assert!(group_has_block_provenance(&c, "group-a", &block_hash).unwrap());
}

#[test]
fn rejected_change_rolls_back_its_versions_and_grants_no_block_capability() {
    let state =
        yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    let block_hash = vec![0x42; 32];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
        7,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let signing = key();
    let mut change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId("group-a".into()),
        vec![Op::Put {
            path: SyncPath("poison.bin".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &signing,
    );
    change.lamport = 99;
    change.sign(&signing);

    assert!(state
        .change_history_repository()
        .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
        .is_err());
    assert!(!state.sqlite().dag_has_file_version("group-a", &version.version_hash).unwrap());
    assert!(!state
        .change_history_repository()
        .dag_group_file_version_references_block("group-a", &block_hash)
        .unwrap());
}

#[test]
fn orphan_version_grants_no_block_capability_until_promotion() {
    let c = conn();
    let block_hash = vec![0x24; 32];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
        7,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    put_file_version(&c, "g", &version).unwrap();
    let signing = key();
    let parent = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("old.bin".into()) }],
        &signing,
    );
    let child = create_signed_for_tests(
        vec![parent.compute_hash()],
        parent.lamport,
        DeviceId("device-A".into()),
        FolderGroupId("g".into()),
        vec![Op::Put {
            path: SyncPath("new.bin".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &signing,
    );

    assert_eq!(admit_change(&c, &child).unwrap().outcome, AdmitOutcome::Orphaned);
    assert!(!group_file_version_references_block(&c, "g", &block_hash).unwrap());
    assert_eq!(admit_change(&c, &parent).unwrap().outcome, AdmitOutcome::Applied);
    assert!(group_file_version_references_block(&c, "g", &block_hash).unwrap());
}

#[test]
fn schema_init_backfills_admitted_change_version_relations() {
    let c = conn();
    let block_hash = vec![0x66; 32];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
        7,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    put_file_version(&c, "g", &version).unwrap();
    emit_local_change(
        &c,
        "g",
        vec![Op::Put {
            path: SyncPath("a".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter(),
    )
    .unwrap();
    c.execute("DELETE FROM change_file_versions", []).unwrap();
    assert!(!group_file_version_references_block(&c, "g", &block_hash).unwrap());

    init_dag_schema(&c).unwrap();
    assert!(group_file_version_references_block(&c, "g", &block_hash).unwrap());
}

#[test]
fn version_sweep_fails_closed_on_a_corrupt_retained_change() {
    let c = conn();
    let version = test_version();
    put_file_version(&c, "g", &version).unwrap();
    c.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, author_seq, lamport, encoded) \
         VALUES (?1, 'g', 'device-A', 1, 1, ?2)",
        rusqlite::params![vec![0x91u8; 32], b"not-a-change".as_slice()],
    )
    .unwrap();

    let error = sweep_unreferenced_file_versions(&c, "g")
        .expect_err("corrupt retained history must abort version GC");
    assert!(matches!(error, SyncSqliteError::CorruptState(_)));
    assert!(get_file_version(&c, "g", &version.version_hash).unwrap().is_some());
}

/// A prune removes the changes a path's materialized basis may name. A
/// basis left standing still reads as current, and the device's next edit
/// of that path would be parented on history this group no longer holds
/// -- below the checkpoint every peer now starts from. The prune has to
/// take the group's bases with it, in its own transaction.
#[test]
fn pruning_history_retires_the_materialized_bases_that_named_it() {
    let c = conn();
    let em = emitter();

    let prior = emit_local_change(&c, "g", vec![create_op("prior.txt")], &em).unwrap();
    let prior_hash = prior.compute_hash();
    crate::materialized_generation::record_materialized_generation(
        &c,
        "g",
        "prior.txt",
        &[prior_hash],
        crate::materialized_generation::MaterializedObjectKind::RegularFile,
        Some(&test_version().version_hash),
        None,
        0,
    )
    .unwrap();
    let child = emit_local_change(&c, "g", vec![create_op("child.txt")], &em).unwrap();
    let child_hash = child.compute_hash();
    // An unrelated group's basis must survive this group's prune.
    let theirs = emit_local_change(&c, "other", vec![create_op("theirs.txt")], &em).unwrap();
    crate::materialized_generation::record_materialized_generation(
        &c,
        "other",
        "theirs.txt",
        &[theirs.compute_hash()],
        crate::materialized_generation::MaterializedObjectKind::RegularFile,
        Some(&test_version().version_hash),
        None,
        0,
    )
    .unwrap();

    // A writer that read prior.txt's fence before the prune and publishes
    // after it.
    let in_flight_epoch =
        crate::materialized_generation::snapshot_mutation_fence(&c, "g", "prior.txt").unwrap();

    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![child_hash],
        [0u8; 32],
    );
    // The retirement is part of the prune's own transaction: a prune that
    // does not commit leaves both the basis and the fence as they were.
    {
        let tx = c.unchecked_transaction().unwrap();
        commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
        drop(tx);
    }
    assert!(has_change(&c, &prior_hash).unwrap(), "sanity: the prune rolled back");
    assert!(
        crate::materialized_generation::lookup_materialized_generation(&c, "g", "prior.txt")
            .unwrap()
            .is_some(),
        "a rolled-back prune must not retire the basis"
    );
    assert_eq!(
        crate::materialized_generation::snapshot_mutation_fence(&c, "g", "prior.txt").unwrap(),
        in_flight_epoch,
        "a rolled-back prune must not move the fence"
    );
    {
        let tx = c.unchecked_transaction().unwrap();
        commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
        tx.commit().unwrap();
    }
    assert!(!has_change(&c, &prior_hash).unwrap());

    // Both halves of the retirement: the row is gone, and the fence has
    // moved so that the in-flight writer cannot put a pre-prune basis back.
    assert!(
        crate::materialized_generation::lookup_materialized_generation_diagnostic(
            &c,
            "g",
            "prior.txt"
        )
        .unwrap()
        .is_none(),
        "the prune must delete the basis row, not only make it unreadable"
    );
    assert!(
        crate::materialized_generation::publish_materialized_generation_if_fence_current(
            &c,
            "g",
            "prior.txt",
            &[prior_hash],
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            Some(&test_version().version_hash),
            None,
            in_flight_epoch,
            0,
        )
        .unwrap()
        .is_none(),
        "a writer that read the fence before the prune must not republish a pruned basis"
    );

    let basis =
        crate::materialized_generation::lookup_materialized_generation(&c, "g", "prior.txt")
            .unwrap()
            .map(|generation| {
                lookup_causal_basis_members(&c, &generation.causal_basis_id.0)
                    .unwrap()
                    .expect("an interned basis")
            });
    assert_eq!(
        basis.as_ref().map(|members| members.iter().map(|h| h.to_hex()).collect::<Vec<_>>()),
        None,
        "prior.txt's basis names {} which the prune removed, yet it still reads as current",
        prior_hash.to_hex(),
    );
    assert!(
        crate::materialized_generation::lookup_materialized_generation(&c, "other", "theirs.txt")
            .unwrap()
            .is_some(),
        "an unrelated group's basis must not be touched by this group's prune"
    );
}

fn create_op(path: &str) -> Op {
    Op::Put {
        path: SyncPath(path.into()),
        version: test_version().version_hash,
        origin: PutOrigin::Direct,
    }
}

/// Builds a validly-signed root change directly via `Change::
/// create_signed`, bypassing `emit_local_change` entirely -- used by
/// the `admit_change_rejects_*` tests below, which construct a
/// deliberately reserved/non-portable-path change specifically to
/// drive the RECEIVING side's own rejection (`admit_change`), not the
/// local-emission-side check `emit_local_change` also applies (see
/// `emit_local_change`'s own comment). Using `emit_local_change` to build
/// these fixtures would refuse the change before it could ever reach
/// the `admit_change` call these tests actually exercise.
fn hand_signed_change(group_id: &str, ops: Vec<Op>) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId(group_id.into()),
        ops,
        &key(),
    )
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-A", key())
}

#[test]
fn local_emission_chains_heads() {
    let c = conn();
    let em = emitter();

    let c1 = emit_local_change(&c, "g", vec![create_op("a")], &em).unwrap();
    assert_eq!(c1.parents, vec![]);
    assert_eq!(c1.lamport, 1);
    assert_eq!(group_heads(&c, "g").unwrap(), vec![c1.compute_hash()]);

    let c2 = emit_local_change(&c, "g", vec![create_op("b")], &em).unwrap();
    // c2 descends from c1, so c1 is no longer a head.
    assert_eq!(c2.parents, vec![c1.compute_hash()]);
    assert_eq!(c2.lamport, 2);
    assert_eq!(group_heads(&c, "g").unwrap(), vec![c2.compute_hash()]);

    assert!(is_ancestor(&c, &c1.compute_hash(), &c2.compute_hash()).unwrap());
    assert!(!is_ancestor(&c, &c2.compute_hash(), &c1.compute_hash()).unwrap());
}

/// `admit_change` (the RECEIVING side) refuses a change containing a non-portable path component
/// (a trailing `.`/` `, which a POSIX filesystem accepts but Windows
/// silently normalizes away) via `validate_no_reserved_paths` -- but
/// LOCAL authoring (`emit_local_change`, reachable directly here, and
/// by extension every one of its own callers: the live watcher,
/// `append_history_backfill`, `emit_local_change_onto`'s rebootstrap
/// squash, `emit_retroactive_repair`) must apply the identical check
/// before signing. Otherwise a POSIX device could sign and append a change no other peer could ever
/// admit, becoming this
/// device's own head with nothing left to build on for every peer
/// that permanently rejects it.
#[test]
fn emit_local_change_refuses_a_non_portable_path() {
    let c = conn();
    let em = emitter();

    let err = emit_local_change(
        &c,
        "g",
        vec![create_op("report.")], // trailing dot: invalid on Windows
        &em,
    )
    .expect_err("a non-portable path must be refused before it is ever signed and appended");
    assert!(
        matches!(err, SyncSqliteError::NonPortablePath(_)),
        "unexpected error variant: {err:?}"
    );
    assert!(
        group_heads(&c, "g").unwrap().is_empty(),
        "the refused change must never become this group's head"
    );
}

/// Same local-authoring-side coverage as
/// `emit_local_change_refuses_a_non_portable_path`, for the reserved
/// Windows device-basename branch of `path_has_non_portable_wire_
/// component` instead of the trailing-dot/space branch. Mirrors
/// `admit_change_rejects_a_reserved_windows_device_name_path` (the
/// RECEIVING-side test for this same predicate, above), so both call
/// sites of `validate_no_reserved_paths` are directly, independently
/// covered for this hazard shape rather than only the receiving side.
#[test]
fn emit_local_change_refuses_a_reserved_windows_device_name() {
    for name in ["CON", "com1", "LPT9.log"] {
        let c = conn();
        let em = emitter();
        let err = emit_local_change(&c, "g", vec![create_op(name)], &em).expect_err(
            "a reserved Windows device name must be refused before it is ever signed \
                 and appended",
        );
        assert!(
            matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == name),
            "{name:?}: expected NonPortablePath, got {err:?}"
        );
        assert!(
            group_heads(&c, "g").unwrap().is_empty(),
            "{name:?}: the refused change must never become this group's head"
        );
    }
}

/// Same local-authoring-side coverage as
/// `emit_local_change_refuses_a_non_portable_path`, for the Win32
/// reserved-filename-character branch instead of the trailing-dot/space
/// branch. Mirrors `admit_change_rejects_a_path_with_a_win32_reserved_
/// filename_character` (the RECEIVING-side test for this same
/// predicate, above).
#[test]
fn emit_local_change_refuses_a_win32_reserved_filename_character() {
    for ch in ['<', '>', '"', '|', '?', '*'] {
        let path = format!("notes{ch}draft.txt");
        let c = conn();
        let em = emitter();
        let err = emit_local_change(&c, "g", vec![create_op(&path)], &em).expect_err(
            "a Win32-reserved filename character must be refused before it is ever \
                     signed and appended",
        );
        assert!(
            matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == &path),
            "{ch:?}: expected NonPortablePath, got {err:?}"
        );
        assert!(
            group_heads(&c, "g").unwrap().is_empty(),
            "{ch:?}: the refused change must never become this group's head"
        );
    }
}

#[test]
fn append_is_idempotent_under_duplicate_delivery() {
    let c = conn();
    let change = emit_local_change(&c, "g", vec![create_op("a")], &emitter()).unwrap();
    // Re-appending the identical change changes nothing.
    assert!(!append_change(&c, &change, now_unix_nanos()).unwrap());
    let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
    assert_eq!(group_heads(&c, "g").unwrap().len(), 1);
}

#[test]
fn concurrent_changes_are_both_heads() {
    // Two devices edit from the same (empty) frontier without seeing
    // each other: both become heads.
    let c = conn();
    let a = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[1u8; 32]));
    let b = ChangeEmitter::new("device-B", SigningKey::from_bytes(&[2u8; 32]));
    let ca = emit_local_change(&c, "g", vec![create_op("a")], &a).unwrap();
    seed_test_version(&c, "g");
    // Force B's change to also root at the empty frontier by admitting it
    // as if it arrived from a peer (its parents = []).
    let cb = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-B".into()),
        FolderGroupId("g".into()),
        vec![create_op("b")],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    let _ = b;
    assert_eq!(admit_change(&c, &cb).unwrap().outcome, AdmitOutcome::Applied);
    let mut heads = group_heads(&c, "g").unwrap();
    heads.sort();
    let mut expected = vec![ca.compute_hash(), cb.compute_hash()];
    expected.sort();
    assert_eq!(heads, expected);
}

/// A write to a path its author has seen no version of must not claim any
/// version of that path, neither directly nor through a later change that
/// descends from one. Everything else the frontier holds is still claimed.
#[test]
fn frontier_without_path_cuts_the_paths_versions_and_their_descendants() {
    let c = conn();
    seed_test_version(&c, "g");
    let base = emit_local_change(&c, "g", vec![create_op("base.txt")], &emitter()).unwrap();
    let base_hash = base.compute_hash();
    let peer_key = SigningKey::from_bytes(&[7u8; 32]);
    let peer_change = |parents: Vec<ChangeHash>, lamport: u64, path: &str| {
        create_signed_for_tests(
            parents,
            lamport,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op(path)],
            &peer_key,
        )
    };
    // A peer creates the path, then edits another path on top of it.
    let create = peer_change(vec![base_hash], base.lamport, "new.txt");
    assert_eq!(admit_change(&c, &create).unwrap().outcome, AdmitOutcome::Applied);
    let on_top = peer_change(vec![create.compute_hash()], create.lamport, "other.txt");
    assert_eq!(admit_change(&c, &on_top).unwrap().outcome, AdmitOutcome::Applied);
    // And, concurrently, a change that has nothing to do with the path.
    let unrelated = peer_change(vec![base_hash], base.lamport, "unrelated.txt");
    assert_eq!(admit_change(&c, &unrelated).unwrap().outcome, AdmitOutcome::Applied);

    assert_eq!(
        path_frontier::frontier_without_unseen_path_heads(&c, "g", "never-written.txt", None)
            .unwrap(),
        None,
        "a path with no version leaves the frontier to the caller"
    );
    let parents = path_frontier::frontier_without_unseen_path_heads(&c, "g", "new.txt", None)
        .unwrap()
        .unwrap();
    assert_eq!(parents, vec![unrelated.compute_hash()]);

    let local =
        emit_local_change_onto(&c, "g", parents, vec![create_op("new.txt")], &emitter()).unwrap();
    let local_hash = local.compute_hash();
    for claimed in [create.compute_hash(), on_top.compute_hash()] {
        assert!(!is_ancestor(&c, &claimed, &local_hash).unwrap());
    }
    assert!(is_ancestor(&c, &base_hash, &local_hash).unwrap());
    let mut live: Vec<[u8; 32]> =
        live_path_heads(&c, "g", "new.txt").unwrap().into_iter().map(|h| h.change_hash).collect();
    live.sort();
    let mut expected = vec![create.compute_hash().0, local_hash.0];
    expected.sort();
    assert_eq!(live, expected, "both versions of the path must stay live");
}

#[test]
fn out_of_order_arrival_is_orphaned_then_promoted() {
    // Build a chain root -> child on a "sender", then deliver child
    // first to a fresh receiver.
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let child = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    // Child arrives before its parent: held, not applied.
    assert_eq!(admit_change(&recv, &child).unwrap().outcome, AdmitOutcome::Orphaned);
    assert!(!has_change(&recv, &child.compute_hash()).unwrap());
    assert!(group_heads(&recv, "g").unwrap().is_empty());

    // Parent arrives: it applies and promotes the buffered child.
    assert_eq!(admit_change(&recv, &root).unwrap().outcome, AdmitOutcome::Applied);
    assert!(has_change(&recv, &root.compute_hash()).unwrap());
    assert!(has_change(&recv, &child.compute_hash()).unwrap());
    // The frontier converged to the single child head, just like the sender.
    assert_eq!(group_heads(&recv, "g").unwrap(), vec![child.compute_hash()]);
    assert_eq!(group_heads(&recv, "g").unwrap(), group_heads(&sender, "g").unwrap());
}

#[test]
fn missing_ancestor_frontier_walks_through_a_stuck_buffered_orphan() {
    // A 3-generation chain root -> mid -> leaf built on a sender.
    // Deliver `leaf` and `mid` to a fresh receiver, but never `root` --
    // both `leaf` and `mid` buffer as orphans, `root` never arrives.
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let mid = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();
    let leaf = emit_local_change(&sender, "g", vec![create_op("c")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &leaf).unwrap().outcome, AdmitOutcome::Orphaned);
    assert_eq!(admit_change(&recv, &mid).unwrap().outcome, AdmitOutcome::Orphaned);

    // The one-level check treats `leaf` as fully known (it's buffered),
    // exactly the gap this fn exists to close: a caller relying on it
    // alone would never discover that `root` is genuinely missing.
    assert!(has_change_or_buffered_orphan(&recv, &leaf.compute_hash()).unwrap());

    let missing = missing_ancestor_frontier(&recv, [leaf.compute_hash()]).unwrap();
    assert_eq!(missing, vec![root.compute_hash()]);

    // Once `root` lands, the whole buffered chain promotes.
    assert_eq!(admit_change(&recv, &root).unwrap().outcome, AdmitOutcome::Applied);
    assert!(has_change(&recv, &leaf.compute_hash()).unwrap());
    assert_eq!(group_heads(&recv, "g").unwrap(), vec![leaf.compute_hash()]);
    assert!(missing_ancestor_frontier(&recv, [leaf.compute_hash()]).unwrap().is_empty());
}

#[test]
fn missing_ancestor_frontier_is_empty_for_a_change_only_waiting_on_an_in_flight_parent() {
    // A single-generation chain: `leaf`'s direct parent `root` simply
    // hasn't arrived yet (not itself stuck behind anything). The old
    // one-level check already handled this correctly -- confirms the
    // new fn doesn't regress the ordinary in-flight case into treating
    // an about-to-be-satisfied orphan as if its own immediate parent
    // were missing when it's genuinely just still in transit.
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let leaf = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &leaf).unwrap().outcome, AdmitOutcome::Orphaned);

    let missing = missing_ancestor_frontier(&recv, [leaf.compute_hash()]).unwrap();
    assert_eq!(missing, vec![root.compute_hash()]);
}

#[test]
fn missing_ancestor_frontier_dedups_a_missing_ancestor_shared_by_two_roots() {
    // Two independent chains, `root -> a` and `root -> b`, sharing the
    // same never-delivered `root`. Both `a` and `b` buffer as orphans;
    // querying both as roots together must report the shared missing
    // ancestor exactly once, not twice -- this is the whole point of
    // taking every root of one logical request in a single call instead
    // of one call per root. Built via two sibling connections both
    // seeded with the already-admitted `root` (so each independently
    // emits a local change parented on it), rather than hand-building
    // `Change` values directly.
    let origin = conn();
    let em_root = emitter();
    let root = emit_local_change(&origin, "g", vec![create_op("root")], &em_root).unwrap();

    let sender_a = conn();
    seed_test_version(&sender_a, "g");
    assert_eq!(admit_change(&sender_a, &root).unwrap().outcome, AdmitOutcome::Applied);
    let em_a = ChangeEmitter::new("device-a", key());
    let a = emit_local_change(&sender_a, "g", vec![create_op("a")], &em_a).unwrap();
    assert_eq!(a.parents, vec![root.compute_hash()]);

    let sender_b = conn();
    seed_test_version(&sender_b, "g");
    assert_eq!(admit_change(&sender_b, &root).unwrap().outcome, AdmitOutcome::Applied);
    let em_b = ChangeEmitter::new("device-b", key());
    let b = emit_local_change(&sender_b, "g", vec![create_op("b")], &em_b).unwrap();
    assert_eq!(b.parents, vec![root.compute_hash()]);

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &a).unwrap().outcome, AdmitOutcome::Orphaned);
    assert_eq!(admit_change(&recv, &b).unwrap().outcome, AdmitOutcome::Orphaned);

    let missing = missing_ancestor_frontier(&recv, [a.compute_hash(), b.compute_hash()]).unwrap();
    assert_eq!(missing, vec![root.compute_hash()]);
}

#[test]
fn missing_ancestor_frontier_reports_only_the_genuinely_missing_branch() {
    // Two independent single-parent chains: one whose parent is already
    // durably admitted (fully resolved, contributes nothing), one whose
    // parent never arrived (genuinely missing). Confirms the walk
    // doesn't conflate an admitted branch with a missing one when both
    // are queried together.
    let admitted_origin = conn();
    let em_p1 = emitter();
    let admitted_parent =
        emit_local_change(&admitted_origin, "g", vec![create_op("p1")], &em_p1).unwrap();

    let missing_origin = conn();
    let em_p2 = ChangeEmitter::new("device-missing", key());
    let missing_parent =
        emit_local_change(&missing_origin, "g", vec![create_op("p2")], &em_p2).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    // `admitted_parent` lands normally (its own parent set is empty --
    // the first change in this group's history on `recv` -- so it
    // applies immediately).
    assert_eq!(admit_change(&recv, &admitted_parent).unwrap().outcome, AdmitOutcome::Applied);

    let resolved_sender = conn();
    seed_test_version(&resolved_sender, "g");
    assert_eq!(
        admit_change(&resolved_sender, &admitted_parent).unwrap().outcome,
        AdmitOutcome::Applied
    );
    let em_resolved = ChangeEmitter::new("device-a", key());
    let resolved_child =
        emit_local_change(&resolved_sender, "g", vec![create_op("resolved-child")], &em_resolved)
            .unwrap();
    assert_eq!(admit_change(&recv, &resolved_child).unwrap().outcome, AdmitOutcome::Applied);

    let orphaned_sender = conn();
    seed_test_version(&orphaned_sender, "g");
    assert_eq!(
        admit_change(&orphaned_sender, &missing_parent).unwrap().outcome,
        AdmitOutcome::Applied
    );
    let em_orphaned = ChangeEmitter::new("device-b", key());
    let orphaned_child =
        emit_local_change(&orphaned_sender, "g", vec![create_op("orphaned-child")], &em_orphaned)
            .unwrap();
    assert_eq!(admit_change(&recv, &orphaned_child).unwrap().outcome, AdmitOutcome::Orphaned);

    let missing = missing_ancestor_frontier(
        &recv,
        [resolved_child.compute_hash(), orphaned_child.compute_hash()],
    )
    .unwrap();
    assert_eq!(missing, vec![missing_parent.compute_hash()]);
}

#[test]
fn missing_ancestor_frontier_propagates_a_corrupt_parent_hash_rather_than_calling_it_missing() {
    // A malformed (non-32-byte) `change_parents.parent_hash` column must
    // surface as an error from the walk, not be silently treated as
    // "the peer doesn't have this either" -- folding a local data/DB
    // problem into "missing" would trigger needless re-fetch storms
    // instead of surfacing the real defect.
    let sender = conn();
    let em = emitter();
    // `leaf` needs a genuinely missing parent to orphan at all -- a
    // change with no parents (the group's very first) applies
    // immediately instead.
    let _root = emit_local_change(&sender, "g", vec![create_op("root")], &em).unwrap();
    let leaf = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &leaf).unwrap().outcome, AdmitOutcome::Orphaned);
    recv.execute("DELETE FROM change_parents WHERE child_hash = ?1", [&leaf.compute_hash().0[..]])
        .unwrap();
    recv.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&leaf.compute_hash().0[..], vec![0xffu8; 4]],
    )
    .unwrap();

    let error = missing_ancestor_frontier(&recv, [leaf.compute_hash()])
        .expect_err("a malformed parent-hash column must be a hard error");
    assert!(matches!(error, SyncSqliteError::NotFound(_)));
}

#[test]
fn promote_orphans_returns_promoted_hashes_in_append_order() {
    // A chain root -> c1 -> c2 built on a sender, with the two descendants
    // delivered to a fresh receiver before their common ancestor. When the
    // ancestor lands, promotion must return the promoted changes' hashes in
    // the order they were appended (oldest-first): the admission caller
    // projects each promoted orphan's paths, so it needs their identities,
    // not just a count.
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let c1 = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();
    let c2 = emit_local_change(&sender, "g", vec![create_op("c")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    // Both descendants arrive before the root: buffered, nothing promoted.
    assert_eq!(admit_change(&recv, &c1).unwrap().outcome, AdmitOutcome::Orphaned);
    assert_eq!(admit_change(&recv, &c2).unwrap().outcome, AdmitOutcome::Orphaned);

    // Land the root directly and promote: c1 unblocks first (its parent is
    // the root), then c2 (its parent is c1).
    assert!(append_change(&recv, &root, now_unix_nanos()).unwrap());
    let promoted = promote_orphans(&recv, &[root.compute_hash()]).unwrap();
    assert_eq!(promoted, vec![c1.compute_hash(), c2.compute_hash()]);
}

/// `init_dag_schema`'s startup self-heal sweep (`already_satisfied_parents`
/// -> `promote_orphans` -> `bump_execution_fence_for_promoted`) runs
/// inside one explicit transaction: unlike ordinary admission (always
/// wrapped in `write_immediate` by its caller), nothing else wraps this
/// startup sweep, and running its two mutating steps as independent
/// statements on a bare autocommit connection would let a failure
/// between them (or a process crash) leave a change durably
/// promoted with no corresponding execution-fence bump for its paths --
/// exactly the "DAG holds a change, no fence exists for its touched
/// paths" window `admit_change`'s own promotion path never has.
///
/// This test proves the atomicity at the mechanism level (mirroring
/// `dropping_a_causal_auth_violation_also_drops_its_buffered_
/// descendants`'s own "isolate the transaction-free mechanism" style
/// above it): build the exact scenario `already_satisfied_parents`
/// exists for (a parent landed via bare `append_change`, never through
/// `admit_change`, so its buffered child was never promoted), then
/// force `bump_execution_fence_for_promoted` to fail immediately after
/// `promote_orphans` succeeds, inside the same transaction shape
/// `init_dag_schema` now uses. Confirmed genuinely RED against the
/// pre-fix (unwrapped, sequential) shape: reverting the `tx`/`commit`
/// wrap in `init_dag_schema` and driving the same two calls directly on
/// `recv` leaves the promotion committed despite the fence-bump error.
#[test]
fn startup_self_heal_promotion_and_fence_bump_are_atomic() {
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let child = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    // child arrives first: buffered as an orphan (root unseen yet).
    assert_eq!(admit_change(&recv, &child).unwrap().outcome, AdmitOutcome::Orphaned);
    // root lands via bare `append_change`, not `admit_change` -- exactly
    // the "crash between append_change and promote_orphans" gap
    // `already_satisfied_parents`'s own doc comment describes. Nothing
    // has promoted `child` yet.
    assert!(append_change(&recv, &root, now_unix_nanos()).unwrap());
    assert!(!has_change(&recv, &child.compute_hash()).unwrap());

    let seeds = orphan_integrity::already_satisfied_parents(&recv).unwrap();
    assert_eq!(seeds, vec![root.compute_hash()], "root must be a self-heal seed");

    // Drive the same promotion+fence-bump sequence `init_dag_schema`'s
    // self-heal block uses, inside one transaction -- but corrupt
    // `child`'s own `changes` row between the two steps, forcing
    // `bump_execution_fence_for_promoted`'s `describe_hash` re-read to
    // fail with `CorruptState` instead of finding it `Admitted`.
    let tx = recv.unchecked_transaction().unwrap();
    let promoted = orphan_integrity::promote_orphans(&tx, &seeds).unwrap();
    assert_eq!(promoted, vec![child.compute_hash()]);
    tx.execute("DELETE FROM changes WHERE change_hash = ?1", [&child.compute_hash().0[..]])
        .unwrap();
    let bump_result = bump_execution_fence_for_promoted(&tx, &promoted);
    assert!(bump_result.is_err(), "the corrupted row must make the fence bump fail");
    drop(tx); // never committed -- an uncommitted transaction rolls back on drop, exactly like a crash before `commit()`.

    // GREEN: because promotion and the fence bump shared one
    // transaction, the promotion rolled back along with the failed
    // bump -- `child` is still a buffered orphan, never left durably
    // promoted with a missing fence.
    assert!(
        !has_change(&recv, &child.compute_hash()).unwrap(),
        "a failed fence bump must roll back its own promotion, not leave a promoted-but-unfenced change"
    );
    assert!(
        has_change_or_buffered_orphan(&recv, &child.compute_hash()).unwrap(),
        "the child must still be recoverable as a buffered orphan after the rollback"
    );
}

/// Happy-path companion to the atomicity test above: confirms the
/// transaction wrap did not break ordinary self-heal. `init_dag_schema`
/// is genuinely re-run on the same connection (a restart, not a fresh
/// database), matching production's own re-open-on-every-startup shape.
///
/// Under `AuthorizationCheckpoint` admission a change's authorization is a static,
/// content-addressed fact that never goes stale between original
/// admission and this sweep, so `init_dag_schema`'s self-heal promotes
/// directly, immediately, at startup, with no deferred re-sweep pass.
/// See `init_dag_schema`'s own self-heal comment.
#[test]
fn startup_self_heal_promotes_a_child_whose_parent_landed_via_append_change_alone() {
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let child = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &child).unwrap().outcome, AdmitOutcome::Orphaned);
    assert!(append_change(&recv, &root, now_unix_nanos()).unwrap());
    assert!(!has_change(&recv, &child.compute_hash()).unwrap());

    // Re-running schema init on the SAME connection is what a restart
    // does in production (`SyncDatabase::open`'s `schema_init(&conn)`
    // call, on every open, not just the first).
    init_dag_schema(&recv).unwrap();

    assert!(
        has_change(&recv, &child.compute_hash()).unwrap(),
        "startup self-heal must promote a child whose parent only ever landed via append_change"
    );
    assert_eq!(group_heads(&recv, "g").unwrap(), vec![child.compute_hash()]);
}

/// The primary-admission seam bumps `projection_obligations` for
/// exactly the admitted change's touched
/// paths, no others. Confirmed genuinely RED by temporarily commenting
/// out this seam's own bump call (in `admit_change`'s `(true, Verified)`
/// arm) and re-running: the obligation row for "a" is never created.
#[test]
fn primary_admission_bumps_the_projection_obligation_for_exactly_its_touched_paths() {
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a"), create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &root).unwrap().outcome, AdmitOutcome::Applied);

    let a = crate::projection_obligations::lookup_projection_obligation(&recv, "g", "a")
        .unwrap()
        .unwrap();
    assert_eq!(a.invalidation_generation, 1);
    let b = crate::projection_obligations::lookup_projection_obligation(&recv, "g", "b")
        .unwrap()
        .unwrap();
    assert_eq!(b.invalidation_generation, 1);
    assert!(
        crate::projection_obligations::lookup_projection_obligation(&recv, "g", "unrelated")
            .unwrap()
            .is_none(),
        "an untouched path must have no obligation at all"
    );
}

/// The promoted-orphan seam bumps the obligation for a change that
/// becomes durable only as a side effect of
/// its parent's own admission, not just for the parent itself. Confirmed
/// genuinely RED by temporarily removing the bump call from
/// `bump_execution_fence_for_promoted`'s loop body and re-running: the
/// orphan's own path ("child-path") is admitted but never obligated.
#[test]
fn promoted_orphan_admission_bumps_the_projection_obligation_for_its_own_touched_paths() {
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("root-path")], &em).unwrap();
    let child = emit_local_change(&sender, "g", vec![create_op("child-path")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    // child arrives first: buffered as an orphan, root unseen.
    assert_eq!(admit_change(&recv, &child).unwrap().outcome, AdmitOutcome::Orphaned);
    assert!(
        crate::projection_obligations::lookup_projection_obligation(&recv, "g", "child-path")
            .unwrap()
            .is_none(),
        "a buffered orphan must not bump any obligation until it is actually promoted"
    );
    // root lands via the normal admission path -- promotes child too.
    assert_eq!(admit_change(&recv, &root).unwrap().outcome, AdmitOutcome::Applied);

    let root_ob =
        crate::projection_obligations::lookup_projection_obligation(&recv, "g", "root-path")
            .unwrap()
            .unwrap();
    assert_eq!(root_ob.invalidation_generation, 1);
    let child_ob =
        crate::projection_obligations::lookup_projection_obligation(&recv, "g", "child-path")
            .unwrap()
            .unwrap();
    assert_eq!(
        child_ob.invalidation_generation, 1,
        "the promoted orphan's own touched path must be obligated too, not just the parent's"
    );
}

/// Local emission bumps the obligation for a change this device
/// authored itself, not only for remotely-admitted
/// changes. Confirmed genuinely RED by temporarily removing the bump
/// call from `admit_prepared_emission` and re-running.
#[test]
fn local_emission_bumps_the_projection_obligation_for_its_touched_paths() {
    let conn = conn();
    let em = emitter();
    seed_test_version(&conn, "g");
    let change = emit_local_change(&conn, "g", vec![create_op("local-path")], &em).unwrap();
    assert!(has_change(&conn, &change.compute_hash()).unwrap());

    let ob = crate::projection_obligations::lookup_projection_obligation(&conn, "g", "local-path")
        .unwrap()
        .unwrap();
    assert_eq!(ob.invalidation_generation, 1);
}

/// Startup self-heal bumps the obligation for a child promoted only
/// because `init_dag_schema` re-ran (the parent
/// landed via bare `append_change`, never through `admit_change`).
/// Confirmed genuinely RED by temporarily removing the bump call this
/// seam shares with `bump_execution_fence_for_promoted` and re-running:
/// the child is promoted (proven by the existing happy-path test above)
/// but never obligated.
#[test]
fn startup_self_heal_bumps_the_projection_obligation_for_the_promoted_child() {
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let child = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &child).unwrap().outcome, AdmitOutcome::Orphaned);
    assert!(append_change(&recv, &root, now_unix_nanos()).unwrap());
    assert!(
        crate::projection_obligations::lookup_projection_obligation(&recv, "g", "b")
            .unwrap()
            .is_none(),
        "a buffered orphan must not be obligated before it is actually promoted"
    );

    init_dag_schema(&recv).unwrap();

    let ob = crate::projection_obligations::lookup_projection_obligation(&recv, "g", "b")
        .unwrap()
        .unwrap();
    assert_eq!(ob.invalidation_generation, 1);
}

/// Re-admitting an already-admitted change (the "already known,
/// no-op" path inside `admit_change`) must not bump any generation
/// and must not create a new obligation row -- this is what makes
/// network redelivery a pure no-op on the desired side, independent
/// of anything a later batch handler does to `handle_change_batch`
/// itself.
#[test]
fn redelivering_an_already_admitted_change_bumps_no_obligation() {
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert_eq!(admit_change(&recv, &root).unwrap().outcome, AdmitOutcome::Applied);
    let first = crate::projection_obligations::lookup_projection_obligation(&recv, "g", "a")
        .unwrap()
        .unwrap();
    assert_eq!(first.invalidation_generation, 1);

    // Re-admit the exact same, already-admitted change -- the "already
    // known" path `admit_change` takes for a hash it has already seen.
    // `AdmitResult.newly_admitted` always reports the primary hash when
    // the outcome is `Applied` -- what "a Change receipt is not a
    // projection event" actually requires is that no durable
    // side effect happens a second time, checked below via the
    // obligation's own generation, not via this return value's shape.
    let second = admit_change(&recv, &root).unwrap();
    assert_eq!(
        second.outcome,
        AdmitOutcome::Applied,
        "re-admitting an already-known change is a no-op success, not an error"
    );

    let after = crate::projection_obligations::lookup_projection_obligation(&recv, "g", "a")
        .unwrap()
        .unwrap();
    assert_eq!(
        after.invalidation_generation, 1,
        "redelivering an already-admitted change must not bump its generation"
    );
}

#[test]
fn admit_change_reports_the_current_change_and_promoted_orphans() {
    // The other half of the same guarantee, but through `admit_change`:
    // admitting the root that unblocks a buffered child must report BOTH
    // the root and the promoted child in `newly_admitted`, root first.
    let sender = conn();
    let em = emitter();
    let root = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let child = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    let orphaned = admit_change(&recv, &child).unwrap();
    assert_eq!(orphaned.outcome, AdmitOutcome::Orphaned);
    assert!(orphaned.newly_admitted.is_empty(), "an orphaned change admits nothing yet");

    let applied = admit_change(&recv, &root).unwrap();
    assert_eq!(applied.outcome, AdmitOutcome::Applied);
    assert_eq!(applied.newly_admitted, vec![root.compute_hash(), child.compute_hash()]);
}

/// A change naming a versioned reserved-namespace artefact must be
/// rejected before admission, so a peer can never route an artefact
/// path into another device's index.
#[test]
fn admit_change_rejects_a_versioned_artefact_path() {
    let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
        yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
        "deadbeef",
    )
    .unwrap();
    let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

    let recv = conn();
    seed_test_version(&recv, "g");
    let err = path_refusal(&recv, &change);
    assert!(
        matches!(err, PathRefusal::ReservedNamespaceCollision { path: ref p } if p == &artefact_path),
        "expected ReservedNamespaceCollision naming the artefact path, got {err:?}"
    );
}

/// THE remote-admission hole this pins closed: a peer's signed change
/// naming this device's own sync-root lock file
/// (`yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME`) must be refused
/// at admission -- driven through the real `admit_change` entry point a
/// peer's change actually arrives through, not a bare predicate call.
/// Without this, the change would later materialize and replace the
/// on-disk lock file out from under this device's own live OS lock,
/// letting a second daemon acquire a fresh lock at the same path and
/// believe it owns the root exclusively too.
#[test]
fn admit_change_rejects_a_sync_root_lock_path() {
    let lock_path = yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME.to_string();
    let change = hand_signed_change("g", vec![create_op(&lock_path)]);

    let recv = conn();
    seed_test_version(&recv, "g");
    let err = path_refusal(&recv, &change);
    assert!(
        matches!(err, PathRefusal::ReservedNamespaceCollision { path: ref p } if p == &lock_path),
        "expected ReservedNamespaceCollision naming the sync-root lock path, got {err:?}"
    );
}

/// The fix for a real defect: rejecting a change at admission used to
/// write nothing durable, so the hash was indistinguishable from one
/// this device simply never received — `has_change_or_buffered_orphan`
/// and `missing_ancestor_frontier` would treat it as still-missing
/// forever, and a peer would be asked for the identical, permanently
/// unadmittable change on every future heads announce. A
/// reserved-namespace rejection is a fixed property of the change's own
/// bytes (re-admitting the identical change can never produce a
/// different verdict), so it must be durably recorded and both
/// "is this hash known" functions must recognize it — proven directly
/// here rather than only through `admit_change`'s own return value.
#[test]
fn a_rejected_change_stops_being_reported_missing_and_is_not_re_requested() {
    let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
        yadorilink_root_authority::reserved_namespace::ArtefactKind::Backup,
        "cafef00d",
    )
    .unwrap();
    let change = hand_signed_change("g", vec![create_op(&artefact_path)]);
    let hash = change.compute_hash();

    let recv = conn();
    seed_test_version(&recv, "g");
    assert!(!has_change_or_buffered_orphan(&recv, &hash).unwrap(), "not seen yet");
    let missing_before = missing_ancestor_frontier(&recv, [hash]).unwrap();
    assert_eq!(missing_before, vec![hash], "genuinely unseen, so genuinely missing");

    path_refusal(&recv, &change);

    assert!(
        has_change_or_buffered_orphan(&recv, &hash).unwrap(),
        "a permanently-rejected hash must count as known — nothing about \
         re-requesting it can ever change the outcome"
    );
    let missing_after = missing_ancestor_frontier(&recv, [hash]).unwrap();
    assert!(
        missing_after.is_empty(),
        "a permanently-rejected hash must never be reported as missing again, or a peer \
         re-request loop never terminates: {missing_after:?}"
    );

    let rejected = list_rejected_changes(&recv, "g").unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].0, hash);
    assert!(rejected[0].1.contains(&artefact_path), "reason must name the exact path");
}

/// The converse guardrail, and the fix for a real defect: a change
/// naming a path that merely *contains* the LEGACY `.yadorilink-tmp.`
/// substring must still be admitted normally. Rejecting it here would
/// (a) permanently block a genuine user file that happens to look like
/// the marker (the marker is a substring match precisely because
/// arbitrary user content can precede it — see
/// `materialization::cleanup_stale_temp_files`'s own refusal to delete
/// such a look-alike), and (b) make any already-signed history
/// containing a legacy-marked path (admitted before this namespace
/// excluded it from indexing) permanently unadmittable by an upgraded
/// peer, stalling the whole group. `admit_change` must key its
/// rejection on the artefact-only predicate, not the broader exclusion
/// predicate; this test fails if it is pointed at the latter.
#[test]
fn admit_change_admits_a_legacy_marker_look_alike_path() {
    let sender = conn();
    let em = emitter();
    let legacy_path = "report.yadorilink-tmp.old";
    let change = emit_local_change(&sender, "g", vec![create_op(legacy_path)], &em).unwrap();

    let recv = conn();
    seed_test_version(&recv, "g");
    let result = admit_change(&recv, &change).unwrap();
    assert_eq!(result.outcome, AdmitOutcome::Applied);
}

/// Windows drops trailing `.`/` ` in most Win32 path APIs, so a peer
/// that spells a reserved name with a trailing dot or space types a
/// path that is not literally the reserved name, but would land on
/// disk — on a Windows device — as exactly the reserved name. This
/// check is a wire-facing boundary between arbitrary peers, so it must
/// catch both forms regardless of which platform is running admission.
#[test]
fn admit_change_rejects_a_versioned_artefact_path_with_windows_trailing_normalization() {
    for suffix in [" ", "."] {
        let artefact_path = format!(
            "{}{suffix}",
            yadorilink_root_authority::reserved_namespace::artefact_component_name(
                yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
                "deadbeef",
            )
            .unwrap()
        );
        let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = path_refusal(&recv, &change);
        assert!(
            matches!(err, PathRefusal::ReservedNamespaceCollision { path: ref p } if p == &artefact_path),
            "suffix {suffix:?}: expected ReservedNamespaceCollision, got {err:?}"
        );
    }
}

/// A trailing space makes this path non-portable (Windows silently
/// drops it), independently of whether the path also happens to look
/// like a legacy marker: two distinct wire paths differing only in a
/// trailing '.'/' ' must never both be admitted as independent index
/// rows, since they'd silently collide onto one on-disk name the
/// moment either materializes on a Windows device. See
/// `admit_change_admits_a_legacy_marker_look_alike_path` for the
/// sibling case (same look-alike name, no trailing space) that
/// confirms the legacy-marker substring match alone must not block an
/// ordinary user file, and
/// `reserved_namespace::tests::wire_predicate_still_excludes_the_legacy_marker_with_a_trailing_space`
/// for where the narrower "trailing-space stripping must not widen the
/// artefact predicate" property this test used to pin now lives — it
/// can no longer be exercised through this full admission pipeline,
/// since the non-portability check below refuses the path before the
/// artefact-vs-legacy classification is ever reached.
#[test]
fn admit_change_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker() {
    let legacy_path = "report.yadorilink-tmp.old ";
    let change = hand_signed_change("g", vec![create_op(legacy_path)]);

    let recv = conn();
    seed_test_version(&recv, "g");
    let err = path_refusal(&recv, &change);
    assert!(
        matches!(err, PathRefusal::NonPortablePath { path: ref p } if p == legacy_path),
        "expected NonPortablePath naming the trailing-space path, got {err:?}"
    );
}

/// NTFS `filename::$DATA` addresses `filename`'s own default stream,
/// so a change naming an ADS-suffixed alias for a versioned artefact
/// must be rejected at admission exactly like the un-suffixed name —
/// otherwise a remote peer can get history admitted that later
/// materializes as a write through the artefact's own default stream.
#[test]
fn admit_change_rejects_an_alternate_data_stream_alias_for_a_versioned_artefact() {
    let artefact_path = format!(
        "{}::$DATA",
        yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
            "deadbeef",
        )
        .unwrap()
    );
    let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

    let recv = conn();
    seed_test_version(&recv, "g");
    let err = path_refusal(&recv, &change);
    assert!(
        matches!(err, PathRefusal::ReservedNamespaceCollision { path: ref p } if p == &artefact_path),
        "expected ReservedNamespaceCollision naming the ADS-aliased path, got {err:?}"
    );
}

/// `change::validate_path` accepts both `/` and `\` as separators, so
/// a change naming a backslash-delimited artefact component must be
/// rejected the same on every host running admission — resolving the
/// path through the local `std::path::Path` type instead would make a
/// Unix receiver admit exactly the history a Windows receiver refuses
/// forever, permanently splitting the group along platform lines.
#[test]
fn admit_change_rejects_a_backslash_delimited_artefact_path_on_every_host() {
    let artefact_path = format!(
        "safe\\{}",
        yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
            "cafef00d",
        )
        .unwrap()
    );
    let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

    let recv = conn();
    seed_test_version(&recv, "g");
    let err = path_refusal(&recv, &change);
    assert!(
        matches!(err, PathRefusal::ReservedNamespaceCollision { path: ref p } if p == &artefact_path),
        "expected ReservedNamespaceCollision naming the backslash-delimited path, got {err:?}"
    );
}

/// A literal backslash anywhere in a wire path is refused outright, on
/// every platform — not just converted or reinterpreted on Windows. A
/// Unix-authored path containing a literal backslash byte would
/// otherwise be ambiguous the moment it reaches a Windows receiver,
/// where `\` is the path separator: the same wire string would name two
/// different filesystem shapes depending on which OS materializes it.
/// Refusing it at the source is the only choice that is unambiguous
/// everywhere.
#[test]
fn admit_change_refuses_an_ordinary_backslash_containing_path() {
    let sender = conn();
    let em = emitter();
    let err = emit_local_change(&sender, "g", vec![create_op("safe\\ordinary-file.txt")], &em)
        .unwrap_err();
    assert!(
        matches!(err, SyncSqliteError::InvalidInput(ref msg) if msg.contains("backslash")),
        "expected a backslash-rejection InvalidInput, got {err:?}"
    );
}

/// A literal `:` anywhere in an ordinary (non-artefact) path component
/// is refused the same way as trailing-dot/space: on a POSIX host it's
/// just a character, but on Windows it's the alternate-data-stream
/// separator, so `"notes"` and `"notes:draft"` would alias the same
/// on-disk object there — see
/// `reserved_namespace::path_has_non_portable_wire_component`'s doc
/// comment.
#[test]
fn admit_change_rejects_a_path_with_a_literal_colon() {
    let path = "notes:draft.txt";
    let change = hand_signed_change("g", vec![create_op(path)]);

    let recv = conn();
    seed_test_version(&recv, "g");
    let err = path_refusal(&recv, &change);
    assert!(
        matches!(err, PathRefusal::NonPortablePath { path: ref p } if p == path),
        "expected NonPortablePath naming the colon-containing path, got {err:?}"
    );
}

/// Windows reserves `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` and
/// `LPT1`-`LPT9` (matched against a component's stem, case-
/// insensitively) as device names: a Windows peer can never create a
/// file under one of these names, while the identical path is a
/// perfectly ordinary file on Linux/macOS. Refused at admission for
/// the same host-independence reason as every other check in this
/// module — a change every non-Windows member accepts must not be one
/// a Windows member can never materialize.
#[test]
fn admit_change_rejects_a_reserved_windows_device_name_path() {
    for name in ["CON", "com1", "LPT9.log"] {
        let change = hand_signed_change("g", vec![create_op(name)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = path_refusal(&recv, &change);
        assert!(
            matches!(err, PathRefusal::NonPortablePath { path: ref p } if p == name),
            "{name:?}: expected NonPortablePath, got {err:?}"
        );
    }
}

/// Win32's `CreateFile` family refuses `<`, `>`, `"`, `|`, `?` and `*`
/// in a filename outright, on every Windows version, every time — each
/// is a perfectly ordinary character in a Linux/macOS filename. Same
/// host-independence reasoning as every other check in this module: a
/// change every non-Windows member accepts must not be one a Windows
/// member can never materialize.
#[test]
fn admit_change_rejects_a_path_with_a_win32_reserved_filename_character() {
    for ch in ['<', '>', '"', '|', '?', '*'] {
        let path = format!("notes{ch}draft.txt");
        let change = hand_signed_change("g", vec![create_op(&path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = path_refusal(&recv, &change);
        assert!(
            matches!(err, PathRefusal::NonPortablePath { path: ref p } if p == &path),
            "{ch:?}: expected NonPortablePath, got {err:?}"
        );
    }
}

#[test]
fn delivery_order_does_not_change_final_heads() {
    // Same three-change set delivered in two different orders converges
    // to the same head set (commutativity at the store level).
    let sender = conn();
    let em = emitter();
    let r = emit_local_change(&sender, "g", vec![create_op("a")], &em).unwrap();
    let m = emit_local_change(&sender, "g", vec![create_op("b")], &em).unwrap();
    let t = emit_local_change(&sender, "g", vec![create_op("c")], &em).unwrap();

    let forward = conn();
    seed_test_version(&forward, "g");
    for ch in [&r, &m, &t] {
        admit_change(&forward, ch).unwrap();
    }
    let reverse = conn();
    seed_test_version(&reverse, "g");
    for ch in [&t, &r, &m] {
        admit_change(&reverse, ch).unwrap();
    }
    assert_eq!(group_heads(&forward, "g").unwrap(), group_heads(&reverse, "g").unwrap());
    assert_eq!(group_heads(&forward, "g").unwrap(), vec![t.compute_hash()]);
}

#[test]
fn admission_rejects_malformed_lamport() {
    let c = conn();
    let em = emitter();
    let root = emit_local_change(&c, "g", vec![create_op("a")], &em).unwrap();
    seed_test_version(&c, "g");
    let bad = create_signed_for_tests(
        vec![root.compute_hash()],
        99,
        DeviceId("device-B".into()),
        FolderGroupId("g".into()),
        vec![create_op("b")],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    assert!(admit_change(&c, &bad).is_err());
}

#[test]
fn admission_rejects_file_version_from_another_group() {
    let c = conn();
    put_file_version(&c, "other-group", &test_version()).unwrap();
    let bad = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-B".into()),
        FolderGroupId("g".into()),
        vec![create_op("b")],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    assert!(admit_change(&c, &bad).is_err());
}

#[test]
fn identical_file_version_is_independently_owned_by_each_group() {
    let c = conn();
    let version = test_version();
    assert!(put_file_version(&c, "group-a", &version).unwrap());
    assert!(put_file_version(&c, "group-b", &version).unwrap());
    assert!(has_file_version(&c, "group-a", &version.version_hash).unwrap());
    assert!(has_file_version(&c, "group-b", &version.version_hash).unwrap());
    assert_eq!(get_file_version(&c, "group-b", &version.version_hash).unwrap().unwrap(), version);
}

#[test]
fn device_frontier_replaces_and_removes() {
    let c = conn();
    let h1 = ChangeHash([1u8; 32]);
    let h2 = ChangeHash([2u8; 32]);
    let h3 = ChangeHash([3u8; 32]);

    // A frontier can carry several concurrent heads.
    set_device_frontier(&c, "g", "dev", &[h2, h1]).unwrap();
    assert_eq!(get_device_frontier(&c, "g", "dev").unwrap(), vec![h1, h2]);

    // Setting replaces the whole frontier rather than accumulating.
    set_device_frontier(&c, "g", "dev", &[h3]).unwrap();
    assert_eq!(get_device_frontier(&c, "g", "dev").unwrap(), vec![h3]);

    // Removal clears it entirely.
    remove_device_frontier(&c, "g", "dev").unwrap();
    assert!(get_device_frontier(&c, "g", "dev").unwrap().is_empty());
}

#[test]
fn encoded_bytes_are_served_verbatim() {
    let c = conn();
    let change = emit_local_change(&c, "g", vec![create_op("a")], &emitter()).unwrap();
    let served = get_encoded(&c, &change.compute_hash()).unwrap().unwrap();
    assert_eq!(served, change.to_wire_bytes());
    // A relayed change round-trips to the identical change.
    assert_eq!(Change::from_wire_bytes(&served).unwrap(), change);
}

/// The dual-write path: `upsert_file_emitting_change` must land the index
/// row and the signed change in one commit, with the change becoming the
/// group's sole head.
#[test]
fn dual_write_commits_index_row_and_change_together() {
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_replica_domain::file::FileRecord;

    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.set_local_policy_head_provider(std::sync::Arc::new(|_| Ok([9u8; 32])));
    let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[7u8; 32]));
    let record = FileRecord {
        path: "a.txt".into(),
        size: 3,
        mtime_unix_nanos: 1,
        blocks: vec![],
        deleted: false,
    };
    let hash = state
        .upsert_file_emitting_change(
            "g",
            &record,
            "device-A",
            ChangeContent { ops: vec![create_op("a.txt")], versions: &[] },
            None,
            None,
            yadorilink_daemon::replica_coordinator::ReplicaChangeEmission {
                emitter: &em,
                permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            },
        )
        .unwrap();

    assert!(state.file_index_repository().get_file("g", "a.txt").unwrap().is_some());
    assert!(state.change_history_repository().dag_has_change(&hash).unwrap());
    assert_eq!(state.sqlite().dag_group_heads("g").unwrap(), vec![hash]);
    let decoded = state.sqlite().dag_get_change(&hash).unwrap().unwrap();
    assert_eq!(decoded.compute_hash(), hash);

    // A subsequent tombstone chains from the first change and becomes the
    // new sole head.
    let del = state
        .mark_deleted_emitting_change(
            "g",
            "a.txt",
            "device-A",
            2,
            false,
            &em,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(state.sqlite().dag_group_heads("g").unwrap(), vec![del]);
    assert!(state.change_history_repository().dag_is_ancestor(&hash, &del).unwrap());
    assert!(state.file_index_repository().get_file("g", "a.txt").unwrap().unwrap().deleted);
}

/// Regression test for the defect described on `frontier_index::
/// max_parent_lamport`'s own doc comment: signing must agree with
/// `validate_present_parent_shape`'s pruned-aware Lamport computation
/// even when a resolved basis is composed *entirely* of pruned parents
/// (the shape a delayed capture can resolve against after a checkpoint
/// prunes the frontier it was materialized on). Before the fix,
/// `max_parent_lamport` read only live `changes` rows, signed this
/// change with Lamport 1, and the very next validation step inside this
/// same call then rejected it against `prior`'s real (pruned) Lamport --
/// permanently, since every retry resolves the identical all-pruned
/// basis.
#[test]
fn emission_onto_a_wholly_pruned_basis_agrees_with_the_pruned_aware_validator() {
    let c = conn();
    let em = emitter();

    let prior = emit_local_change(&c, "g", vec![create_op("prior.txt")], &em).unwrap();
    let prior_hash = prior.compute_hash();
    assert_eq!(prior.lamport, 1);

    let child = emit_local_change(&c, "g", vec![create_op("child.txt")], &em).unwrap();
    let child_hash = child.compute_hash();
    assert_eq!(child.lamport, 2);

    // Checkpoint at `child` prunes `prior`: the frontier moves past the
    // point a delayed capture's basis was resolved against.
    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![child_hash],
        [0u8; 32],
    );
    {
        let tx = c.unchecked_transaction().unwrap();
        commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
        tx.commit().unwrap();
    }
    assert!(!has_change(&c, &prior_hash).unwrap());

    let delayed =
        emit_local_change_onto(&c, "g", vec![prior_hash], vec![create_op("delayed.txt")], &em)
            .unwrap();
    // `prior`'s recorded (pruned) Lamport is 1, so the correct, agreed
    // clock is 1 + 1 = 2 -- not the pruned-blind 0 + 1 = 1 that used to
    // be signed and then rejected one line later.
    assert_eq!(delayed.lamport, 2);
    assert_eq!(delayed.parents, vec![prior_hash]);
}

/// The common, already-working shape: a basis with at least one live
/// member alongside a pruned one. Guards against a fix that only checks
/// `pruned_lamport` and stops consulting live `changes` rows.
#[test]
fn emission_onto_a_mixed_live_and_pruned_basis_still_agrees() {
    let c = conn();
    let em = emitter();

    let prior = emit_local_change(&c, "g", vec![create_op("prior.txt")], &em).unwrap();
    let prior_hash = prior.compute_hash();
    assert_eq!(prior.lamport, 1);

    let child = emit_local_change(&c, "g", vec![create_op("child.txt")], &em).unwrap();
    let child_hash = child.compute_hash();
    assert_eq!(child.lamport, 2);

    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![child_hash],
        [0u8; 32],
    );
    {
        let tx = c.unchecked_transaction().unwrap();
        commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
        tx.commit().unwrap();
    }
    assert!(!has_change(&c, &prior_hash).unwrap());
    assert!(has_change(&c, &child_hash).unwrap());

    // Basis names both the now-pruned `prior` and the still-live `child`;
    // the live parent's Lamport (2) dominates, so the expected clock is
    // 2 + 1 = 3.
    let mixed = emit_local_change_onto(
        &c,
        "g",
        vec![prior_hash, child_hash],
        vec![create_op("mixed.txt")],
        &em,
    )
    .unwrap();
    assert_eq!(mixed.lamport, 3);
}

/// An author whose own tip this replica no longer holds goes on writing.
///
/// That is the shape a replaced history leaves behind: the author's latest
/// change is gone from retained history and from pruned ancestry alike,
/// because a base was installed over the history it belonged to. Nothing
/// could walk to it, on this replica or on any peer, for as long as the
/// base stands.
///
/// It does not have to be walked to. The author's next change NAMES it,
/// and a name survives the loss of the thing it names: the emitting side
/// reads the tip out of the author's own retained state and signs it in,
/// and the admitting side compares it against the state the base carried.
/// The sequence still moves forward from the watermark, which is what
/// stops a used position being re-minted.
#[test]
fn a_local_emission_continues_an_author_whose_tip_the_base_replaced() {
    const GROUP: &str = "emit-vanished-tip";
    let conn = conn();
    seed_test_version(&conn, GROUP);
    let emitter = ChangeEmitter::new("device-a", key());
    let put = |path: &str| Op::Put {
        path: SyncPath(path.to_string()),
        version: test_version().version_hash,
        origin: PutOrigin::Direct,
    };

    let first = emit_local_change(&conn, GROUP, vec![put("first.txt")], &emitter)
        .expect("the author's first change follows nothing and must be emitted");
    assert_eq!(first.author_prev, None, "a first change names nothing before it");

    // The author's recorded tip is a change this replica no longer holds
    // anywhere -- not in `changes`, not in its pruned ancestry.
    let vanished = ChangeHash([0x5Au8; 32]);
    author_chain::advance_author_state(
        &conn,
        GROUP,
        "device-a",
        yadorilink_replica_domain::ids::AuthorSeq(9),
        &vanished,
    )
    .unwrap();

    let second = emit_local_change(&conn, GROUP, vec![put("second.txt")], &emitter)
        .expect("an author whose tip the base replaced continues from its watermark");
    assert_eq!(
        second.author_seq,
        yadorilink_replica_domain::ids::AuthorSeq(10),
        "the position moves on from the watermark, never back to a used one"
    );
    assert_eq!(
        second.author_prev,
        Some(vanished),
        "the change names the tip the author's state carries, whether or not it is retained"
    );
    assert_eq!(
        second.parents,
        vec![first.compute_hash()],
        "the change is built on what this replica actually holds"
    );
    assert_eq!(group_heads(&conn, GROUP).unwrap(), vec![second.compute_hash()]);
}

/// A local edit authored onto an older basis is an ordinary emission, with
/// no exemption and no warning.
///
/// It is the shape every debounced local edit has: the parents are the
/// causal basis of the bytes the user actually edited, which this author
/// may have written past on some other path. There is nothing to exempt,
/// because the author chain asks the change to NAME its author's previous
/// change, and a change authored onto any basis at all can do that. The
/// emission therefore signs the author's real tip while parenting the
/// change where its bytes came from — the two links pointing at different
/// places is the normal case, not a special one.
#[test]
fn a_local_edit_onto_an_older_basis_names_its_authors_tip_without_parenting_on_it() {
    const GROUP: &str = "emit-older-basis";
    let conn = conn();
    seed_test_version(&conn, GROUP);
    let emitter = ChangeEmitter::new("device-a", key());
    let put = |path: &str| Op::Put {
        path: SyncPath(path.to_string()),
        version: test_version().version_hash,
        origin: PutOrigin::Direct,
    };

    let first = emit_local_change(&conn, GROUP, vec![put("doc.txt")], &emitter).unwrap();
    let second = emit_local_change(&conn, GROUP, vec![put("other.txt")], &emitter).unwrap();

    // The edit to `doc.txt`, whose bytes still come from `first`.
    let edit = emit_local_change_onto(
        &conn,
        GROUP,
        vec![first.compute_hash()],
        vec![put("doc.txt")],
        &emitter,
    )
    .expect("an edit onto the basis its bytes came from is an ordinary emission");

    assert_eq!(
        edit.parents,
        vec![first.compute_hash()],
        "the causal basis stays what the user actually edited"
    );
    assert_eq!(
        edit.author_prev,
        Some(second.compute_hash()),
        "and the author link names this author's real tip, which is not among those parents"
    );
    assert!(
        !edit.parents.contains(&second.compute_hash()),
        "naming the tip must not drag it in as a parent: that would be the lost update"
    );
}

/// "Below `a`" is the namespace relation. `a-b`, `a.txt` and `a0` sort
/// between `a` and `a/x` or right after its range and share its first
/// byte, and none of them is inside `a`; a removed descendant is not live.
#[test]
fn live_descendant_query_excludes_a_dash_b_and_a0() {
    let c = conn();
    let em = emitter();
    for path in ["a", "a-b", "a-b/x", "a.txt", "a0", "a0/x", "ab/y", "a/x", "a/y/z", "a/w"] {
        emit_local_change(&c, "g", vec![create_op(path)], &em).unwrap();
    }
    emit_local_change(&c, "g", vec![Op::Delete { path: SyncPath("a/x".into()) }], &em).unwrap();
    // Another group's tree is not this group's.
    emit_local_change(&c, "other", vec![create_op("a/q")], &em).unwrap();

    assert_eq!(
        path_frontier::live_descendant_paths(&c, "g", "a", 10).unwrap(),
        vec!["a/w".to_string(), "a/y/z".to_string()]
    );
    assert_eq!(path_frontier::live_descendant_paths(&c, "g", "a", 1).unwrap(), vec!["a/w"]);
    assert!(path_frontier::has_live_descendant(&c, "g", "a").unwrap());
    assert!(path_frontier::has_live_descendant(&c, "g", "a/y").unwrap());
    assert!(!path_frontier::has_live_descendant(&c, "g", "a/w").unwrap());
    assert!(!path_frontier::has_live_descendant(&c, "g", "a/x").unwrap());
    assert!(!path_frontier::has_live_descendant(&c, "g", "a.txt").unwrap());
    assert_eq!(path_frontier::live_descendant_paths(&c, "g", "a-b", 10).unwrap(), vec!["a-b/x"]);
    assert!(matches!(
        path_frontier::live_descendant_paths(&c, "g", "", 10),
        Err(SyncSqliteError::InvalidInput(_))
    ));
}

/// Two concurrent live heads of one descendant are one descendant.
#[test]
fn live_descendant_query_lists_a_contested_path_once() {
    let c = conn();
    seed_test_version(&c, "g");
    emit_local_change(&c, "g", vec![create_op("a/x")], &emitter()).unwrap();
    let peer = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-B".into()),
        FolderGroupId("g".into()),
        vec![create_op("a/x")],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    assert_eq!(admit_change(&c, &peer).unwrap().outcome, AdmitOutcome::Applied);
    assert_eq!(live_path_heads(&c, "g", "a/x").unwrap().len(), 2);
    assert_eq!(path_frontier::live_descendant_paths(&c, "g", "a", 10).unwrap(), vec!["a/x"]);
}
