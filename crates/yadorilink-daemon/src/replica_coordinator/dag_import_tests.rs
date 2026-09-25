#![cfg(test)]

use super::*;
use crate::dag_import::{ensure_initial_import, ImportOutcome};

/// End-to-end proof that `ensure_initial_import` converts a real index
/// into signed history when called through a `ReplicaCoordinator` --
/// not merely that the trait bound type-checks.
#[test]
fn ensure_initial_import_runs_against_a_replica_coordinator() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    let record = FileRecord {
        path: "a.txt".into(),
        size: 3,
        mtime_unix_nanos: 1,
        blocks: vec![yadorilink_replica_domain::file::BlockInfo {
            hash: vec![1, 2, 3],
            offset: 0,
            size: 3,
        }],
        deleted: false,
    };
    coordinator
        .file_index_repository()
        .upsert_file("g", &record, &RootCommitPermit::for_tests())
        .unwrap();

    let emitter = ChangeEmitter::new("device-A", ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
    let outcome = ensure_initial_import(&coordinator, "g", &emitter, None).unwrap();
    assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 1 });

    let heads = coordinator.sqlite().dag_group_heads("g").unwrap();
    assert_eq!(heads.len(), 1);
}

/// Race B (the first-change race): something OTHER than
/// `ensure_initial_import` -- here, `append_history_backfill` claiming
/// exactly one path, exactly the shape `backfill_missing_history`'s own
/// per-path loop produces if it is interrupted after its first
/// iteration -- gives the group a head before `ensure_initial_import`
/// ever runs. An "any head at all means already imported" pre-check
/// would bail immediately, leaving `b.txt` permanently unbound: a group can be
/// DAG-backed (`b_dag_heads` nonempty) while `b.txt` -- a current,
/// version_seq > 0 row -- never gets a verified authoring identity.
/// `ensure_initial_import` must converge regardless of which unrelated path
/// got there first.
#[test]
fn ensure_initial_import_converges_even_after_backfill_claims_one_path_first() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();
    for path in ["a.txt", "b.txt"] {
        coordinator
            .file_index_repository()
            .upsert_file(
                "g",
                &FileRecord {
                    path: path.into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
    }
    assert_eq!(
        coordinator.file_index_repository().list_unauthored_current_paths("g").unwrap().len(),
        2,
        "sanity: both rows start unbound, DAG still empty"
    );

    let emitter = ChangeEmitter::new("device-A", ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));

    // `backfill_missing_history`'s own per-path loop, run for exactly
    // ONE path -- simulating it having claimed only this much before an
    // interruption (a restart, a scheduler yield, the group's startup
    // finishing and un-gating it mid-sweep).
    let version = FileVersion::new(
        Vec::new(),
        0,
        yadorilink_replica_domain::file::FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: yadorilink_replica_domain::file::RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let op = Op::Put {
        path: yadorilink_replica_domain::ids::SyncPath("a.txt".into()),
        version: version.version_hash,
        origin: yadorilink_replica_domain::change::PutOrigin::Direct,
    };
    coordinator
        .append_history_backfill("g", vec![op], std::slice::from_ref(&version), &emitter)
        .unwrap();

    // The group now has a head, from `a.txt` alone -- and `b.txt` is
    // still unbound.
    assert!(!coordinator.sqlite().dag_group_heads("g").unwrap().is_empty());
    assert_eq!(
        coordinator.file_index_repository().list_unauthored_current_paths("g").unwrap(),
        std::collections::HashSet::from(["b.txt".to_string()]),
    );

    // The actual fix under test: `ensure_initial_import` must not treat
    // "the group already has a head" as "fully imported" -- it must
    // still notice and bind `b.txt`.
    let outcome = ensure_initial_import(&coordinator, "g", &emitter, None).unwrap();
    assert_eq!(
        outcome,
        ImportOutcome::Imported { changes: 1, ops: 1 },
        "must import the one remaining unbound row, chained onto the head backfill created"
    );
    assert!(
        coordinator.file_index_repository().list_unauthored_current_paths("g").unwrap().is_empty(),
        "every current row for this group must be bound once ensure_initial_import returns"
    );
}
