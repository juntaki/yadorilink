//! What admitting a returning device's edits is allowed to read.
//!
//! A device that worked offline on files that already existed comes back
//! with a branch forked from shared history. Admitting each of its changes
//! has to decide whether the edit supersedes the path's current head, and
//! that head was written in shared history, before the fork. Deciding it by
//! walking back from the edit until the old head turns up costs a walk
//! through shared history on every admission; the admission path instead
//! settles it from what it recorded when that history was admitted.
//!
//! A timing test cannot tell those two apart when the walk happens to be a
//! constant length, so this one removes what the walk would need. Every
//! parent edge and every encoded body in shared history is destroyed before
//! the branch arrives. An admission that walked or decoded shared history
//! could not then find the old head, would leave it live beside the edit
//! that superseded it, and the path would resolve to two heads instead of
//! one.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sync_sqlite::dag_store::{
    admit_change, group_heads, init_conflict_copy_provenance_schema, init_dag_schema,
    live_path_heads, put_file_version, AdmitOutcome,
};

const GROUP: &str = "group-catch-up";
const FILES: usize = 200;
const MAINLINE_AFTER_FORK: usize = 50;

fn version() -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 1_000,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

#[test]
fn catching_up_edits_to_existing_files_reads_no_shared_history() {
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    init_conflict_copy_provenance_schema(&conn).unwrap();
    let v = version();
    put_file_version(&conn, GROUP, &v).unwrap();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let sign = |parents: Vec<ChangeHash>, parent_lamport: u64, device: &str, path: String| {
        create_signed_for_tests(
            parents,
            parent_lamport,
            DeviceId(device.to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath(path),
                version: v.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key,
        )
    };

    // Shared history: every file exists before the fork, and this device
    // keeps working on unrelated files after it.
    let mut parents: Vec<ChangeHash> = Vec::new();
    let mut parent_lamport = 0u64;
    let mut fork = None;
    for i in 0..FILES + MAINLINE_AFTER_FORK {
        let path = if i < FILES { format!("p{i:07}.bin") } else { format!("mainline{i:07}.bin") };
        let change = sign(parents.clone(), parent_lamport, "device-a", path);
        admit_change(&conn, &change).unwrap();
        parent_lamport = change.lamport;
        parents = vec![change.compute_hash()];
        if i == FILES - 1 {
            fork = Some((change.compute_hash(), change.lamport));
        }
    }
    let mainline_tip = parents[0];
    let (fork_hash, fork_lamport) = fork.unwrap();

    // The returning device edited every pre-existing file once.
    let mut branch: Vec<Change> = Vec::with_capacity(FILES);
    let mut b_parents = vec![fork_hash];
    let mut b_lamport = fork_lamport;
    for i in 0..FILES {
        let change = sign(b_parents.clone(), b_lamport, "device-b", format!("p{i:07}.bin"));
        b_lamport = change.lamport;
        b_parents = vec![change.compute_hash()];
        branch.push(change);
    }

    let removed_edges = conn.execute("DELETE FROM change_parents", []).unwrap();
    assert_eq!(
        removed_edges,
        FILES + MAINLINE_AFTER_FORK - 1,
        "sanity: every shared-history edge must be gone before the branch arrives"
    );
    let replaced =
        conn.execute("UPDATE changes SET encoded = x'00' WHERE group_id = ?1", [GROUP]).unwrap();
    assert_eq!(
        replaced,
        FILES + MAINLINE_AFTER_FORK,
        "sanity: every shared-history body must be unreadable before the branch arrives"
    );

    for change in &branch {
        let result = admit_change(&conn, change).unwrap();
        assert!(
            matches!(result.outcome, AdmitOutcome::Applied),
            "the returning edit must be admitted, got {:?}",
            result.outcome
        );
    }

    for (i, edit) in branch.iter().enumerate() {
        let path = format!("p{i:07}.bin");
        let live = live_path_heads(&conn, GROUP, &path).unwrap();
        assert_eq!(
            live.iter().map(|head| head.change_hash).collect::<Vec<_>>(),
            vec![edit.compute_hash().0],
            "{path} must resolve to the offline edit alone: its shared-history head is an \
             ancestor of that edit, and admission has to know so without walking or \
             decoding shared history"
        );
    }
    let mut heads = group_heads(&conn, GROUP).unwrap();
    heads.sort();
    let mut expected = vec![mainline_tip, branch[FILES - 1].compute_hash()];
    expected.sort();
    assert_eq!(heads, expected, "the group must end with the two branch tips as its heads");
}
