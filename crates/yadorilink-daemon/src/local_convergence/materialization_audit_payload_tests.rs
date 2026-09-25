#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use super::types::{AuditCandidate, MaterializationPayload};
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_root_authority::root_commit::RootCommitPermit;

/// Every column one incarnation of the row covers -- the same set the
/// fake's own `RowIncarnation` covered, kept together here for the same
/// reason: seeding and superseding must move exactly the same columns,
/// or the test would be comparing against a shape no writer produces.
#[derive(Clone)]
struct RowIncarnation {
    record: Option<FileRecord>,
    record_kind: Option<RecordKind>,
    symlink_target: Option<Vec<u8>>,
    symlink_out_of_root: bool,
    unix_mode: Option<u32>,
    xattrs: Vec<(String, Vec<u8>)>,
    origin_device_id: Option<String>,
    authoring_change_hash: Option<ChangeHash>,
}

/// Moves the row to `next` wholesale, through the repositories that own
/// each column.
fn install_incarnation(
    state: &ReplicaCoordinator,
    group_id: &str,
    path: &str,
    next: &RowIncarnation,
) {
    let permit = RootCommitPermit::for_tests();
    let files = state.file_index_repository();
    if let Some(record) = &next.record {
        files
            .upsert_file_with_origin(
                group_id,
                record,
                next.origin_device_id.as_deref().unwrap_or("device-seed"),
                &permit,
            )
            .unwrap();
    }
    if let Some(kind) = next.record_kind {
        files.set_record_kind(group_id, path, kind, &permit).unwrap();
    }
    files.set_symlink_target(group_id, path, next.symlink_target.as_deref()).unwrap();
    files.set_symlink_out_of_root(group_id, path, next.symlink_out_of_root).unwrap();
    files.set_unix_mode(group_id, path, next.unix_mode, &permit).unwrap();
    files.set_xattrs(group_id, path, &next.xattrs, &permit).unwrap();
    if let Some(authoring) = &next.authoring_change_hash {
        files.set_authoring_change_hash(group_id, path, authoring).unwrap();
    }
}

fn incarnation(
    mtime: i64,
    hash_byte: u8,
    unix_mode: u32,
    xattr_value: &[u8],
    origin: &str,
    authoring: u8,
) -> RowIncarnation {
    RowIncarnation {
        record: Some(FileRecord {
            path: "contended.sh".to_string(),
            size: 5,
            mtime_unix_nanos: mtime,
            blocks: vec![BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 5 }],
            deleted: false,
        }),
        record_kind: Some(RecordKind::File),
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: Some(unix_mode),
        xattrs: vec![("user.tag".to_string(), xattr_value.to_vec())],
        origin_device_id: Some(origin.to_string()),
        authoring_change_hash: Some(ChangeHash([authoring; 32])),
    }
}

fn version_of(row: &RowIncarnation) -> FileVersion {
    let record = row.record.clone().unwrap();
    FileVersion::from_index_row(
        record.blocks,
        record.size,
        record.mtime_unix_nanos,
        row.record_kind.unwrap(),
        row.unix_mode,
        row.symlink_target.clone(),
        row.xattrs.clone(),
    )
}

fn describes(
    row: &RowIncarnation,
    record: &FileRecord,
    meta: &super::types::IncomingWireMeta,
) -> bool {
    row.record.as_ref() == Some(record)
        && row.record_kind == Some(meta.record_kind)
        && row.symlink_target == meta.symlink_target
        && row.unix_mode == meta.unix_mode
        && row.xattrs == meta.xattrs
        && row.origin_device_id == meta.origin_device_id
        && row.authoring_change_hash == meta.authoring_change_hash
}

/// A supersession landing in the MIDDLE of the audit's read cannot
/// make the audit's payload a value no row ever held.
///
/// This is the producer-side half of
/// `a_supersession_during_the_write_cannot_rename_what_is_written`.
/// That test rules out the row moving while a lane is between its
/// payload and its proof. This one rules out the row moving while
/// the payload is still being *assembled* — which the payload type
/// alone cannot prevent, because a coherent type built from a torn
/// read is still torn. It just cannot be told apart afterwards.
///
/// `TestObservers::armed_supersession` fires from the real
/// coordinator's `current_row_snapshot` once the row has been
/// captured, so the move lands inside the read window. The hook is
/// compiled under `#[cfg(test)]` only. It fires for a coherent producer too — it just lands
/// after that producer's single read instead of between two of them,
/// which is exactly the difference being asserted.
///
/// It goes through the executor rather than the conversion itself,
/// because the conversion no longer reads: it takes one
/// `CurrentRowSnapshot`, so it could not tear if it tried. What is
/// still worth holding down is the read site — this method is where
/// every audit payload this device produces gets its row, and a
/// future edit that assembled the payload from a second read would
/// reintroduce exactly the bug below without touching the conversion
/// at all.
///
/// The supersession here changes content, metadata and authoring
/// identity together, because that is the only shape that can
/// actually tear. A same-authoring, metadata-only supersession —
/// the shape the write-window test uses — cannot: with the content
/// columns equal between the two incarnations, "V1's record plus
/// V2's metadata" *is* V2, exactly, and there is nothing to detect.
/// Content moving under an unchanged authoring identity is not a
/// state this system admits either (`apply_locked_record` treats it
/// as `CorruptState`). What remains, and what a DAG applier or a
/// local capture produces all the time while an audit pass is
/// running, is an ordinary supersession that moves everything.
///
/// Before this producer read the row once, it read it eight times:
/// `get_files_by_paths` for the content, then `get_record_kind`,
/// `get_symlink_target`, `get_symlink_out_of_root`, `get_unix_mode`,
/// `get_xattrs`, `get_origin_device_id` and
/// `get_authoring_change_hash`. With the move landing after the
/// first of those, the payload held V1's blocks, size and mtime
/// beside V2's mode, xattrs and authoring hash — so
/// `MaterializationPayload::from_wire` derived a `version_hash` over
/// a combination of columns that had never been in the index
/// together, and the pair claimed V2's change had authored V1's
/// content.
#[test]
fn an_audit_payload_cannot_tear_across_a_supersession() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = tempfile::tempdir().unwrap();
    state.link_repository().add_link(&root.path().to_string_lossy(), "group-1").unwrap();

    let v1 = incarnation(111, 0xA1, 0o644, b"one", "device-a", 1);
    let v2 = incarnation(222, 0xB2, 0o755, b"two", "device-b", 2);
    install_incarnation(&state, "group-1", "contended.sh", &v1);
    // Fires from inside the current-row read, so a producer that reads
    // once gets the move after its read and one that reads twice gets it
    // between them -- the same semantic boundary the fake fired on.
    {
        let superseding_state = state.clone();
        let v2_for_hook = v2.clone();
        *state
            .test_observers
            .armed_supersession
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(crate::replica_coordinator::test_observers::ArmedSupersession {
                group_id: "group-1".to_string(),
                path: "contended.sh".to_string(),
                apply: Box::new(move || {
                    install_incarnation(&superseding_state, "group-1", "contended.sh", &v2_for_hook)
                }),
            });
    }

    let deps = yadorilink_peer_session::peer_session::PeerSyncSessionDeps::test_permissive();
    let store_dir = tempfile::tempdir().unwrap();
    let executor = super::LocalConvergenceExecutor::new(
        state.clone(),
        "device-local".to_string(),
        deps.root_commit_authority_provider.clone(),
        deps.pending_local_change_flush.clone(),
        HashMap::new(),
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap()),
        deps.block_write_activity_provider.clone(),
        super::HeadroomPolicy::disabled(),
    );

    let (record, meta) =
        match executor.materialization_audit_candidate("group-1", "contended.sh").unwrap() {
            AuditCandidate::Payload(record, meta) => (record, meta),
            other => {
                panic!("a seeded, non-deleted, authored row must produce a payload: {other:?}")
            }
        };

    assert_eq!(
        state
            .file_index_repository()
            .get_file("group-1", "contended.sh")
            .unwrap()
            .unwrap()
            .mtime_unix_nanos,
        222,
        "fixture check: the supersession must really have landed during the read, or this \
         test proves nothing"
    );

    assert!(
        describes(&v1, &record, &meta) || describes(&v2, &record, &meta),
        "the payload must be ONE incarnation of the row. Got blocks/mtime from one and \
         metadata from the other: record={record:?} meta={meta:?}"
    );

    let payload_version = MaterializationPayload::from_wire(record, &meta);
    let v1_hash = version_of(&v1).version_hash;
    let v2_hash = version_of(&v2).version_hash;
    assert!(
        payload_version.version().version_hash == v1_hash
            || payload_version.version().version_hash == v2_hash,
        "the version this payload's proof would name must be a version some incarnation of \
         the row actually had. A stitched payload derives a hash over a column combination \
         that was never in the index at all, and no downstream guard can catch that, because \
         every guard compares against the row rather than against what was written"
    );
}
