#![cfg(test)]

use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

use super::*;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::{DeviceId, SyncPath};

#[test]
fn v2_snapshot_round_trips_without_version_vector_payload() {
    let group = FolderGroupId("g".into());
    let version = FileVersion::new(
        vec![VersionBlock {
            hash: yadorilink_replica_domain::ids::BlockHash(vec![7; 32]),
            size: 3,
        }],
        3,
        FileMeta {
            mtime_unix_nanos: 11,
            record_kind: RecordKind::File,
            symlink_target: None,
            unix_mode: None,
            xattrs: Vec::new(),
        },
    );
    let change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("d".into()),
        group.clone(),
        vec![Op::Put {
            path: SyncPath("a".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &SigningKey::from_bytes(&[3; 32]),
    );
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        vec![SnapshotFile {
            record: FileRecord {
                path: "a".into(),
                size: 3,
                mtime_unix_nanos: 11,
                blocks: vec![BlockInfo { hash: vec![7; 32], offset: 0, size: 3 }],
                deleted: false,
            },
            version_seq: 0,
            state: SnapshotVersionState::Current,
            origin_device_id: Some("d".into()),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            xattrs: Vec::new(),
            authoring_change_hash: None,
        }],
        vec![change.to_wire_bytes()],
        vec![version.canonical_encoding()],
        vec![],
        vec![],
        vec![SnapshotAuthorState {
            device_id: "d".into(),
            watermark: change.author_seq,
            tip_change_hash: change.compute_hash(),
        }],
        vec![SnapshotPathHead {
            path: "a".into(),
            change_hash: change.compute_hash(),
            device_id: "d".into(),
            author_seq: change.author_seq,
            lamport: change.lamport,
            version_hash: version.version_hash,
            naming_device_id: "d".into(),
        }],
        change.lamport,
    )
    .unwrap();
    let encoded = snapshot.canonical_encoding();
    let decoded = RebootstrapSnapshot::decode(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.snapshot_hash(), snapshot.snapshot_hash());
    let checkpoint = Checkpoint::new(group, vec![change.compute_hash()], snapshot.snapshot_hash());
    decoded.validate_against_checkpoint(&checkpoint).unwrap();
}

/// Retained history is per *version*, not per path: a compacted snapshot
/// must be able to carry a superseded row and the current row for the same
/// path. This is independent of the removed version-vector section — it
/// pins the `(path, version_seq)` shape the store reads back.
#[test]
fn snapshot_can_retain_multiple_versions_for_one_path() {
    let group = FolderGroupId("g".into());
    let record = |mtime| FileRecord {
        path: "a".into(),
        size: 0,
        mtime_unix_nanos: mtime,
        blocks: vec![],
        deleted: false,
    };
    let snapshot = RebootstrapSnapshot::new(
        group,
        vec![
            SnapshotFile {
                record: record(1),
                version_seq: 1,
                state: SnapshotVersionState::Superseded,
                origin_device_id: None,
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                unix_mode: None,
                xattrs: Vec::new(),
                authoring_change_hash: None,
            },
            SnapshotFile {
                record: record(2),
                version_seq: 2,
                state: SnapshotVersionState::Current,
                origin_device_id: None,
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                unix_mode: None,
                xattrs: Vec::new(),
                authoring_change_hash: None,
            },
        ],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        0,
    )
    .unwrap();
    assert_eq!(snapshot.files.len(), 2);
}

/// Two devices that wrote the same bytes concurrently wrote twice. A
/// summary that folded them into one entry would have no way to say that
/// the second survives a delete descending only from the first, and the
/// content would be gone with no trace it existed. Identity is the change
/// that wrote the head, never the content it landed.
#[test]
fn two_heads_of_one_path_landing_the_same_version_are_two_heads() {
    use yadorilink_replica_domain::ids::{AuthorSeq, VersionHash};

    let shared = VersionHash([5; 32]);
    let head = |device: &str, change: u8| SnapshotPathHead {
        path: "a".into(),
        change_hash: ChangeHash([change; 32]),
        device_id: device.into(),
        author_seq: AuthorSeq(1),
        lamport: 1,
        version_hash: shared,
        naming_device_id: device.into(),
    };
    let author = |device: &str, change: u8| SnapshotAuthorState {
        device_id: device.into(),
        watermark: AuthorSeq(1),
        tip_change_hash: ChangeHash([change; 32]),
    };
    let snapshot = RebootstrapSnapshot::new(
        FolderGroupId("g".into()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![author("d1", 1), author("d2", 2)],
        vec![head("d1", 1), head("d2", 2)],
        1,
    )
    .unwrap();
    assert_eq!(snapshot.path_heads.len(), 2, "same content, two writes, two heads");
    let decoded = RebootstrapSnapshot::decode(&snapshot.canonical_encoding()).unwrap();
    assert_eq!(decoded, snapshot, "and the pair survives a round trip intact");
}

/// One author's two writes to one path are ordered by that author's own
/// chain, so the earlier one cannot be maximal beside the later one. Two
/// heads of one path from one author is therefore not a summary of any
/// history, and is refused rather than carried.
#[test]
fn two_heads_of_one_path_by_one_author_are_refused_as_corrupt() {
    use yadorilink_replica_domain::ids::{AuthorSeq, VersionHash};

    let head = |change: u8, version: u8, seq: u64| SnapshotPathHead {
        path: "a".into(),
        change_hash: ChangeHash([change; 32]),
        device_id: "d1".into(),
        author_seq: AuthorSeq(seq),
        lamport: seq,
        version_hash: VersionHash([version; 32]),
        naming_device_id: "d1".into(),
    };
    let error = RebootstrapSnapshot::new(
        FolderGroupId("g".into()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: "d1".into(),
            watermark: AuthorSeq(2),
            tip_change_hash: ChangeHash([2; 32]),
        }],
        vec![head(1, 1, 1), head(2, 2, 2)],
        2,
    )
    .unwrap_err();
    assert!(
        format!("{error}").contains("two heads"),
        "unexpected error for one author holding two heads of one path: {error}"
    );
}

/// A head standing above its own author's watermark describes a history
/// the summary also says never happened. Refused, because there is no
/// reading of it that is both true.
#[test]
fn a_head_above_its_authors_watermark_is_refused() {
    use yadorilink_replica_domain::ids::{AuthorSeq, VersionHash};

    let error = RebootstrapSnapshot::new(
        FolderGroupId("g".into()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: "d1".into(),
            watermark: AuthorSeq(1),
            tip_change_hash: ChangeHash([1; 32]),
        }],
        vec![SnapshotPathHead {
            path: "a".into(),
            change_hash: ChangeHash([9; 32]),
            device_id: "d1".into(),
            author_seq: AuthorSeq(4),
            lamport: 4,
            version_hash: VersionHash([1; 32]),
            naming_device_id: "d1".into(),
        }],
        4,
    )
    .unwrap_err();
    assert!(
        format!("{error}").contains("above that author's own watermark"),
        "unexpected error: {error}"
    );
}

/// A frontier change whose author the summary has no position for is the
/// exact state the summary exists to prevent: the receiver would install
/// that change and still have nothing attested to measure that device's
/// next change against.
#[test]
fn a_frontier_change_whose_author_has_no_position_is_refused() {
    let group = FolderGroupId("g".into());
    let change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("d".into()),
        group.clone(),
        vec![Op::Delete { path: SyncPath("a".into()) }],
        &SigningKey::from_bytes(&[3; 32]),
    );
    let error = RebootstrapSnapshot::new(
        group,
        Vec::new(),
        vec![change.to_wire_bytes()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        change.lamport,
    )
    .unwrap_err();
    assert!(
        format!("{error}").contains("no position for that author"),
        "unexpected error: {error}"
    );
}

/// A Lamport value a replica cannot store is refused where the snapshot is
/// built or decoded, not written and then read back as damage by every
/// admission on the installed epoch.
#[test]
fn a_lamport_value_beyond_the_storable_range_is_refused() {
    use yadorilink_replica_domain::ids::AuthorSeq;

    let author = || {
        vec![SnapshotAuthorState {
            device_id: "d1".into(),
            watermark: AuthorSeq(1),
            tip_change_hash: ChangeHash([1; 32]),
        }]
    };
    let unstorable = i64::MAX as u64 + 1;
    for (boundary, ceiling, what) in [
        (Vec::new(), unstorable, "a Lamport ceiling"),
        (
            vec![BoundaryParentAuth {
                child_hash: ChangeHash([2; 32]),
                parent_hash: ChangeHash([3; 32]),
                parent_lamport: unstorable,
            }],
            0,
            "a boundary parent's Lamport value",
        ),
    ] {
        let error = RebootstrapSnapshot::new(
            FolderGroupId("g".into()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            boundary,
            author(),
            Vec::new(),
            ceiling,
        )
        .expect_err(what);
        assert!(
            format!("{error}").contains("storable"),
            "{what} beyond the storable range, unexpected error: {error}"
        );
    }
}

/// A merged base is minted over the identity of the joined summary, not
/// over the snapshot bytes. A snapshot whose hash its merged checkpoint
/// commits to but whose summary is not the one the base was minted over
/// would install a base under a name that describes another history, and
/// is refused.
#[test]
fn a_merged_checkpoint_binds_the_summary_its_snapshot_carries() {
    use yadorilink_replica_domain::base_negotiation::SummaryIdentity;
    use yadorilink_replica_domain::ids::AuthorSeq;
    use yadorilink_replica_domain::rebootstrap::{HistoryBase, MergedFrom};

    let snapshot = RebootstrapSnapshot::new(
        FolderGroupId("g".into()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: "d1".into(),
            watermark: AuthorSeq(1),
            tip_change_hash: ChangeHash([1; 32]),
        }],
        Vec::new(),
        1,
    )
    .unwrap();
    let merged = |summary: SummaryIdentity| {
        Checkpoint::new_merged(
            FolderGroupId("g".into()),
            Vec::new(),
            snapshot.snapshot_hash(),
            MergedFrom::new(HistoryBase([1; 32]), HistoryBase([2; 32]), summary).unwrap(),
        )
    };

    snapshot.validate_against_checkpoint(&merged(snapshot.summary_identity())).unwrap();
    let error =
        snapshot.validate_against_checkpoint(&merged(SummaryIdentity([0; 32]))).unwrap_err();
    assert!(format!("{error}").contains("summary"), "unexpected error: {error}");
}
