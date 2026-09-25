#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::EntryKind;

#[test]
fn materialization_state_label_covers_every_state() {
    assert_eq!(materialization_state_label(MaterializationState::Hydrated), "hydrated");
    assert_eq!(materialization_state_label(MaterializationState::Placeholder), "placeholder");
    assert_eq!(materialization_state_label(MaterializationState::Hydrating), "hydrating");
    assert_eq!(materialization_state_label(MaterializationState::Evicting), "evicting");
    assert_eq!(materialization_state_label(MaterializationState::Unspecified), "unknown");
}

#[test]
fn version_line_renders_every_field() {
    let v = FileVersionInfo {
        version_seq: 3,
        size: 42,
        mtime_unix_nanos: 12345,
        state: "superseded".into(),
        origin_device_id: "device-a".into(),
        unix_mode: Some(0o755),
        kind: EntryKind::File as i32,
    };
    assert_eq!(
        version_line(&v),
        "v3  12345  size=42  origin=device-a  state=superseded  mode=0o755"
    );
}

#[test]
fn version_line_renders_unknown_origin() {
    let v = FileVersionInfo {
        version_seq: 1,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: String::new(),
        unix_mode: None,
        kind: EntryKind::File as i32,
    };
    assert!(version_line(&v).contains("origin=unknown"));
}

/// No Unix permission info (a version authored on Windows) renders as
/// `-`, never a fabricated octal value -- same rule as the CLI's own
/// `version_history::version_line`.
#[test]
fn version_line_renders_absent_unix_mode() {
    let v = FileVersionInfo {
        version_seq: 1,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: "device-a".into(),
        unix_mode: None,
        kind: EntryKind::File as i32,
    };
    assert!(version_line(&v).contains("mode=-"));
}

#[test]
fn conflict_origin_line_renders_device_and_timestamp() {
    let detail = yadorilink_product_view::ConflictDetail {
        current_path: "vacation.jpg".into(),
        loser_device_id: Some("device-b".into()),
        timestamp: Some("2026-01-01-000000".into()),
        content_hash_hex: Some(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into(),
        ),
        reason: yadorilink_product_view::ConflictReason::ConcurrentEdit,
    };
    assert_eq!(conflict_origin_line(&detail), "From device-b, saved 2026-01-01-000000");
}

#[test]
fn conflict_origin_line_degrades_when_unparseable() {
    let detail = yadorilink_product_view::ConflictDetail {
        current_path: "plain.txt".into(),
        loser_device_id: None,
        timestamp: None,
        content_hash_hex: None,
        reason: yadorilink_product_view::ConflictReason::ConcurrentEdit,
    };
    assert_eq!(conflict_origin_line(&detail), "Origin device unknown");
}

#[test]
fn trashed_file_provenance_line_renders_every_field() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "vacation.jpg".into(),
        version_seq: 4,
        last_known_size: 1_258_291, // ~1.2 MiB
        origin_device_id: "device-a".into(),
        deleted_at_unix_nanos: (now - 3600) * 1_000_000_000,
        kind: EntryKind::File as i32,
        deleted_by_operation: String::new(),
    };
    let line = trashed_file_provenance_line(&f);
    assert!(line.contains("Deleted 1h ago by device-a"), "got {line:?}");
    assert!(line.contains("v4"), "got {line:?}");
    assert!(line.contains("MiB"), "got {line:?}");
}

#[test]
fn trashed_file_provenance_line_reports_unknown_origin_and_time() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "vacation.jpg".into(),
        version_seq: 1,
        last_known_size: 0,
        origin_device_id: String::new(),
        deleted_at_unix_nanos: 0,
        kind: EntryKind::File as i32,
        deleted_by_operation: String::new(),
    };
    let line = trashed_file_provenance_line(&f);
    assert!(line.contains("unknown device"), "got {line:?}");
    assert!(line.contains("unknown time"), "got {line:?}");
}

#[test]
fn relative_time_from_unix_nanos_buckets_like_last_seen_label() {
    assert_eq!(relative_time_from_unix_nanos(0), "unknown time");
    assert_eq!(relative_time_from_unix_nanos(-1), "unknown time");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(relative_time_from_unix_nanos(now * 1_000_000_000), "just now");
    assert_eq!(relative_time_from_unix_nanos((now - 120) * 1_000_000_000), "2m ago");
}

/// Same rule as the CLI: a directory version has no size or mtime of its
/// own, so the line names the kind instead of printing `size=0`.
#[test]
fn directory_version_line_does_not_print_size() {
    let v = FileVersionInfo {
        version_seq: 4,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: "device-a".into(),
        unix_mode: Some(0o755),
        kind: EntryKind::Directory as i32,
    };
    assert_eq!(version_line(&v), "v4  directory  origin=device-a  state=current  mode=0o755");
}

#[test]
fn trashed_directory_provenance_line_does_not_print_size() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album".into(),
        version_seq: 2,
        last_known_size: 0,
        origin_device_id: "device-a".into(),
        deleted_at_unix_nanos: 0,
        kind: EntryKind::Directory as i32,
        deleted_by_operation: String::new(),
    };
    let line = trashed_file_provenance_line(&f);
    assert!(line.ends_with("v2  ·  folder"), "got {line:?}");
}

fn trashed(path: &str, operation: &str) -> TrashedFileInfo {
    TrashedFileInfo {
        local_path: "/home/alice/Photos".into(),
        path: path.into(),
        version_seq: 1,
        last_known_size: 10,
        origin_device_id: "device-a".into(),
        deleted_at_unix_nanos: 0,
        kind: EntryKind::File as i32,
        deleted_by_operation: operation.into(),
    }
}

/// The entries one recursive delete removed form one group, restorable as
/// a folder; an entry deleted on its own stays a group of one.
#[test]
fn trash_groups_entries_removed_by_one_operation_together() {
    let files = vec![
        trashed("album/a.jpg", "device-a:0102"),
        trashed("loose.txt", ""),
        trashed("album", "device-a:0102"),
        trashed("other/b.jpg", "device-b:0304"),
        trashed("album/sub/c.jpg", "device-a:0102"),
    ];
    let groups = trash_groups(&files);
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0].operation.as_deref(), Some("device-a:0102"));
    assert_eq!(
        groups[0].entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
        ["album/a.jpg", "album", "album/sub/c.jpg"]
    );
    assert_eq!(groups[0].root_path(), "album");
    assert_eq!(groups[1].operation, None);
    assert_eq!(groups[1].entries.len(), 1);
    assert_eq!(groups[2].root_path(), "other/b.jpg");
    assert_eq!(folder_group_title(&groups[0]), "Removed together with album (3 items)");
    assert_eq!(folder_group_title(&groups[2]), "Removed together with other/b.jpg (1 item)");
}

#[test]
fn folder_restore_message_reports_what_came_back() {
    use yadorilink_ipc_proto::daemonctl::RestoreTrashOperationFailure;
    let clean = RestoreTrashOperationResponse {
        restored_paths: vec!["album".into(), "album/a.jpg".into()],
        failed: vec![],
        partial: false,
    };
    assert_eq!(folder_restore_message(&clean), Ok("Restored 2 items of the folder.".into()));

    let partial = RestoreTrashOperationResponse { partial: true, ..clean.clone() };
    let text = folder_restore_message(&partial).expect("a partial restore is not a failure");
    assert!(text.contains("has not reached this device"), "{text}");

    let failed = RestoreTrashOperationResponse {
        restored_paths: vec!["album".into()],
        failed: vec![RestoreTrashOperationFailure {
            path: "album/a.jpg".into(),
            error: "content unavailable".into(),
        }],
        partial: false,
    };
    let text = folder_restore_message(&failed).expect_err("a failed entry fails the restore");
    assert!(text.starts_with("Restored 1 item of the folder."), "{text}");
    assert!(text.contains("album/a.jpg: content unavailable"), "{text}");
}
