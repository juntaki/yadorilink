#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::EntryKind;

/// `versions` output shape — one line per version, newest
/// first is the daemon's own ordering contract (`SyncState::list_versions`'s
/// doc comment), this just checks the per-line rendering.
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

/// An unknown origin (empty string, see `FileVersionInfo.origin_device_id`'s
/// own doc comment) renders as `unknown`, not a blank field a user
/// could mistake for a rendering bug.
#[test]
fn version_line_renders_unknown_origin() {
    let v = FileVersionInfo {
        version_seq: 1,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: String::new(),
        unix_mode: Some(0o644),
        kind: EntryKind::File as i32,
    };
    assert!(version_line(&v).contains("origin=unknown"));
}

/// No Unix permission info (a version authored on Windows) renders as
/// `-`, never a fabricated octal value.
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
fn trashed_file_line_renders_every_field() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "vacation.jpg".into(),
        version_seq: 2,
        last_known_size: 1000,
        origin_device_id: "device-b".into(),
        deleted_at_unix_nanos: 999,
        kind: EntryKind::File as i32,
        deleted_by_operation: String::new(),
    };
    assert_eq!(
        trashed_file_line(&f),
        "/tmp/photos/vacation.jpg  deleted_at=999  last_known_size=1000  origin=device-b"
    );
}

#[test]
fn conflicted_file_line_renders_every_field() {
    let f = ConflictedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "vacation (conflicted copy, 2026-01-01-000000, device-b).jpg".into(),
        size: 1234,
        mtime_unix_nanos: 5678,
        kind: EntryKind::File as i32,
        reason: 0,
    };
    assert_eq!(
        conflicted_file_line(&f),
        "/tmp/photos/vacation (conflicted copy, 2026-01-01-000000, device-b).jpg  size=1234  \
         mtime=5678"
    );
}

/// A directory version has no size or mtime of its own (both are
/// canonically 0), so printing `size=0` would read as an empty file.
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
fn trashed_directory_line_does_not_print_size() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album".into(),
        version_seq: 2,
        last_known_size: 0,
        origin_device_id: "device-b".into(),
        deleted_at_unix_nanos: 999,
        kind: EntryKind::Directory as i32,
        deleted_by_operation: String::new(),
    };
    assert_eq!(
        trashed_file_line(&f),
        "/tmp/photos/album/  deleted_at=999  directory  origin=device-b"
    );
}

#[test]
fn conflicted_directory_line_does_not_print_size() {
    let f = ConflictedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        size: 0,
        mtime_unix_nanos: 0,
        kind: EntryKind::Directory as i32,
        reason: 0,
    };
    assert_eq!(
        conflicted_file_line(&f),
        "/tmp/photos/album (conflicted copy, 2026-01-01-000000, device-b)/  directory"
    );
}

/// An entry a recursive delete removed says so, with a short form of the
/// operation, so the entries of one folder read as one group.
#[test]
fn trashed_line_names_the_folder_operation_that_removed_it() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album/cover.jpg".into(),
        version_seq: 2,
        last_known_size: 10,
        origin_device_id: "device-b".into(),
        deleted_at_unix_nanos: 999,
        kind: EntryKind::File as i32,
        deleted_by_operation: format!("device-b:{}", "ab".repeat(16)),
    };
    assert_eq!(
        trashed_file_line(&f),
        "/tmp/photos/album/cover.jpg  deleted_at=999  last_known_size=10  origin=device-b  \
         folder_operation=abababab"
    );
}

#[test]
fn conflicted_file_line_names_a_folder_at_its_path() {
    let f = ConflictedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        size: 3,
        mtime_unix_nanos: 4,
        kind: EntryKind::File as i32,
        reason: yadorilink_ipc_proto::daemonctl::ConflictReason::FolderAtPath as i32,
    };
    assert_eq!(
        conflicted_file_line(&f),
        "/tmp/photos/album (conflicted copy, 2026-01-01-000000, device-b)  size=3  mtime=4  \
         reason=folder_at_path"
    );
}
