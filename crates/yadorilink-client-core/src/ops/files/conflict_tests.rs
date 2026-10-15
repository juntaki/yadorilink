use super::*;

const COPY: &str = "plan (conflicted copy, 2026-01-01-000000, device-b).txt";

fn info(root: &std::path::Path, path: &str) -> ConflictedFileInfo {
    ConflictedFileInfo {
        local_path: root.to_string_lossy().into_owned(),
        path: path.into(),
        size: 1,
        ..Default::default()
    }
}

fn folder_with_copy() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("plan.txt"), "mine").unwrap();
    std::fs::write(dir.path().join(COPY), "theirs").unwrap();
    dir
}

#[test]
fn keep_this_replaces_the_original_with_the_copy() {
    let dir = folder_with_copy();
    let kept = apply_conflict_choice(&info(dir.path(), COPY), ConflictChoice::KeepThis).unwrap();
    assert_eq!(kept, dir.path().join("plan.txt"));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "theirs");
    assert!(!dir.path().join(COPY).exists());
}

#[test]
fn keep_both_renames_the_copy_to_a_plain_name() {
    let dir = folder_with_copy();
    let kept = apply_conflict_choice(&info(dir.path(), COPY), ConflictChoice::KeepBoth).unwrap();
    assert_eq!(kept, dir.path().join("plan (other version).txt"));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "theirs");
    assert_eq!(std::fs::read_to_string(dir.path().join("plan.txt")).unwrap(), "mine");
    assert!(!dir.path().join(COPY).exists());
}

#[test]
fn keep_both_never_overwrites_an_existing_name() {
    let dir = folder_with_copy();
    std::fs::write(dir.path().join("plan (other version).txt"), "older").unwrap();
    let kept = apply_conflict_choice(&info(dir.path(), COPY), ConflictChoice::KeepBoth).unwrap();
    assert_eq!(kept, dir.path().join("plan (other version 2).txt"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("plan (other version).txt")).unwrap(),
        "older"
    );
}

#[test]
fn a_name_that_is_not_a_conflict_copy_is_refused() {
    let dir = folder_with_copy();
    let err = apply_conflict_choice(&info(dir.path(), "plan.txt"), ConflictChoice::KeepThis);
    assert!(err.is_err());
    assert_eq!(std::fs::read_to_string(dir.path().join("plan.txt")).unwrap(), "mine");
}

#[test]
fn keep_this_refuses_when_the_original_name_is_a_folder() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("plan.txt")).unwrap();
    std::fs::write(dir.path().join(COPY), "theirs").unwrap();
    assert!(apply_conflict_choice(&info(dir.path(), COPY), ConflictChoice::KeepThis).is_err());
    assert!(dir.path().join(COPY).exists());
}
