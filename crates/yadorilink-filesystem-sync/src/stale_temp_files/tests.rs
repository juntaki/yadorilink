#![cfg(test)]

use super::*;

#[test]
fn is_own_stale_temp_file_name_matches_exact_suffix_shape() {
    assert!(is_own_stale_temp_file_name("report.txt.yadorilink-tmp.12345.7"));
    assert!(is_own_stale_temp_file_name(".yadorilink-tmp.1.2"));
}

#[test]
fn is_own_stale_temp_file_name_rejects_a_mere_substring_match() {
    assert!(!is_own_stale_temp_file_name("notes.yadorilink-tmp.txt"));
    assert!(!is_own_stale_temp_file_name("report.yadorilink-tmp.12345.7.bak"));
    assert!(!is_own_stale_temp_file_name("plain.txt"));
    assert!(!is_own_stale_temp_file_name("report.yadorilink-tmp.abc.7"));
}

#[test]
fn cleanup_stale_temp_files_removes_only_matching_names_recursively() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("keep.txt"), b"x").unwrap();
    std::fs::write(root.join("stale.txt.yadorilink-tmp.111.2"), b"x").unwrap();
    std::fs::write(root.join("notes.yadorilink-tmp.txt"), b"x").unwrap();
    let sub = root.join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("nested.bin.yadorilink-tmp.222.3"), b"x").unwrap();

    let mut removed = cleanup_stale_temp_files(root);
    removed.sort();

    assert_eq!(removed.len(), 2);
    assert!(root.join("keep.txt").exists());
    assert!(root.join("notes.yadorilink-tmp.txt").exists());
    assert!(!root.join("stale.txt.yadorilink-tmp.111.2").exists());
    assert!(!sub.join("nested.bin.yadorilink-tmp.222.3").exists());
}

#[test]
fn cleanup_stale_temp_files_on_a_missing_root_is_a_no_op() {
    let missing = std::path::Path::new("/nonexistent/does-not-exist-yadorilink");
    assert!(cleanup_stale_temp_files(missing).is_empty());
}
