#![cfg(test)]

use super::types::is_safe_relative_path;

#[test]
fn ordinary_relative_paths_are_safe() {
    assert!(is_safe_relative_path("hello.txt"));
    assert!(is_safe_relative_path("nested/dir/file.txt"));
}

#[test]
fn parent_dir_traversal_is_rejected() {
    assert!(!is_safe_relative_path("../outside.txt"));
    assert!(!is_safe_relative_path("nested/../../outside.txt"));
    assert!(!is_safe_relative_path("../../../.ssh/authorized_keys"));
}

#[test]
fn absolute_paths_are_rejected() {
    assert!(!is_safe_relative_path("/etc/passwd"));
}

#[test]
fn empty_path_is_rejected() {
    assert!(!is_safe_relative_path(""));
}
