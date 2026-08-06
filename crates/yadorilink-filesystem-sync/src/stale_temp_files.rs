//! Startup/periodic sweep that recursively removes stale temp-write
//! artifacts left behind by an interrupted materialization write, placeholder
//! write, symlink materialization, or block-store put — real filesystem
//! execution with no index/SQL/state dependency at all, moved out of
//! `yadorilink-sync-core`'s `materialization.rs` in Phase 7D-9C
//! (`docs/design/phase7d9-dependency-plan.md`'s 7D-9C routing rules: "real
//! file generation/hydrate/evict/rename/metadata application →
//! `filesystem-sync`").

use std::path::{Path, PathBuf};

use yadorilink_root_authority::reserved_namespace;

/// Recursively removes stale temp-write artifacts left behind by an
/// interrupted materialization write (`materialize_write::reconstruct_file`/
/// `write_placeholder`/`materialize_symlink_at`), or `FsBlockStore::put` when
/// `root` is a block-store root instead of a link's synced folder — both
/// crates' `unique_tmp_path` helpers generate the identical naming scheme. A
/// crash between creating one of those temp files and the rename that would
/// have replaced it leaves it sitting on disk forever, since nothing else
/// ever revisits it.
///
/// Only ever removes a filename matching the *exact*
/// `<original-name>.yadorilink-tmp.<pid>.<counter>` suffix shape those
/// functions generate (both `<pid>` and `<counter>` non-empty and
/// ASCII-digit-only) — see [`is_own_stale_temp_file_name`]. Aggressive
/// cleanup could delete user files, so a user file that merely *contains*
/// the substring `.yadorilink-tmp.` somewhere in a name it chose itself
/// (e.g. `notes.yadorilink-tmp.txt`, or `report.yadorilink-tmp.12345.7.bak`)
/// is deliberately left untouched — real temp files this crate creates
/// never have anything follow the numeric counter.
///
/// Safe to call unconditionally at every startup, before any other recovery
/// or sync work begins: any matching file that still exists at that point is
/// by definition orphaned — this process hasn't performed a single write
/// yet, and the only path that ever creates one either completes with a
/// rename that removes it, or is a *previous* run's writer that got killed
/// mid-write.
///
/// Best-effort per-entry: a failure to read one subdirectory, or to remove
/// one matching file (e.g. a permissions problem), is skipped rather than
/// aborting the whole walk — one bad entry should not block cleanup of every
/// other stale temp file. Returns the paths actually removed.
pub fn cleanup_stale_temp_files(root: &Path) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    if root.is_dir() {
        walk_and_remove_stale_temp_files(root, &mut removed);
    }
    removed
}

fn walk_and_remove_stale_temp_files(dir: &Path, removed: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        // A versioned reserved-namespace artefact (`.yadorilink-v1-*`) is
        // never in scope for this sweep — it's a distinct, additive
        // namespace from the legacy `.yadorilink-tmp.` marker this sweep
        // owns (see `reserved_namespace`'s module doc comment), and this
        // process has no journal row telling it which artefact, if any, it
        // owns. Checked before the directory/file branch below (and before
        // recursing) so a reserved *directory* is never descended into
        // either — no current `ArtefactKind` is directory-shaped, but "never
        // touch an unowned artefact" has to hold for its contents too, not
        // just for itself; `link_preflight::scan_directory` prunes the same
        // way for the same reason.
        if reserved_namespace::classify_component(entry.file_name().as_os_str())
            .is_some_and(|c| matches!(c, reserved_namespace::ReservedComponent::Artefact { .. }))
        {
            continue;
        }
        if file_type.is_dir() {
            walk_and_remove_stale_temp_files(&path, removed);
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        if is_own_stale_temp_file_name(&name) && std::fs::remove_file(&path).is_ok() {
            removed.push(path);
        }
    }
}

/// Recognizes exactly the `.yadorilink-tmp.<pid>.<counter>` suffix
/// `unique_tmp_path` (`yadorilink-local-storage`'s `chunker`/`fs_backend`
/// modules) appends — see [`cleanup_stale_temp_files`]'s doc comment for why
/// this must be strict rather than a bare substring match.
fn is_own_stale_temp_file_name(name: &str) -> bool {
    const MARKER: &str = ".yadorilink-tmp.";
    let Some(idx) = name.find(MARKER) else { return false };
    let suffix = &name[idx + MARKER.len()..];
    let mut parts = suffix.split('.');
    let (Some(pid), Some(counter), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    is_ascii_digits(pid) && is_ascii_digits(counter)
}

fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
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
}
