//! Filename hazard detection: pure detection logic for the two
//! name-based hazards a materialization/
//! hydration write must never proceed past —
//!
//! - a **case-fold collision** with an existing sibling on a
//!   case-insensitive filesystem: two paths that differ only by
//!   case (`Photo.jpg` vs. `photo.jpg`) can coexist in the index (two
//!   peers, or a case-sensitive filesystem, can legally hold both), but
//!   writing both to the same case-insensitive directory clobbers one with
//!   the other.
//! - a **platform-invalid name**: the documented Windows-
//!   reserved device basenames, a trailing `.`/` `, or any of `<>:"|?*`.
//!
//! Kept in its own module rather than folded into `peer_session.rs` because
//! almost all of it — `invalid_name_reason`, `case_fold_collision` — is
//! pure string/path logic with no `SyncState`/filesystem dependency at all,
//! directly unit-testable on its own. `is_case_insensitive_filesystem` is
//! the one real filesystem probe in this module; see its doc comment.
//!
//! `peer_session::PeerSyncSession::hazard_reason_for` is the only caller:
//! it composes both checks and turns a hazard into the free-form
//! `held_reason` string `SyncState::set_held` (section 1's schema) records.
//! Per a hazard here **never** produces an automatic rename or
//! escape — the record is held, exactly as-is, under its original path, or
//! not held at all. See `peer_session.rs`'s
//! `no_hazard_ever_writes_under_any_alternate_name` regression test.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::types::FileRecord;

/// `SyncState::set_held`'s own doc comment in `index.rs`
/// already documents these two exact reason-string prefixes as its
/// canonical examples (`"case_collision"`, `"invalid_name"`) — this module
/// is what actually produces them, so the constants live here as the
/// single source of truth. Both are prefixes: the full `held_reason`
/// stored also carries a human-readable detail after a `": "` separator
/// (e.g. `"case_collision: collides with existing 'Photo.jpg'"`), but
/// `held_reason.starts_with(HELD_REASON_CASE_COLLISION)` is the stable
/// thing to match against — the detail text is for humans (CLI display),
/// not for programmatic dispatch.
pub const HELD_REASON_CASE_COLLISION: &str = "case_collision";
pub const HELD_REASON_INVALID_NAME: &str = "invalid_name";

/// Which platform's filename rules gate materialization (gated
/// on the local platform — a Windows peer holds a `CON.txt`, a POSIX peer
/// materializing the exact same index record does not, since the name is
/// completely valid there). A real materializing device always uses
/// [`NamePolicy::local`]; tests exercise both variants directly against
/// identical index state to prove exactly that asymmetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamePolicy {
    Posix,
    Windows,
}

impl NamePolicy {
    /// The policy this actual running device's platform implies.
    #[cfg(windows)]
    pub fn local() -> Self {
        NamePolicy::Windows
    }

    /// See the `#[cfg(windows)]` variant above.
    #[cfg(not(windows))]
    pub fn local() -> Self {
        NamePolicy::Posix
    }
}

/// The documented Windows-reserved device basenames, compared
/// case-insensitively against a filename's stem (the part before its
/// *first* `.` — see `windows_invalid_name_detail`'s doc comment for why
/// `CON.txt` is still reserved).
const RESERVED_BASENAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The documented forbidden-character set.
const FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// the Windows-invalid-name reason `final_component` (a single
/// path component — the file's own name, not a full path) would be held
/// for, or `None` if it's fine under Windows' documented naming rules.
/// Pure string analysis; never touches the filesystem. Checks, in order:
/// any of `<>:"|?*` anywhere in the name; a trailing `.` or ` `; and the
/// reserved-basename list, checked against the name *without* its
/// extension (`stem`, the substring before the first `.`) — Windows
/// reserves `CON` as a device name regardless of what follows it, so
/// `CON.txt` and `CON.tar.gz` are both still reserved, exactly as `CON`
/// itself is.
fn windows_invalid_name_detail(final_component: &str) -> Option<String> {
    if final_component.is_empty() {
        return None;
    }
    if let Some(bad) = final_component.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
        return Some(format!("forbidden character '{bad}'"));
    }
    if final_component.ends_with('.') || final_component.ends_with(' ') {
        return Some("trailing dot or space".to_string());
    }
    let stem = final_component.split('.').next().unwrap_or(final_component);
    if RESERVED_BASENAMES.iter().any(|reserved| reserved.eq_ignore_ascii_case(stem)) {
        return Some(format!("reserved device name '{}'", stem.to_uppercase()));
    }
    None
}

/// `path`'s held reason under `policy`, or `None` if
/// materializing it under `policy` is safe. Always `None` under
/// [`NamePolicy::Posix`] — the Windows-only rule set never gates a POSIX
/// materialization, since a name like `CON.txt` is completely valid on a
/// POSIX filesystem (gated on the local platform). Only the
/// *final* path component (`path`'s own filename) is checked, matching the
/// requirement to check against the filename — an intermediate
/// directory component happening to be named `CON` is out of scope here,
/// same as `case_fold_collision` below only ever compares siblings within
/// one directory.
pub fn invalid_name_reason(policy: NamePolicy, path: &str) -> Option<String> {
    if policy == NamePolicy::Posix {
        return None;
    }
    let final_component = final_component_of(path);
    windows_invalid_name_detail(final_component)
        .map(|detail| format!("{HELD_REASON_INVALID_NAME}: {detail}"))
}

/// `path`'s parent directory, as the same `/`-joined slash string every
/// `FileRecord::path` already uses (`local_change.rs` normalizes
/// separators to `/` at scan/watch time, regardless of host OS) — `""` for
/// a top-level file.
fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(idx) => &path[..idx],
        None => "",
    }
}

/// `path`'s final path component (its own file/directory name).
fn final_component_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// the already-indexed sibling in `siblings` that `path` collides
/// with case-insensitively, if any — a non-deleted record living in the
/// same parent directory whose final path component case-folds
/// identically to `path`'s own but is not byte-identical to it (so
/// updating a file at its own unchanged path is never flagged as
/// colliding with itself). `siblings` is expected to be every record
/// currently indexed for the group (`SyncState::list_files`) — this
/// function does the directory-scoping and case-fold comparison itself
/// (including the `deleted` filter), so it stays a pure, directly testable
/// function with no `SyncState` dependency of its own.
///
/// O(siblings.len()) per call — this module doesn't index siblings by
/// parent directory or case-folded name, since this isn't scoped as a
/// performance-sensitive path; a large single folder group could make this a
/// real cost worth revisiting, but that's a follow-on, not this function's
/// job.
pub fn case_fold_collision<'a>(path: &str, siblings: &'a [FileRecord]) -> Option<&'a FileRecord> {
    let parent = parent_of(path);
    let name_lower = final_component_of(path).to_lowercase();
    siblings.iter().find(|sibling| {
        !sibling.deleted
            && sibling.path != path
            && parent_of(&sibling.path) == parent
            && final_component_of(&sibling.path).to_lowercase() == name_lower
    })
}

/// process-wide cache of "is this canonicalized directory's
/// filesystem case-insensitive", keyed by the canonicalized directory path
/// that was actually probed. `probe_case_insensitive_filesystem` performs
/// a real filesystem round trip (creates and removes a small temp file) —
/// expensive and stable enough for a sync root's lifetime that paying it
/// once per root (not once per materialized record) is worth a
/// process-wide cache rather than a per-`PeerSyncSession` one: several
/// sessions (one per connected peer) legitimately share the same sync
/// roots, and re-probing per session would multiply real filesystem I/O
/// for no behavioral benefit.
static CASE_SENSITIVITY_CACHE: OnceLock<Mutex<HashMap<PathBuf, bool>>> = OnceLock::new();

/// whether `dir`'s filesystem is case-insensitive. Probed for
/// real rather than assumed from `cfg!(target_os = ...)`, since neither
/// direction of that assumption holds: macOS APFS can be formatted either
/// case-sensitive or case-insensitive (case-insensitive is only the
/// *default*), and a case-insensitive volume (a mounted exFAT/NTFS share,
/// for instance) can exist on a case-sensitive-by-default OS too. Probes
/// by creating a uniquely-named file with mixed-case letters directly
/// under `dir`, then checking whether an all-uppercase variant of that
/// exact name resolves to the same entry — cached per canonicalized `dir`
/// (see [`CASE_SENSITIVITY_CACHE`]) so repeated materializations into the
/// same directory pay the real filesystem round trip only once.
///
/// On any probe I/O failure (can't create `dir`, can't canonicalize it,
/// can't write the probe file — e.g. a not-yet-existing or read-only
/// root), this conservatively assumes case-**insensitive**: the stricter
/// of the two answers, since it never lets a possible collision through
/// unheld — the opposite default (case-sensitive) would let a real
/// collision through unheld on a filesystem this device simply couldn't
/// successfully probe, which is the failure mode exists to
/// prevent.
pub fn is_case_insensitive_filesystem(dir: &Path) -> bool {
    let cache = CASE_SENSITIVITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let canonical = match std::fs::create_dir_all(dir).and_then(|_| std::fs::canonicalize(dir)) {
        Ok(c) => c,
        Err(_) => return true, // conservative default — see doc comment
    };

    if let Some(&insensitive) =
        cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&canonical)
    {
        return insensitive;
    }

    let insensitive = probe_case_insensitive_filesystem(&canonical).unwrap_or(true);
    cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(canonical, insensitive);
    insensitive
}

fn probe_case_insensitive_filesystem(canonical_dir: &Path) -> std::io::Result<bool> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mixed-case letters, so `.to_uppercase()` below actually changes the
    // string — a name with no letters (or already all-uppercase) would
    // make this probe meaningless.
    let probe_name = format!(".yl-case-probe-{}-{n}", std::process::id());
    let lower_path = canonical_dir.join(&probe_name);
    let upper_path = canonical_dir.join(probe_name.to_uppercase());

    // Best-effort cleanup of a leftover probe file from a previous
    // crashed/killed process — never fatal if there's nothing to remove.
    let _ = std::fs::remove_file(&lower_path);

    std::fs::File::create(&lower_path)?;
    let insensitive = upper_path.exists();
    let _ = std::fs::remove_file(&lower_path);
    Ok(insensitive)
}

#[cfg(test)]
mod invalid_name_tests {
    use super::{invalid_name_reason, NamePolicy};

    #[test]
    fn posix_policy_never_holds_anything_windows_would_reject() {
        for name in ["CON", "con.txt", "COM1", "trailing.", "trailing ", "bad<name>.txt"] {
            assert_eq!(
                invalid_name_reason(NamePolicy::Posix, name),
                None,
                "{name:?} must never be held under a POSIX policy"
            );
        }
    }

    #[test]
    fn windows_policy_holds_a_bare_reserved_name() {
        let reason = invalid_name_reason(NamePolicy::Windows, "CON").unwrap();
        assert!(reason.starts_with(super::HELD_REASON_INVALID_NAME));
    }

    #[test]
    fn windows_policy_holds_a_reserved_name_with_an_extension() {
        // Windows reserves the device name regardless of what follows it.
        assert!(invalid_name_reason(NamePolicy::Windows, "con.txt").is_some());
        assert!(invalid_name_reason(NamePolicy::Windows, "COM1.tar.gz").is_some());
    }

    #[test]
    fn windows_policy_holds_within_a_nested_path() {
        assert!(invalid_name_reason(NamePolicy::Windows, "docs/notes/CON.txt").is_some());
    }

    #[test]
    fn windows_policy_does_not_hold_a_name_that_merely_contains_a_reserved_word() {
        // "CONTRACT.txt" is not "CON" — only an exact stem match reserves.
        assert_eq!(invalid_name_reason(NamePolicy::Windows, "CONTRACT.txt"), None);
        assert_eq!(invalid_name_reason(NamePolicy::Windows, "economics.txt"), None);
    }

    #[test]
    fn windows_policy_holds_trailing_dot_or_space() {
        assert!(invalid_name_reason(NamePolicy::Windows, "notes.").is_some());
        assert!(invalid_name_reason(NamePolicy::Windows, "notes ").is_some());
    }

    #[test]
    fn windows_policy_holds_forbidden_characters() {
        for name in ["a<b.txt", "a>b.txt", "a:b.txt", "a\"b.txt", "a|b.txt", "a?b.txt", "a*b.txt"] {
            assert!(invalid_name_reason(NamePolicy::Windows, name).is_some(), "{name:?}");
        }
    }

    #[test]
    fn windows_policy_does_not_hold_an_ordinary_name() {
        assert_eq!(invalid_name_reason(NamePolicy::Windows, "vacation-photo.jpg"), None);
    }
}

#[cfg(test)]
mod case_fold_collision_tests {
    use super::case_fold_collision;
    use crate::types::FileRecord;
    use crate::version_vector::VersionVector;

    fn record(path: &str) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    #[test]
    fn detects_a_same_directory_case_fold_collision() {
        let siblings = vec![record("Photo.jpg")];
        let found = case_fold_collision("photo.jpg", &siblings).unwrap();
        assert_eq!(found.path, "Photo.jpg");
    }

    #[test]
    fn does_not_flag_updating_the_same_path_as_a_collision_with_itself() {
        let siblings = vec![record("photo.jpg")];
        assert!(case_fold_collision("photo.jpg", &siblings).is_none());
    }

    #[test]
    fn ignores_a_case_fold_match_in_a_different_directory() {
        let siblings = vec![record("other/Photo.jpg")];
        assert!(case_fold_collision("photo.jpg", &siblings).is_none());
    }

    #[test]
    fn ignores_a_tombstoned_sibling() {
        let mut deleted = record("Photo.jpg");
        deleted.deleted = true;
        let siblings = vec![deleted];
        assert!(case_fold_collision("photo.jpg", &siblings).is_none());
    }

    #[test]
    fn distinct_names_never_collide() {
        let siblings = vec![record("vacation.jpg")];
        assert!(case_fold_collision("photo.jpg", &siblings).is_none());
    }

    #[test]
    fn matches_within_a_nested_directory_too() {
        let siblings = vec![record("albums/Summer/Photo.jpg")];
        let found = case_fold_collision("albums/Summer/photo.jpg", &siblings).unwrap();
        assert_eq!(found.path, "albums/Summer/Photo.jpg");
    }
}

#[cfg(test)]
mod case_insensitive_probe_tests {
    use super::is_case_insensitive_filesystem;

    /// This is a real filesystem probe, not a mock — it must agree with
    /// what the actual host filesystem does. macOS's default APFS volume
    /// (almost certainly what a dev machine's tempdir sits on) is
    /// case-insensitive; this is documented as environment-dependent
    /// rather than asserted as a hard fact about every possible CI runner.
    #[test]
    fn probe_returns_a_stable_answer_for_the_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        let first = is_case_insensitive_filesystem(dir.path());
        let second = is_case_insensitive_filesystem(dir.path());
        assert_eq!(first, second, "the cached answer must be stable across calls");
    }

    #[test]
    fn probe_leaves_no_leftover_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        is_case_insensitive_filesystem(dir.path());
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(entries.is_empty(), "the probe file must be cleaned up: {entries:?}");
    }

    #[test]
    fn a_missing_and_uncreatable_directory_conservatively_reports_insensitive() {
        // A path under a file (not a directory) can never be created —
        // `create_dir_all` fails, exercising the conservative-default arm.
        let base = tempfile::tempdir().unwrap();
        let not_a_dir = base.path().join("plain-file");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let unreachable = not_a_dir.join("child");
        assert!(is_case_insensitive_filesystem(&unreachable));
    }
}
