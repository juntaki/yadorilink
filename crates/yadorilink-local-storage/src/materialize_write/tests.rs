#![cfg(test)]

use super::*;
use std::ffi::OsString;
use std::sync::Mutex;
use yadorilink_root_authority::fs_identity::{FileIdentity, ObjectKind};

/// One call the materializer made on its structural-directory ledger, and
/// what was on disk at the path when it made it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LedgerCall {
    /// `record_intent`, and whether anything was at the path already.
    Intent {
        path: String,
        existed: bool,
    },
    /// `complete`, and whether the identity it was handed is the
    /// directory now at the path.
    Complete {
        path: String,
        identity_is_the_directory_there: bool,
    },
    Abandon {
        path: String,
    },
}

/// A ledger that records every call, against a root it can look at, and
/// can be told to act or fail at a chosen call.
/// A hook run inside `record_intent` for one path.
type IntentHook = Box<dyn Fn(&Path) + Send + Sync>;

#[derive(Default)]
struct RecordingLedger {
    root: Option<std::path::PathBuf>,
    calls: Mutex<Vec<LedgerCall>>,
    /// Runs inside `record_intent` for this path, after the call is
    /// recorded: what a user's `mkdir` racing the materializer's does.
    on_intent: Option<(String, IntentHook)>,
    fail_intent_for: Option<String>,
    fail_complete_for: Option<String>,
}

impl RecordingLedger {
    fn over(root: &Path) -> Self {
        Self { root: Some(root.to_path_buf()), ..Self::default() }
    }

    fn calls(&self) -> Vec<LedgerCall> {
        self.calls.lock().unwrap().clone()
    }

    fn at(&self, rel_path: &str) -> std::path::PathBuf {
        self.root.as_ref().expect("a ledger that looks at disk needs its root").join(rel_path)
    }
}

impl StructuralDirectoryLedger for RecordingLedger {
    fn record_intent(&self, rel_path: &str) -> Result<(), StorageError> {
        if self.fail_intent_for.as_deref() == Some(rel_path) {
            return Err(StorageError::Io(std::io::Error::other("injected intent failure")));
        }
        let existed = self.root.is_some() && fs::symlink_metadata(self.at(rel_path)).is_ok();
        self.calls.lock().unwrap().push(LedgerCall::Intent { path: rel_path.to_string(), existed });
        if let Some((path, hook)) = &self.on_intent {
            if path == rel_path {
                hook(&self.at(rel_path));
            }
        }
        Ok(())
    }

    fn complete(&self, rel_path: &str, identity: &FileIdentity) -> Result<(), StorageError> {
        let identity_is_the_directory_there = identity.object_kind == ObjectKind::Directory
            && self.root.is_some()
            && FileIdentity::observe_path(&self.at(rel_path))
                .is_ok_and(|now| now.object_id == identity.object_id);
        self.calls.lock().unwrap().push(LedgerCall::Complete {
            path: rel_path.to_string(),
            identity_is_the_directory_there,
        });
        if self.fail_complete_for.as_deref() == Some(rel_path) {
            return Err(StorageError::Io(std::io::Error::other("injected completion failure")));
        }
        Ok(())
    }

    fn abandon(&self, rel_path: &str) -> Result<(), StorageError> {
        self.calls.lock().unwrap().push(LedgerCall::Abandon { path: rel_path.to_string() });
        Ok(())
    }
}

fn intent(path: &str) -> LedgerCall {
    LedgerCall::Intent { path: path.to_string(), existed: false }
}

fn completed(path: &str) -> LedgerCall {
    LedgerCall::Complete { path: path.to_string(), identity_is_the_directory_there: true }
}

/// Every directory the materializer creates for a descendant is bracketed
/// in the ledger: the intent is recorded while nothing is at the path
/// yet, and the completion carries the identity of the directory the
/// `mkdir` made. Ancestors that already exist are not claimed.
#[test]
fn materializer_mkdir_records_structural_origin_around_create() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("existing")).unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger::over(&canonical_root);

    let out_path = root.path().join("existing/a/b/file.txt");
    verify_write_target_within_root(&out_path, root.path(), &ledger).unwrap();

    assert!(root.path().join("existing/a/b").is_dir());
    assert_eq!(
        ledger.calls(),
        vec![
            intent("existing/a"),
            completed("existing/a"),
            intent("existing/a/b"),
            completed("existing/a/b"),
        ]
    );
}

/// Crash window 1: the intent could not be made durable. Nothing may be
/// created, or a directory would exist that no record says this device
/// made.
#[test]
fn a_structural_mkdir_whose_intent_fails_creates_nothing() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        fail_intent_for: Some("a".to_string()),
        ..RecordingLedger::over(&canonical_root)
    };

    let result =
        verify_write_target_within_root(&root.path().join("a/f.txt"), root.path(), &ledger);

    assert!(result.is_err());
    assert!(!root.path().join("a").exists(), "no mkdir may run without a durable intent");
}

/// Crash window 2: the directory was created but its completion was not
/// recorded. The error surfaces (the write does not proceed as if the
/// origin were recorded) and the directory stays; the pending intent is
/// the ledger's to recover.
#[test]
fn a_structural_mkdir_whose_completion_fails_surfaces_the_error() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        fail_complete_for: Some("a".to_string()),
        ..RecordingLedger::over(&canonical_root)
    };

    let result =
        verify_write_target_within_root(&root.path().join("a/b/f.txt"), root.path(), &ledger);

    assert!(result.is_err());
    assert!(root.path().join("a").is_dir());
    assert!(!root.path().join("a/b").exists(), "nothing below may be created past the failure");
    assert_eq!(ledger.calls(), vec![intent("a"), completed("a")]);
}

/// A user's `mkdir` of the same name between the intent and the
/// materializer's own `mkdir`: the materializer's `mkdir` finds the name
/// taken, so the directory there is not one it created, and it claims no
/// origin for it. It still goes on to create what is missing below.
#[test]
fn mkdir_eexist_race_with_user_mkdir_does_not_claim_origin() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        on_intent: Some((
            "a".to_string(),
            Box::new(|path: &Path| fs::create_dir(path).expect("the user's mkdir")),
        )),
        ..RecordingLedger::over(&canonical_root)
    };

    verify_write_target_within_root(&root.path().join("a/b/f.txt"), root.path(), &ledger).unwrap();

    assert!(root.path().join("a/b").is_dir());
    assert_eq!(
        ledger.calls(),
        vec![
            intent("a"),
            LedgerCall::Abandon { path: "a".to_string() },
            intent("a/b"),
            completed("a/b"),
        ]
    );
}

/// An explicit directory's missing ancestors are structural and recorded;
/// the directory itself is the replicated entry and is not.
#[test]
fn an_explicit_directory_records_only_its_ancestors_as_structural() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger::over(&canonical_root);

    let created =
        create_explicit_directory(&canonical_root.join("a/b"), &canonical_root, &ledger).unwrap();

    assert_eq!(created, ExplicitDirectoryCreation::Created);
    assert!(root.path().join("a/b").is_dir());
    assert_eq!(ledger.calls(), vec![intent("a"), completed("a")]);

    let again =
        create_explicit_directory(&canonical_root.join("a/b"), &canonical_root, &ledger).unwrap();
    assert_eq!(again, ExplicitDirectoryCreation::AlreadyDirectory);
}

/// A file where the directory belongs is neither replaced nor followed.
#[test]
fn an_explicit_directory_over_a_file_is_refused_and_the_file_kept() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    fs::write(root.path().join("a"), b"a user's file").unwrap();

    let result = create_explicit_directory(
        &canonical_root.join("a"),
        &canonical_root,
        &RecordingLedger::over(&canonical_root),
    );

    assert!(matches!(
        result,
        Err(StorageError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(root.path().join("a")).unwrap(), b"a user's file");
}

#[test]
fn remove_empty_dir_removes_an_empty_directory() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("empty")).unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("empty")).unwrap(),
        crate::EmptyDirectoryRemoval::Removed
    );
    assert!(!root.path().join("empty").exists());
}

/// A directory holding anything -- here the OS junk every Finder
/// window leaves behind -- is never emptied on anyone's behalf.
#[test]
fn remove_empty_dir_keeps_a_directory_holding_os_junk_and_the_junk() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("a")).unwrap();
    fs::write(root.path().join("a/.DS_Store"), b"finder state").unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("a")).unwrap(),
        crate::EmptyDirectoryRemoval::NotEmpty
    );
    assert_eq!(fs::read(root.path().join("a/.DS_Store")).unwrap(), b"finder state");
}

#[test]
fn remove_empty_dir_reports_an_absent_path() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("gone")).unwrap(),
        crate::EmptyDirectoryRemoval::Absent
    );
}

#[test]
fn remove_empty_dir_never_removes_a_file() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("f"), b"x").unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("f")).unwrap(),
        crate::EmptyDirectoryRemoval::NotADirectory
    );
    assert!(root.path().join("f").exists());
}

/// A symlink to an empty directory is not a directory to remove: neither
/// the link nor its target is touched.
#[cfg(unix)]
#[test]
fn remove_empty_dir_never_follows_a_symlink() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("target")).unwrap();
    std::os::unix::fs::symlink(root.path().join("target"), root.path().join("link")).unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("link")).unwrap(),
        crate::EmptyDirectoryRemoval::NotADirectory
    );
    assert!(root.path().join("link").symlink_metadata().is_ok());
    assert!(root.path().join("target").is_dir());
}

/// `reconstruct_file_to_temp` + `persist_reconstructed_file` must
/// together produce exactly what the composed `reconstruct_file` always
/// did -- and, critically, the temp-write half alone must never touch
/// `out_path` at all, since a caller batching several paths' SQLite
/// commits relies on being able to run this half for many paths without
/// any of them becoming visible until the (separate, later) publish
/// half runs.
#[test]
fn reconstruct_file_to_temp_then_persist_matches_reconstruct_file() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("file.bin");
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    fs::write(&src_path, &content).unwrap();
    let blocks = crate::chunker::chunk_file(&store, &src_path).unwrap();

    let out_path = src_dir.path().join("reconstructed.bin");
    let tmp_path = reconstruct_file_to_temp(&store, &out_path, &blocks, -1).unwrap();

    assert!(!out_path.exists(), "the temp-write half must not touch out_path at all");
    assert!(tmp_path.exists());
    assert_eq!(fs::read(&tmp_path).unwrap(), content);

    persist_reconstructed_file(&tmp_path, &out_path).unwrap();

    assert!(!tmp_path.exists(), "the temp path must be gone after a successful publish");
    assert_eq!(fs::read(&out_path).unwrap(), content);
}

/// A placeholder reports the file's correct size via `stat`
/// without its content actually occupying disk space or being fetched.
#[test]
fn write_placeholder_reports_correct_size_with_no_content() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    write_placeholder(&out_path, 5_000_000, 1_700_000_000_000_000_000).unwrap();

    let metadata = fs::metadata(&out_path).unwrap();
    assert_eq!(metadata.len(), 5_000_000);
    // No real bytes were written — reading it back is all zeros, not
    // whatever content a real 5MB file might have had.
    let content = fs::read(&out_path).unwrap();
    assert!(content.iter().all(|&b| b == 0));
}

/// The identity `write_placeholder` returns for a freshly-written
/// placeholder must actually match the placeholder's real on-disk
/// identity, not merely be present -- a caller comparing against it
/// later relies on this being the truth, not a synthetic value.
#[test]
#[cfg(unix)]
fn write_placeholder_returns_the_real_on_disk_identity() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    let identity = write_placeholder(&out_path, 4096, 0).unwrap().unwrap();

    let metadata = fs::metadata(&out_path).unwrap();
    assert_eq!(identity.dev, metadata.dev());
    assert_eq!(identity.ino, metadata.ino());
}

/// Two placeholders written to the SAME path in sequence (mirroring a
/// peer sending an updated version, or a repeated eviction) must mint
/// DIFFERENT identities -- each `write_placeholder` call creates a
/// fresh temp file and renames it in, so the second call's inode can
/// never equal the first's. This is the exact property the
/// generation-staleness invariant depends on: an old identity must
/// stop matching once its placeholder is superseded.
#[test]
#[cfg(unix)]
fn successive_placeholder_writes_to_the_same_path_mint_different_identities() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    let first = write_placeholder(&out_path, 100, 0).unwrap().unwrap();
    let second = write_placeholder(&out_path, 100, 0).unwrap().unwrap();

    assert_ne!(first, second, "a re-written placeholder must mint a fresh identity");
}

/// On Windows, `create_or_defer_placeholder` must write NOTHING
/// to disk -- the real reparse-point placeholder is created later by
/// `cfapi-host.exe`'s own poll, which `write_placeholder`'s prior
/// unconditional sparse-file write would have pre-empted (that write
/// made `full_path.exists()` true, and `sync_placeholders` skips any
/// path that already exists).
#[test]
#[cfg(windows)]
fn windows_create_or_defer_placeholder_writes_nothing_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    let outcome = create_or_defer_placeholder(&out_path, 5_000_000, 0).unwrap();

    assert!(!out_path.exists(), "Windows must defer creation to cfapi-host, not pre-empt it");
    assert!(matches!(
        outcome,
        PlaceholderIdentityToRecord::RecordIfAbsent {
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            ..
        }
    ));
}

/// The old bug this closes: `write_placeholder` returning `None` on
/// Windows made every caller call `clear_placeholder_generation`,
/// discarding any generation. `create_or_defer_placeholder` must always
/// return `RecordIfAbsent`, never `Clear`, on Windows. It must also
/// never return `RecordOverwrite` -- an unconditional overwrite would
/// reintroduce the exact race this shape exists to prevent (see
/// `PlaceholderIdentityToRecord`'s own doc comment).
#[test]
#[cfg(windows)]
fn windows_create_or_defer_placeholder_never_clears() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    let outcome = create_or_defer_placeholder(&out_path, 100, 0).unwrap();

    assert!(matches!(outcome, PlaceholderIdentityToRecord::RecordIfAbsent { .. }));
}

/// Mirrors `successive_placeholder_writes_to_the_same_path_mint_
/// different_identities` for the Windows path: a re-create at the same
/// path (an evict immediately followed by a re-materialize) must not
/// reuse a stale generation a live CfAPI comparison could mistake for
/// the OLD placeholder still being untouched.
#[test]
#[cfg(windows)]
fn windows_successive_defers_at_the_same_path_mint_different_generations() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    let first = create_or_defer_placeholder(&out_path, 100, 0).unwrap();
    let second = create_or_defer_placeholder(&out_path, 100, 0).unwrap();

    assert_ne!(first, second, "a re-deferred placeholder must mint a fresh generation");
}

#[test]
fn failed_placeholder_rename_removes_its_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("occupied");
    fs::create_dir(&out_path).unwrap();

    assert!(write_placeholder(&out_path, 1024, 0).is_err());

    let entries: Vec<_> =
        fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(entries, vec![OsString::from("occupied")]);
    assert!(out_path.is_dir());
}

/// `materialize_symlink` creates a real, correctly-targeted symlink at
/// `out_path`, atomically (via `unique_tmp_path` + rename — no
/// partial/temp artifact left behind at the final path).
#[cfg(unix)]
#[test]
fn materialize_symlink_creates_a_real_symlink_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("link.txt");

    materialize_symlink(&out_path, b"../outside/target.txt").unwrap();

    let link_meta = fs::symlink_metadata(&out_path).unwrap();
    assert!(link_meta.file_type().is_symlink(), "must be a real symlink, not a regular file");
    assert_eq!(fs::read_link(&out_path).unwrap(), Path::new("../outside/target.txt"));
}

/// Re-materializing the same path (e.g. a re-sent index
/// update for an unchanged symlink record) must cleanly replace the
/// old link via the same atomic rename, not error on "already exists".
#[cfg(unix)]
#[test]
fn materialize_symlink_can_replace_an_existing_link_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("link.txt");

    materialize_symlink(&out_path, b"old-target.txt").unwrap();
    materialize_symlink(&out_path, b"new-target.txt").unwrap();

    assert_eq!(fs::read_link(&out_path).unwrap(), Path::new("new-target.txt"));
}

#[test]
fn stamp_mtime_at_path_actually_changes_disk_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    fs::write(&path, b"content").unwrap();
    // A multiple of 100: Windows' FILETIME, and therefore `std::fs::
    // FileTimes`, only has 100ns resolution, so any other value would
    // round-trip through `stamp_mtime_at_path` as a different number there
    // and fail the exact-match assertion below for a reason unrelated to
    // what this test checks.
    let desired = 1_700_000_123_456_700i64;

    assert!(!mtime_already_matches_disk(&path, desired).unwrap());
    stamp_mtime_at_path(&path, desired).unwrap();
    assert!(mtime_already_matches_disk(&path, desired).unwrap());
}

/// A negative `desired_mtime_unix_nanos` (the "no authoritative
/// mtime to stamp" sentinel) is trivially satisfied regardless of
/// whatever the disk actually holds -- there is nothing to compare
/// against, mirroring `unix_mode_already_matches_disk`'s own
/// `unix_mode: None` treatment.
#[test]
fn mtime_already_matches_disk_is_trivially_true_for_a_negative_sentinel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    fs::write(&path, b"content").unwrap();
    assert!(mtime_already_matches_disk(&path, -1).unwrap());
}

/// Changing the requested mode actually changes the on-disk permission
/// bits, and is idempotent (calling it again with the same value
/// doesn't error or otherwise misbehave). `None` is a deliberate no-op
/// — never fabricates a mode for a version that carries none.
#[cfg(unix)]
#[test]
fn apply_unix_mode_sets_and_clears_permission_bits() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("script.sh");
    fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    apply_unix_mode(&path, Some(0o744)).unwrap();
    let mode_after_set = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode_after_set & 0o777, 0o744, "owner-exec bit must be set");

    // Idempotent: setting it again when already set is a harmless no-op.
    apply_unix_mode(&path, Some(0o744)).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o744);

    apply_unix_mode(&path, Some(0o644)).unwrap();
    let mode_after_clear = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode_after_clear & 0o777, 0o644, "owner-exec bit must be cleared");

    // `None` is a no-op — the mode from the last real apply survives.
    apply_unix_mode(&path, None).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
}

/// `apply_unix_mode` must never error on a plain file — this
/// runs unconditionally (not `#[cfg(unix)]`-gated) so the non-Unix
/// no-op arm is at least compiled and exercised on every platform this
/// crate builds for; on this dev machine it's the `#[cfg(unix)]`-arm's
/// real permission-changing behavior above that's exercised.
#[test]
fn apply_unix_mode_never_errors_on_a_plain_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.txt");
    fs::write(&path, b"hello").unwrap();
    apply_unix_mode(&path, Some(0o755)).unwrap();
    apply_unix_mode(&path, None).unwrap();
}

/// `create_dir_all(parent)` follows symlinks like any other `mkdir`
/// chain, so a symlink planted at an intermediate component (`escape ->
/// outside`) would let a naive directory-creation step create real
/// directories on the far side of it, entirely outside the sync root, before the `canonicalize`+
/// `starts_with` check that runs after it could ever refuse the
/// write. The `Err` result alone (already covered by
/// `materialize_symlink_at_refuses_a_root_whose_marker_no_longer_
/// matches`-style tests elsewhere) is not enough to prove this --
/// the whole point is that side effects outside the root must never
/// happen at all, error or not.
#[cfg(unix)]
#[test]
fn verify_write_target_within_root_creates_no_directories_through_an_escape_symlink() {
    let sync_root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), sync_root.path().join("escape")).unwrap();

    let out_path = sync_root.path().join("escape").join("a").join("b").join("pwned.txt");
    let result =
        verify_write_target_within_root(&out_path, sync_root.path(), &RecordingLedger::default());

    assert!(result.is_err(), "a write target reached only through a symlink must be refused");
    assert!(
        !outside.path().join("a").exists(),
        "no directory must ever be created on the far side of the escape symlink, \
         regardless of whether the write itself is correctly refused"
    );
}

/// The non-escaping case must keep working exactly as before: nested
/// directories that genuinely need creating under the real root are
/// still created, component by component, with no regression from
/// the old single `create_dir_all` call.
#[test]
fn verify_write_target_within_root_still_creates_genuine_nested_directories() {
    let sync_root = tempfile::tempdir().unwrap();
    let out_path = sync_root.path().join("a").join("b").join("c").join("file.txt");

    verify_write_target_within_root(&out_path, sync_root.path(), &RecordingLedger::default())
        .unwrap();

    assert!(sync_root.path().join("a").join("b").join("c").is_dir());
}

/// `apply_xattrs` must both set every attribute in the supplied list
/// AND remove any `user.*` attribute already on disk that the list no
/// longer carries -- the same "set exactly what's replicated, nothing
/// left over from a prior version" contract `apply_unix_mode` gives
/// for permission bits.
#[cfg(target_os = "linux")]
#[test]
fn apply_xattrs_sets_new_attributes_and_removes_stale_ones() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.keep".to_string(), b"v1".to_vec())]).unwrap();
    assert_eq!(
        crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()),
        vec![("user.keep".to_string(), b"v1".to_vec())]
    );

    // A later version drops "user.keep" and adds "user.new" -- the
    // stale attribute must not survive the second call.
    apply_xattrs(&path, &[("user.new".to_string(), b"v2".to_vec())]).unwrap();
    assert_eq!(
        crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()),
        vec![("user.new".to_string(), b"v2".to_vec())]
    );
}

/// An empty attribute list is a real, meaningful target state (this
/// version genuinely carries no extended attributes) -- confirms it
/// clears whatever was already on disk rather than being silently
/// treated as "nothing to do."
#[cfg(target_os = "linux")]
#[test]
fn apply_xattrs_with_an_empty_list_clears_existing_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.gone".to_string(), b"v".to_vec())]).unwrap();
    apply_xattrs(&path, &[]).unwrap();

    assert_eq!(crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()), Vec::new());
}

/// Regression: `apply_xattrs`'s removal side and its set side both
/// restrict themselves to `user.*`, rather than handing every incoming
/// name straight to `fsetxattr` -- defense-in-depth for the same
/// allow-list `FileMeta::decode` rejects a violation of at the wire-decode
/// boundary (a second, independent layer, in case some future caller
/// ever builds an `xattrs` list some other way). Confirmed genuinely
/// RED by temporarily hardcoding this to `true` for every name: it no
/// longer distinguished the allow-listed namespace from any other.
#[cfg(target_os = "linux")]
#[test]
fn is_replicated_xattr_name_only_accepts_the_user_namespace() {
    assert!(is_replicated_xattr_name("user.foo"));
    assert!(!is_replicated_xattr_name("security.selinux"));
    assert!(!is_replicated_xattr_name("trusted.overlay"));
    assert!(!is_replicated_xattr_name("system.posix_acl_access"));
    assert!(!is_replicated_xattr_name("com.apple.quarantine"));
}

/// The `ExactObject` proof gate's positive case: an attribute set
/// genuinely applied end to end verifies as an exact match.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_confirms_a_genuine_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    let desired = vec![("user.a".to_string(), b"1".to_vec())];

    apply_xattrs(&path, &desired).unwrap();

    assert!(verify_replicated_xattrs_exact(&path, &desired).unwrap());
}

/// Regression: a desired attribute that never actually landed on disk (standing in
/// for `apply_xattrs`'s own `fsetxattr` silently failing, which it
/// never surfaces as an `Err`) must never verify as an exact match.
/// Confirmed genuinely RED by temporarily hardcoding this function's
/// comparison to `true`: the mismatch below went undetected.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_detects_an_attribute_that_never_landed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    let desired = vec![("user.missing".to_string(), b"1".to_vec())];

    // No `apply_xattrs` call at all -- disk carries none of what is
    // desired, exactly what a silently-swallowed `fsetxattr` failure
    // would also leave behind.

    assert!(!verify_replicated_xattrs_exact(&path, &desired).unwrap());
}

/// The mirror case: a stale attribute still on disk that the desired
/// version no longer carries (standing in for `apply_xattrs`'s
/// `fremovexattr` silently failing) must also never verify as exact.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_detects_a_stale_attribute_that_should_be_gone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.stale".to_string(), b"v".to_vec())]).unwrap();
    // The version this file is meant to now exactly hold desires no
    // attributes at all -- as if `apply_xattrs(&path, &[])`'s own
    // `fremovexattr` call for "user.stale" had silently failed.

    assert!(!verify_replicated_xattrs_exact(&path, &[]).unwrap());
}

/// A same-name attribute whose VALUE differs must also fail exactness
/// -- name-only comparison would wrongly accept this.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_detects_a_value_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.a".to_string(), b"old".to_vec())]).unwrap();

    assert!(
        !verify_replicated_xattrs_exact(&path, &[("user.a".to_string(), b"new".to_vec())]).unwrap()
    );
}

/// The proof gate fails closed where the best-effort reader does not:
/// a file whose attribute listing succeeds but whose attribute read is
/// refused. The best-effort reader drops the attribute it could not
/// read, so a version that carries no attributes would compare equal to
/// a file that really does carry one; the strict comparison must be an
/// `Err` instead, never a match.
///
/// Listing a file's attribute names needs no permission on the file,
/// but reading a `user.` attribute's value needs read permission, so a
/// write-only descriptor on a mode 0o200 file reaches exactly that state
/// deterministically. The path-based `verify_replicated_xattrs_exact`
/// opens read-only and so cannot be driven there; the comparison it
/// delegates to is tested directly. A process that ignores file
/// permissions (root) cannot be refused the read, so the test has
/// nothing to check there and returns early.
#[cfg(target_os = "linux")]
#[test]
fn the_exact_xattr_comparison_fails_closed_where_the_best_effort_reader_sees_no_attributes() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    apply_xattrs(&path, &[("user.present".to_string(), b"v".to_vec())]).unwrap();
    assert!(verify_replicated_xattrs_exact(&path, &[("user.present".to_string(), b"v".to_vec())])
        .unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
    if fs::File::open(&path).is_ok() {
        // Permissions are not enforced for this process: nothing to test.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let write_only = fs::OpenOptions::new().write(true).open(&path).unwrap();

    let best_effort = crate::chunker::read_replicated_xattrs(&write_only);
    let strict = replicated_xattrs_exactly_match(&write_only, &[]);

    drop(write_only);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        best_effort.is_empty(),
        "precondition: the best-effort reader drops the attribute it cannot read: {best_effort:?}"
    );
    assert!(
        strict.is_err(),
        "an attribute set that could not be read must not compare as a match: {strict:?}"
    );
}

// The non-Linux `verify_replicated_xattrs_exact` arm (always
// `Ok(true)`, unconditionally treating xattrs as retained-only on a
// backend with no replicated-xattr support -- see its own doc
// comment for the target-projection-contract reasoning) is `#[cfg(not(
// target_os = "linux"))]`, so it never compiles on the Linux machines
// this workspace is actually developed/tested on and has no dedicated
// test here; it is now a single unconditional return with no branch
// left to exercise.

/// A replicated mode that takes the owner's read (or write) permission
/// away must not stop the replicated attributes from landing: the
/// attributes are applied while the file still has the mode it was
/// written with, and the mode last. Applying the mode first made
/// `apply_xattrs` fail with EACCES on a `0o200` file.
#[cfg(target_os = "linux")]
#[test]
fn apply_file_metadata_sets_attributes_even_when_the_mode_revokes_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    let xattrs = vec![("user.keep".to_string(), b"v1".to_vec())];

    apply_file_metadata(&path, Some(0o200), &xattrs).unwrap();

    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o200);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()), xattrs);
}

/// `xattrs_already_match_disk` only chooses between a snapshot and a
/// mutating attempt, so a file whose mode denies its owner read access is
/// "not known to match" -- never a hard error that stops the caller.
#[cfg(target_os = "linux")]
#[test]
fn xattrs_already_match_disk_reports_an_unreadable_file_as_not_matching() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();

    let result = xattrs_already_match_disk(&path, &[]);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(result, Ok(false)), "got {result:?}");
}
