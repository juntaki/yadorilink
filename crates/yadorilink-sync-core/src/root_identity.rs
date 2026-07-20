//! Sync-root identity: proving that the directory a scan is about to treat as
//! authoritative really is the folder this link was established against.
//!
//! The failure this exists to prevent: a sync root that lives on a removable or
//! network volume, unmounted. On every mainstream platform the mountpoint is an
//! ordinary directory that *survives* the unmount, so every existence check
//! (`Path::exists`, `fs::metadata`, even `canonicalize`) still succeeds and the
//! scanner walks a bare, empty directory. A full scan is authoritative by
//! design, so every indexed file then looks deleted and those deletions
//! propagate as tombstones to every other device. Unplugging a drive silently
//! destroys the folder everywhere. An existence check cannot see this, because
//! the thing that vanished is the *filesystem*, not the path.
//!
//! The guard is a marker file ([`ROOT_MARKER_FILE_NAME`]) written inside the
//! root, naming the group and an opaque per-link `root_token` that is also
//! persisted in the local `links` table. The marker rides on the same
//! filesystem as the content, so it disappears exactly when the content does: a
//! bare mountpoint has no marker, the token cannot be corroborated, and the
//! check fails closed.
//!
//! THE MARKER IS THE AUTHORITY — deliberately, in preference to a filesystem
//! identity such as `st_dev`. A device number is neither portable across
//! platforms nor stable across remounts: a USB volume routinely gets a
//! different `st_dev` on each plug, so an `st_dev` check would reject the very
//! folder it is meant to protect, on the ordinary happy path. It is recorded in
//! the marker as a human diagnostic for bug reports and is never compared —
//! see [`RootMarker::st_dev_hint`].
//!
//! `root_token` is an opaque identity nonce, never a digest of the folder's
//! contents or paths. It answers "is this the same folder I adopted?", a
//! question whose answer must stay `true` across every legitimate edit to that
//! folder — so binding it to content would make it self-invalidating. It is
//! orthogonal to exact-version binding (`change::VersionHash`), which is the
//! construct for "are these the same bytes".

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::SyncError;
use crate::index::SyncState;
use crate::materialization::disk_bytes_match_indexed_blocks;
use crate::types::{FileRecord, MaterializationState, RecordKind};

/// The marker file's name, at the top level of a sync root. Excluded from sync
/// (see `local_change::is_excluded_from_sync`) so it is never indexed, never
/// transmitted, and can never spawn a conflicted copy: each device mints its
/// own token, so a synced marker would overwrite a peer's identity with ours —
/// the exact confusion this module exists to detect.
pub const ROOT_MARKER_FILE_NAME: &str = ".yadorilink-root";

/// Written into every marker so a user who finds this file in their folder can
/// tell what it is and why deleting it is not harmless.
const MARKER_COMMENT: &str = concat!(
    "YadoriLink sync-root marker. Identifies this folder to YadoriLink so that an unmounted ",
    "or replaced volume is not mistaken for a folder whose files you deleted. ",
    "Do not edit, move, or delete it.",
);

/// True for exactly `<root>/.yadorilink-root` and nothing else. A
/// `.yadorilink-root` nested in a subdirectory is ordinary user content and
/// syncs normally — only the root-level marker is this module's, mirroring
/// `ignore_patterns::is_ignore_file_relative_path`'s identical top-level-only
/// rule for `.yadorilinkignore`.
///
/// Allocation-free: this runs once per directory entry on the scan's walk, so
/// it is a hot path and must not build a `Vec` to answer a question about at
/// most one path segment.
pub fn is_root_marker_relative_path(relative_path: impl AsRef<Path>) -> bool {
    let mut segments =
        relative_path.as_ref().components().filter(|c| !matches!(c, Component::CurDir));
    match (segments.next(), segments.next()) {
        // Exactly one segment, and it is the marker. Anything with a second
        // segment is nested; anything non-`Normal` (`..`, a root, a Windows
        // prefix) is not a plain top-level name and so is not the marker.
        (Some(Component::Normal(only)), None) => {
            only == std::ffi::OsStr::new(ROOT_MARKER_FILE_NAME)
        }
        _ => false,
    }
}

/// The on-disk marker. Plain JSON, and deliberately human-legible: a user who
/// opens it should be able to see what it is without tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootMarker {
    /// Explanatory text for a human reader only. `default`ed on read so an
    /// older or hand-trimmed marker still parses — it carries no identity and
    /// is never compared.
    #[serde(default, rename = "_comment")]
    comment: String,
    group_id: String,
    root_token: String,
    /// The `st_dev` of the root when the marker was written, on Unix. A
    /// **diagnostic hint only** — never read back for the identity check, and
    /// deliberately so: see this module's doc comment on why a device number
    /// changes across ordinary remounts. It exists to make "which volume was
    /// this folder on when it was adopted?" answerable from a bug report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    st_dev_hint: Option<u64>,
}

/// A sync root whose identity has been verified against this link's persisted
/// `root_token`. Holding one is proof the check ran and passed.
///
/// The field is private on purpose: that is the anti-recurrence guard. The bug
/// this type exists to close has recurred along independent code paths (the
/// disk scan and the interrupted-materialization repair each grew their own
/// root check, and each checked only existence). Making the *type* — not a call
/// at each site — carry the guarantee means a future scan entry point cannot
/// forget it: there is no way to name a root to those functions without
/// producing one of these first.
///
/// The guarantee every constructor must uphold, and which any constructor added
/// later inherits as a requirement rather than an option:
///
/// 1. `ensure_single_root` — the group has at most one live link. A group with
///    two live roots has no answerable "which folder is this?", and guessing
///    tombstones the other root's files on every device.
/// 2. The marker check — this really is that link's folder, not a bare
///    mountpoint or another device's copy.
///
/// Both, in that order, before anything is written. A constructor that skips
/// either is not a `VerifiedRoot` constructor; it is the bug wearing the type.
/// Do not add a `from_path`/`new_unchecked` escape hatch; a caller that
/// genuinely means "re-establish this folder's identity" wants
/// [`VerifiedRoot::readopt`], which still ends in the same checked constructor.
#[derive(Debug, Clone)]
pub struct VerifiedRoot {
    /// Canonical. Callers relativize walked entries against this, so it must be
    /// the same resolution `process_event` performs internally or every
    /// `strip_prefix` silently fails.
    path: PathBuf,
}

/// What the index says about a root that carries no marker — the input to the
/// adoption decision below.
enum AdoptionEvidence {
    /// Every indexed, live path is present on disk.
    Corroborated,
    /// The index has live rows and at least one is absent. A partially reused
    /// bare mountpoint and a genuine local deletion are indistinguishable.
    IndexedFilesAllMissing,
    /// The index has no live rows: a first link, or a group whose every file is
    /// already a tombstone. Nothing can be lost by adopting.
    IndexEmpty,
}

impl VerifiedRoot {
    /// Verify an already-adopted root without changing either disk or index.
    /// Peer-driven writes must use this path: unlike [`Self::open`], it never
    /// creates a marker and never backfills a missing token, so an unmounted or
    /// replaced folder cannot be silently adopted merely because a peer had
    /// data to write into it.
    pub fn verify(root: &Path, group_id: &str, state: &SyncState) -> Result<Self, SyncError> {
        let path = root.canonicalize()?;
        ensure_single_root(group_id, state)?;
        let persisted = state.link_root_token_for_group(group_id)?.ok_or_else(|| {
            root_identity_mismatch(&path, group_id, "the link has no previously-adopted root token")
        })?;
        let marker = read_marker(&path)?.ok_or_else(|| {
            root_identity_mismatch(&path, group_id, "the folder has no root identity marker")
        })?;
        if marker.group_id != group_id {
            return Err(root_identity_mismatch(
                &path,
                group_id,
                &format!("it carries the marker of group {}", marker.group_id),
            ));
        }
        if marker.root_token != persisted {
            return Err(root_identity_mismatch(
                &path,
                group_id,
                "its marker's root token is not the one this link adopted",
            ));
        }
        Ok(Self { path })
    }

    /// Canonicalize `root`, then prove it is this group's folder by matching the
    /// marker it carries against the `root_token` persisted for the link.
    ///
    /// Fails closed. `Err` means "this scan's view of the folder is not
    /// authoritative", never "the folder is empty" — the whole point is that
    /// those two are indistinguishable by inspection, so the ambiguous case must
    /// not resolve to the destructive one.
    ///
    /// Adoption (see this type's `open` body) is what makes the check
    /// deployable on an existing install, where no link has a marker yet.
    pub fn open(root: &Path, group_id: &str, state: &SyncState) -> Result<Self, SyncError> {
        // A root that cannot be canonicalized is absent or unreadable. This
        // subsumes the scan's former bare `root.canonicalize()?` guard, which
        // caught the root-*removed* case; the marker check below is what
        // additionally catches the root-*emptied* case that guard could not see.
        let path = root.canonicalize()?;
        // Before the token lookup, and before the adoption dispatch below: both
        // of those WRITE. `adopt_unmarked_root` reuses the token already
        // persisted for the group, so on an ambiguous group it would stamp the
        // FIRST root's token into the SECOND root's marker — after which both
        // folders verify successfully, forever, and their mutual tombstoning is
        // permanent and invisible. Refusing here is what keeps that from being
        // laundered into a "valid" state.
        ensure_single_root(group_id, state)?;
        let persisted = state.link_root_token_for_group(group_id)?;

        let Some(marker) = read_marker(&path)? else {
            return Self::adopt_unmarked_root(path, group_id, state, persisted);
        };

        // A marker for a different group means this path is some *other* link's
        // root — a mount landed in the wrong place, or two links were swapped.
        // Refuse regardless of what the index says.
        if marker.group_id != group_id {
            return Err(root_identity_mismatch(
                &path,
                group_id,
                &format!("it carries the marker of group {}", marker.group_id),
            ));
        }
        match persisted {
            Some(token) if token != marker.root_token => Err(root_identity_mismatch(
                &path,
                group_id,
                "its marker's root token is not the one this link adopted, so this is a \
                 different folder for the same group (a restored backup, a re-created folder, \
                 or another device's copy)",
            )),
            Some(_) => Ok(Self { path }),
            // A marker with nothing persisted to check it against: the token
            // column was added after this link was created, or a previous
            // adoption wrote the marker and was killed before committing the
            // row. Trust the marker (it is the authority) and backfill, so the
            // next open verifies the pair fully.
            None => {
                state.set_link_root_token_for_group(group_id, &marker.root_token)?;
                Ok(Self { path })
            }
        }
    }

    /// Re-establish this folder's identity: mint a fresh token, write the
    /// marker, and verify. This is the deliberate, explicit way past a refusal —
    /// including the legitimate "I really did delete every file in this folder"
    /// case, which is otherwise indistinguishable from an unmounted volume and
    /// so is refused by [`VerifiedRoot::open`].
    ///
    /// Not an escape hatch from the check: it *changes the persisted state* so
    /// the check passes, then runs the check. It must only ever be reached from
    /// an explicit user action, never from a scan, a repair, or a retry — an
    /// automatic caller would re-adopt the bare mountpoint and reintroduce the
    /// whole-folder loss this module prevents.
    pub fn readopt(root: &Path, group_id: &str, state: &SyncState) -> Result<Self, SyncError> {
        // At the very top: everything below this line mutates. Minting, writing
        // the marker and persisting the token all happen BEFORE the `Self::open`
        // that would otherwise catch an ambiguous group, so relying on `open`'s
        // check alone would fan a fresh token onto BOTH of the group's rows and
        // only then refuse — deepening the exact state it means to reject.
        ensure_single_root(group_id, state)?;
        let path = root.canonicalize()?;
        let token = mint_root_token();
        write_marker(&path, group_id, &token)?;
        state.set_link_root_token_for_group(group_id, &token)?;
        Self::open(root, group_id, state)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The upgrade/backfill path: a root with no marker. Every link on an
    /// existing install starts here exactly once, so a naive fail-closed rule
    /// would break every install on upgrade — but blanket-adopting would equally
    /// happily adopt a bare mountpoint and re-arm the bug. The index is the
    /// tiebreaker: adopt only when the folder on disk corroborates what we
    /// already believe is in it.
    ///
    /// Two cheaper-looking discriminators are deliberately NOT used here, and
    /// both are traps a future reader will otherwise re-derive and get wrong:
    ///
    /// - **`st_dev` / "is this still a mountpoint?"** cannot be the check. A
    ///   device number is not stable across remounts (a USB volume gets a fresh
    ///   one on each plug), so comparing it rejects the healthy folder. Nor can
    ///   the weaker "the root is not a mountpoint, so it is ordinary local
    ///   storage, so adopt" work — after a disconnect the bare mountpoint is
    ///   exactly a plain directory on the parent filesystem and is no longer a
    ///   mountpoint. That rule fires *precisely* in the disconnect case it is
    ///   meant to exclude.
    ///
    /// - **An open materialization intent** cannot vouch for the root either.
    ///   Intents live in SQLite on the system disk, not on the sync volume, so
    ///   they survive an unmount exactly as they survive a crash and carry zero
    ///   signal about whether the volume is present. Worse, letting one
    ///   intent-bearing path vouch for the root would then bless the bare
    ///   mountpoint for every OTHER indexed file — all of them absent because
    ///   unmounted, and intent-free — and the scan that follows would tombstone
    ///   the lot. That trades a recoverable stall for the whole-folder loss this
    ///   module exists to prevent.
    ///
    /// What is left is the on-disk evidence. Every live indexed row must still
    /// be present before an unmarked root can be adopted automatically. A
    /// single survivor is not sufficient corroboration: it can be an unrelated
    /// file in a reused mountpoint while the actual volume is absent.
    fn adopt_unmarked_root(
        path: PathBuf,
        group_id: &str,
        state: &SyncState,
        persisted: Option<String>,
    ) -> Result<Self, SyncError> {
        match adoption_evidence(&path, group_id, state)? {
            AdoptionEvidence::Corroborated | AdoptionEvidence::IndexEmpty => {}
            AdoptionEvidence::IndexedFilesAllMissing => {
                return Err(root_identity_mismatch(
                    &path,
                    group_id,
                    "it has no sync-root marker, and not every one of this folder's known files is \
                     present in it. Two different situations look identical from here: the \
                     folder's storage may not be mounted (an unmounted volume leaves its \
                     mountpoint behind as an empty directory), or the files may never have been \
                     written to this device. Syncing either one would delete this folder's \
                     contents on every device, so it is left untouched until the situation is \
                     confirmed. If the storage should be connected, connect it and retry. If \
                     this folder really is meant to be empty, re-adopt it explicitly to confirm \
                     that, which will then propagate the deletions",
                ));
            }
        }
        // Reuse the persisted token when there is one: the marker was lost from
        // an otherwise-healthy folder (e.g. a user cleaned it out), so
        // re-minting would gratuitously invalidate a token other state may
        // already reference.
        let token = persisted.unwrap_or_else(mint_root_token);
        write_marker(&path, group_id, &token)?;
        state.set_link_root_token_for_group(group_id, &token)?;
        Ok(Self { path })
    }
}

/// Refuses a group that has more than one live link, before any constructor
/// touches disk or the index.
///
/// Shared free function called EXPLICITLY from every `VerifiedRoot`
/// constructor, rather than left to happen transitively via whichever token
/// lookup each one performs. Coverage that rides on a constructor incidentally
/// calling a hardened reader is coverage by coincidence: it silently lapses the
/// moment a constructor is reordered or a new one is added. A named call at the
/// top of each constructor is what a future constructor's author has to
/// deliberately delete.
///
/// This is the gate that stops the dominant harm. `reconcile_disk_with_ignore`
/// takes a `&VerifiedRoot`, the tombstone-emitting loop lives inside it, and
/// this type's field is private — so no `VerifiedRoot` means no tombstones, by
/// type rather than by discipline.
fn ensure_single_root(group_id: &str, state: &SyncState) -> Result<(), SyncError> {
    state.ensure_unambiguous_group(group_id)
}

/// Single pass over the index. Automatic adoption is intentionally strict:
/// every live indexed path must be present on disk.
fn adoption_evidence(
    root: &Path,
    group_id: &str,
    state: &SyncState,
) -> Result<AdoptionEvidence, SyncError> {
    let mut has_live_rows = false;
    for record in state.list_files(group_id)? {
        if record.deleted {
            continue;
        }
        has_live_rows = true;
        if !indexed_path_is_corroborated(root, group_id, state, &record)? {
            return Ok(AdoptionEvidence::IndexedFilesAllMissing);
        }
    }
    Ok(if has_live_rows { AdoptionEvidence::Corroborated } else { AdoptionEvidence::IndexEmpty })
}

/// Returns true only when one live index row is represented by the same kind
/// and content on disk. Duplicate-root recovery uses the identical predicate
/// as automatic root adoption so mere path existence cannot disarm deletion
/// suppression.
pub fn indexed_path_is_corroborated(
    root: &Path,
    group_id: &str,
    state: &SyncState,
    record: &FileRecord,
) -> Result<bool, SyncError> {
    let disk_path = root.join(&record.path);
    // `symlink_metadata`, not `metadata`: never follow an attacker-swapped
    // symlink while deciding whether this is the authoritative root.
    let Ok(metadata) = disk_path.symlink_metadata() else {
        return Ok(false);
    };
    let kind = state.get_record_kind(group_id, &record.path)?.unwrap_or_default();
    Ok(match kind {
        RecordKind::Directory => metadata.file_type().is_dir(),
        RecordKind::Symlink => {
            metadata.file_type().is_symlink()
                && std::fs::read_link(&disk_path)
                    .ok()
                    .map(|target| target.to_string_lossy().to_string())
                    == state.get_symlink_target(group_id, &record.path)?
        }
        RecordKind::File => {
            if !metadata.file_type().is_file() {
                false
            } else {
                match state.get_materialization_state(group_id, &record.path)? {
                    Some(MaterializationState::Placeholder) => metadata.len() == record.size,
                    Some(MaterializationState::Hydrating)
                    | Some(MaterializationState::Evicting) => false,
                    _ => {
                        metadata.len() == record.size
                            && disk_bytes_match_indexed_blocks(&disk_path, &record.blocks)?
                    }
                }
            }
        }
    })
}

/// An opaque 256-bit nonce. Not derived from the path, the group, the device,
/// or the folder's contents: two folders that agree on all of those must still
/// get different tokens, since telling such folders apart (a restored backup, a
/// duplicated copy) is exactly what the token is for.
fn mint_root_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    hex::encode(bytes)
}

/// `Ok(None)` only for a marker that is genuinely absent. Every other outcome —
/// unreadable, truncated, malformed JSON — is an `Err`: a marker we cannot read
/// is not a marker we can say matches, and this check exists precisely to not
/// resolve ambiguity in the destructive direction.
fn read_marker(root: &Path) -> Result<Option<RootMarker>, SyncError> {
    match std::fs::read(root.join(ROOT_MARKER_FILE_NAME)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A plain (non-atomic) write: the marker is a single small buffer, and the
/// failure mode of a torn write is a malformed marker, which `read_marker`
/// fails closed on. Deliberately not written via a temp file + rename — the
/// link root is swept for stale temp files on startup
/// (`materialization::cleanup_stale_temp_files`), and a marker in flight is
/// exactly the kind of thing that sweep would race.
fn write_marker(root: &Path, group_id: &str, root_token: &str) -> Result<(), SyncError> {
    let marker = RootMarker {
        comment: MARKER_COMMENT.to_string(),
        group_id: group_id.to_string(),
        root_token: root_token.to_string(),
        st_dev_hint: st_dev_hint(root),
    };
    let bytes = serde_json::to_vec_pretty(&marker)?;
    std::fs::write(root.join(ROOT_MARKER_FILE_NAME), bytes)?;
    Ok(())
}

/// Writes a marker through the REAL writer, for tests that need a root already
/// carrying a given identity (notably the already-duplicated "two rows, one
/// token" state, which is what the pre-fix by-`group_id` token writer produced
/// and where the read-side gate is the only remaining protection).
///
/// Deliberately routed through `write_marker` rather than letting each test
/// hand-roll the JSON: a test that writes its own marker format silently stops
/// exercising the real one the moment the struct changes, and this marker's
/// whole job is to be read back by `read_marker`.
#[cfg(any(test, feature = "test-support"))]
pub fn write_root_marker_for_test(root: &Path, group_id: &str, root_token: &str) {
    write_marker(root, group_id, root_token).expect("test setup: writing a root marker");
}

/// Diagnostic only — see [`RootMarker::st_dev_hint`]. Never fails the write: a
/// hint we could not collect is simply absent.
fn st_dev_hint(root: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(root).ok().map(|m| m.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        None
    }
}

/// `InvalidInput` rather than a dedicated variant: the root path handed to the
/// operation is the thing that is wrong, and it is rejected before any state is
/// written — which is that variant's documented contract. It is deliberately
/// NOT `Io`/`NotFound`: those read as "transient, retry", and a caller that
/// retries this condition retries it against the same wrong folder forever.
fn root_identity_mismatch(root: &Path, group_id: &str, why: &str) -> SyncError {
    SyncError::InvalidInput(format!(
        "refusing to treat {root:?} as the sync root for group {group_id}: {why}. No file was \
         indexed and no deletion was emitted"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileRecord;
    use crate::version_vector::VersionVector;

    /// A registered link is the production shape, and the token column lives on
    /// that row — without one there is nothing to persist a token *to*, so a
    /// test that skipped this would silently only exercise the marker half of
    /// the check.
    fn linked_state(root: &Path, group_id: &str) -> SyncState {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link(&root.to_string_lossy(), group_id).unwrap();
        state
    }

    /// The marker is top-level-only, exactly like `.yadorilinkignore`: a
    /// same-named file a user keeps inside a subdirectory is their content and
    /// must keep syncing.
    #[test]
    fn only_the_top_level_marker_is_recognized() {
        assert!(is_root_marker_relative_path(".yadorilink-root"));
        assert!(is_root_marker_relative_path("./.yadorilink-root"));
        assert!(!is_root_marker_relative_path("nested/.yadorilink-root"));
        assert!(!is_root_marker_relative_path(".yadorilink-root/inner.txt"));
        assert!(!is_root_marker_relative_path("notes.txt"));
    }

    /// A fresh link (empty index, empty folder) adopts: there is nothing to
    /// lose, and this is how every new link acquires its identity.
    #[test]
    fn a_fresh_empty_root_is_adopted_and_marked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = linked_state(&root, "group-1");

        let verified = VerifiedRoot::open(&root, "group-1", &state).unwrap();

        assert_eq!(verified.path(), root);
        assert!(root.join(ROOT_MARKER_FILE_NAME).exists(), "adoption must leave a marker");
        assert!(
            state.link_root_token_for_group("group-1").unwrap().is_some(),
            "adoption must persist the token it wrote into the marker"
        );
    }

    #[test]
    fn one_surviving_indexed_file_does_not_adopt_an_unmarked_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = linked_state(&root, "group-1");
        let record = |path: &str| FileRecord {
            path: path.into(),
            size: 1,
            mtime_unix_nanos: 1,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        };
        state.upsert_file("group-1", &record("survivor.txt")).unwrap();
        state.upsert_file("group-1", &record("missing.txt")).unwrap();
        std::fs::write(root.join("survivor.txt"), b"x").unwrap();

        assert!(VerifiedRoot::open(&root, "group-1", &state).is_err());
        assert!(!root.join(ROOT_MARKER_FILE_NAME).exists());
    }

    /// The token is an identity nonce, not a derivation: two folders alike in
    /// every visible respect must still be distinguishable.
    #[test]
    fn each_adoption_mints_a_distinct_token() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let root_a = dir_a.path().canonicalize().unwrap();
        let root_b = dir_b.path().canonicalize().unwrap();
        let state_a = linked_state(&root_a, "group-1");
        let state_b = linked_state(&root_b, "group-1");
        VerifiedRoot::open(&root_a, "group-1", &state_a).unwrap();
        VerifiedRoot::open(&root_b, "group-1", &state_b).unwrap();

        assert_ne!(
            state_a.link_root_token_for_group("group-1").unwrap(),
            state_b.link_root_token_for_group("group-1").unwrap()
        );
    }

    /// Re-opening an already-adopted root is the steady state and must be
    /// stable — in particular it must not re-mint, which would make the token
    /// meaningless.
    #[test]
    fn reopening_an_adopted_root_keeps_its_token() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = linked_state(&root, "group-1");
        VerifiedRoot::open(&root, "group-1", &state).unwrap();
        let first = state.link_root_token_for_group("group-1").unwrap();
        assert!(first.is_some(), "adoption must have persisted a token to re-check against");

        VerifiedRoot::open(&root, "group-1", &state).unwrap();

        assert_eq!(first, state.link_root_token_for_group("group-1").unwrap());
    }

    /// A marker naming another group means the mount landed in the wrong place.
    #[test]
    fn a_marker_for_another_group_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = linked_state(&root, "group-1");
        write_marker(&root, "someone-elses-group", "aa").unwrap();

        let err = VerifiedRoot::open(&root, "group-1", &state).unwrap_err();

        assert!(matches!(err, SyncError::InvalidInput(_)), "got {err:?}");
    }

    /// A corrupt marker must fail closed, not fall through to the
    /// "no marker, adopt me" path — that would let a single truncated byte
    /// re-arm the bug.
    #[test]
    fn an_unparsable_marker_is_an_error_not_an_absent_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = linked_state(&root, "group-1");
        std::fs::write(root.join(ROOT_MARKER_FILE_NAME), b"{ this is not json").unwrap();

        assert!(VerifiedRoot::open(&root, "group-1", &state).is_err());
    }

    /// The explicit way past a refusal. `readopt` is the only thing that may
    /// re-establish identity, and it must actually work — otherwise a user
    /// whose folder legitimately emptied is stuck forever.
    #[test]
    fn readopt_replaces_the_token_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = linked_state(&root, "group-1");
        VerifiedRoot::open(&root, "group-1", &state).unwrap();
        let original = state.link_root_token_for_group("group-1").unwrap();
        assert!(original.is_some(), "the folder must be adopted before it can be re-adopted");

        VerifiedRoot::readopt(&root, "group-1", &state).unwrap();
        let readopted = state.link_root_token_for_group("group-1").unwrap();

        assert_ne!(original, readopted, "re-adoption must mint a new identity");
        assert!(
            VerifiedRoot::open(&root, "group-1", &state).is_ok(),
            "the folder must verify cleanly afterwards"
        );
    }

    /// A root that does not exist at all still errors — the pre-existing guard
    /// this module subsumed, kept honest.
    #[test]
    fn a_missing_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created");
        let state = linked_state(&missing, "group-1");

        assert!(VerifiedRoot::open(&missing, "group-1", &state).is_err());
    }

    // --- One live link per group -------------------------------------------

    /// The gate must refuse BEFORE the adoption dispatch, which writes. A check
    /// placed after it would let `adopt_unmarked_root` write a marker and stamp
    /// the row first.
    #[test]
    fn verified_root_open_refuses_before_writing_anything() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let state = linked_state(a.path(), "group-1");
        state.force_second_live_link_for_test(&b.path().to_string_lossy(), "group-1").unwrap();

        let err = VerifiedRoot::open(a.path(), "group-1", &state)
            .expect_err("an ambiguous group must not produce a VerifiedRoot");
        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");

        assert!(
            !a.path().join(ROOT_MARKER_FILE_NAME).exists(),
            "the refusal must not have written a marker into either folder"
        );
        assert!(!b.path().join(ROOT_MARKER_FILE_NAME).exists());
        assert_eq!(
            state.link_root_tokens_for_group_unchecked_for_test("group-1").unwrap(),
            vec![None, None],
            "the refusal must not have stamped a token onto either row"
        );
    }

    /// The laundering mechanism: `adopt_unmarked_root` reuses the token already
    /// persisted for the group, so the SECOND root would write the FIRST root's
    /// token into its own marker -- after which BOTH folders verify
    /// successfully, forever, and their mutual tombstoning is permanent and
    /// invisible.
    #[test]
    fn adopt_does_not_launder_a_second_root_with_the_first_roots_token() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let state = linked_state(a.path(), "group-1");
        VerifiedRoot::open(a.path(), "group-1", &state).unwrap();
        assert!(a.path().join(ROOT_MARKER_FILE_NAME).exists(), "A adopts normally");

        state.force_second_live_link_for_test(&b.path().to_string_lossy(), "group-1").unwrap();

        let err = VerifiedRoot::open(b.path(), "group-1", &state)
            .expect_err("the second root must not adopt");
        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");
        assert!(
            !b.path().join(ROOT_MARKER_FILE_NAME).exists(),
            "B must not be handed A's token: with it, both roots verify forever"
        );
    }

    /// `readopt` mints, writes the marker and persists the token all BEFORE the
    /// `Self::open` that would catch the ambiguity -- so a check only in `open`
    /// fans a fresh token onto both rows and only then refuses.
    #[test]
    fn readopt_refuses_without_minting_or_stamping() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let state = linked_state(a.path(), "group-1");
        state.set_link_root_token_for_group("group-1", "tok-a").unwrap();
        state.force_second_live_link_for_test(&b.path().to_string_lossy(), "group-1").unwrap();

        let err = VerifiedRoot::readopt(a.path(), "group-1", &state)
            .expect_err("readopt must refuse an ambiguous group");
        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");

        assert!(
            !a.path().join(ROOT_MARKER_FILE_NAME).exists(),
            "readopt must not write a marker before refusing"
        );
        // Order-independent: the rows are ordered by `local_path`, and which of
        // the two temp dirs sorts first is not this test's subject. The property
        // is that the ONLY token present is still the pre-existing one -- no
        // freshly minted token was fanned onto either row.
        let mut tokens = state.link_root_tokens_for_group_unchecked_for_test("group-1").unwrap();
        tokens.sort();
        assert_eq!(
            tokens,
            vec![None, Some("tok-a".to_string())],
            "readopt must not mint a fresh token onto the rows before refusing"
        );
    }

    /// Zero links still adopts: the check is `> 1`, not `!= 1`. Driving a scan
    /// against a bare directory with no link row registered is a documented,
    /// live case.
    #[test]
    fn zero_links_still_adopts() {
        let dir = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();

        VerifiedRoot::open(dir.path(), "group-1", &state)
            .expect("a group with no link row must still adopt");
    }

    // --- One orphaned + one live link on a group: the brick ------------------

    /// The identity the DEAD root adopted while it was still live. A fixed
    /// value, so a test can assert the LIVE root did not inherit it.
    const DEAD_TOKEN: &str = "dead0000000000000000000000000000";

    /// Drives the group into "1 orphaned + 1 live link" through the ORDINARY
    /// PUBLIC API ONLY -- no test helper, no trigger-dropping, no raw SQL. That
    /// is the point: this state is not a corruption and not an attack, it is
    /// what an ordinary join that never activated leaves behind when the user
    /// retries the join at a different folder.
    ///
    /// The orphaned root's `local_path` sorts BEFORE the live one's, which is
    /// the ordering that makes an unfiltered `ORDER BY local_path`
    /// first-row-wins read pick the DEAD root's row. Root A is also fully
    /// adopted (marker on disk, token on its row) BEFORE it is orphaned, since
    /// that is what a real join at A does and it is the only way the dead
    /// token lands on A's row rather than B's.
    ///
    /// The token stamped onto the orphaned root A is [`DEAD_TOKEN`].
    fn one_orphaned_one_live(group: &str) -> (SyncState, tempfile::TempDir, PathBuf, PathBuf) {
        // ONE `TempDir` holding both roots, returned to the caller: two sibling
        // `TempDir`s inside a third would have the parent dropped here, deleting
        // both roots out from under the test.
        let parent = tempfile::tempdir().unwrap();
        let root_a = parent.path().canonicalize().unwrap().join("aaa-root");
        let root_b = parent.path().canonicalize().unwrap().join("bbb-root");
        std::fs::create_dir(&root_a).unwrap();
        std::fs::create_dir(&root_b).unwrap();
        assert!(root_a < root_b, "root A must sort first for this test to mean anything");

        let state = SyncState::open_in_memory().unwrap();

        // 1. The user joins the group at folder A. The daemon commits the link
        //    together with the pending-enrollment marker guarding its
        //    still-unconfirmed coordination-side activation.
        let marker = crate::index::PendingEnrollment {
            operation_id: "op-1".into(),
            kind: crate::types::EnrollmentKind::Join,
            group_id: group.into(),
            device_id: "device-1".into(),
            local_path: root_a.to_string_lossy().into_owned(),
        };
        state.add_link_with_pending_enrollment(&root_a.to_string_lossy(), group, &marker).unwrap();

        // 1b. A is adopted, exactly as a real link at A is: marker on disk,
        //     token on A's row. Done WHILE A IS LIVE -- that is the only way the
        //     token lands on A's row, and it is what makes A a dead root that
        //     still carries an identity once step 2 orphans it.
        write_marker(&root_a, group, DEAD_TOKEN).unwrap();
        state.set_link_root_token_for_group(group, DEAD_TOKEN).unwrap();

        // 2. That join never activates (the daemon was offline past the TTL, so
        //    reconciliation gets `Deleted`). The link is orphaned and the marker
        //    dropped -- ONE transaction, the daemon's real reconciliation step.
        //    `root_token` is deliberately PRESERVED by that write.
        state.orphan_link_and_remove_pending_enrollment(&root_a.to_string_lossy(), "op-1").unwrap();

        // 3. The user retries the join, this time at folder B. Zero LIVE rows
        //    exist for the group, so both the Rust chokepoint's live check and
        //    the schema trigger's `EXISTS(... orphaned = 0 ...)` accept it.
        state.add_link(&root_b.to_string_lossy(), group).unwrap();

        (state, parent, root_a, root_b)
    }

    /// THE BRICK. A group holding one orphaned and one live link is a state the
    /// ambiguity GATE calls legal (it counts only LIVE rows -- there is exactly
    /// one) but the by-`group_id` token WRITER used to see as two rows, making
    /// its fan-out assert fire forever.
    ///
    /// The consequence is not a warning: the group's SOLE LIVE ROOT can never be
    /// verified again on this device, and `readopt` -- the documented escape
    /// hatch out of every other refusal in this module -- cannot save it either,
    /// because it mints and writes the marker BEFORE the write that fails. The
    /// user's group is permanently unsyncable, reachable with no attacker and no
    /// corruption.
    ///
    /// Asserts BOTH constructors, because a fix that only unbricks `open` would
    /// leave the escape hatch bricked.
    #[test]
    fn a_group_with_one_orphaned_and_one_live_link_still_verifies_its_live_root() {
        let (state, _parent, _root_a, root_b) = one_orphaned_one_live("group-1");

        let verified = VerifiedRoot::open(&root_b, "group-1", &state).expect(
            "the group's SOLE LIVE root must verify: an orphaned sibling row is not a \
                     second root, and the gate itself calls this state legal",
        );
        assert_eq!(verified.path(), root_b);

        // The escape hatch must work too -- it is what the refusal's own message
        // sends the user to, and it writes before it can fail.
        VerifiedRoot::readopt(&root_b, "group-1", &state)
            .expect("re-adopting the group's sole live root must work in this state");
    }

    /// R4: the LIVE root must not inherit the DEAD root's identity.
    ///
    /// With the orphaned row sorting first and carrying a token, an unfiltered
    /// first-row-wins read hands `adopt_unmarked_root` the DEAD root's token,
    /// which it stamps into the LIVE root's marker (`persisted.unwrap_or_else`).
    /// That manufactures the "two folders sharing one token, permanently
    /// indistinguishable" state this whole module exists to prevent -- on the
    /// READ side, where no writer assert can see it.
    #[test]
    fn the_live_root_does_not_inherit_the_orphaned_roots_token() {
        use sha2::{Digest, Sha256};

        let (state, _parent, _root_a, root_b) = one_orphaned_one_live("group-1");
        let dead_token = DEAD_TOKEN.to_string();

        // The LIVE root B is unmarked but corroborated: one indexed file of the
        // group is present in it, so adoption proceeds.
        std::fs::write(root_b.join("present.txt"), b"hi").unwrap();
        state
            .upsert_file(
                "group-1",
                &crate::types::FileRecord {
                    path: "present.txt".into(),
                    size: 2,
                    mtime_unix_nanos: 1,
                    version: Default::default(),
                    blocks: vec![crate::types::BlockInfo {
                        hash: Sha256::digest(b"hi").to_vec(),
                        offset: 0,
                        size: 2,
                    }],
                    deleted: false,
                },
            )
            .unwrap();

        VerifiedRoot::open(&root_b, "group-1", &state).expect("the live root must adopt");

        let marker_b = read_marker(&root_b).unwrap().expect("B must have been marked");
        assert_ne!(
            marker_b.root_token, dead_token,
            "the LIVE root must mint its OWN identity, never inherit the orphaned root's -- two \
             folders sharing one token are permanently indistinguishable by the very check meant \
             to tell them apart"
        );

        // And row-level: the orphaned row's token must be UNCHANGED, and the
        // live row must carry B's own.
        let tokens = state.link_root_tokens_for_group_unchecked_for_test("group-1").unwrap();
        assert_eq!(
            tokens,
            vec![Some(dead_token), Some(marker_b.root_token)],
            "the orphaned row's token must survive untouched and the live row must hold its own"
        );
    }

    /// R3: the token-absent case must NOT re-arm adoption.
    ///
    /// Once the reader is orphan-filtered, a group whose ONLY row is orphaned
    /// reads `token = None`. `None` must change only WHICH token a legitimate
    /// adoption stamps (reuse vs mint) -- never WHETHER adoption happens. The
    /// bare-mountpoint refusal is gated by on-disk evidence alone and is
    /// token-blind, and this pins that: it must still refuse.
    ///
    /// Asserts the ABSENCE OF A MARKER, not merely the `Err`. The marker is what
    /// adoption writes, so its absence is the direct evidence that adoption did
    /// not happen -- an `Err` returned after a marker was written would still be
    /// a blessed bare mountpoint.
    #[test]
    fn a_token_absent_group_still_refuses_to_adopt_a_bare_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = SyncState::open_in_memory().unwrap();

        // A link that exists but is orphaned: zero LIVE rows => token reads None.
        state.add_link(&root.to_string_lossy(), "group-1").unwrap();
        state.set_link_root_token_for_group("group-1", "sometoken").unwrap();
        state.mark_link_orphaned(&root.to_string_lossy()).unwrap();
        assert_eq!(
            state.link_root_token_for_group("group-1").unwrap(),
            None,
            "an all-orphaned group must read no token -- this test is about what happens NEXT"
        );

        // The index says this group has a file; the root is empty. That is the
        // unmount signature.
        state
            .upsert_file(
                "group-1",
                &crate::types::FileRecord {
                    path: "gone.txt".into(),
                    size: 1,
                    mtime_unix_nanos: 1,
                    version: Default::default(),
                    blocks: vec![],
                    deleted: false,
                },
            )
            .unwrap();

        VerifiedRoot::open(&root, "group-1", &state)
            .expect_err("a token-absent group must still refuse a root with none of its files");
        assert!(
            !root.join(ROOT_MARKER_FILE_NAME).exists(),
            "the refusal must not have adopted: a marker here means the bare mountpoint was \
             blessed, which is the whole-folder loss this module exists to prevent"
        );
    }

    /// R3b: the same, with NO link row at all -- the other route to a `None`
    /// token read. `zero_links_still_adopts` pins that this case ADOPTS when the
    /// evidence supports it; this pins that the evidence, not the token, is what
    /// decides.
    #[test]
    fn a_group_with_no_link_row_still_refuses_to_adopt_a_bare_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = SyncState::open_in_memory().unwrap();

        state
            .upsert_file(
                "group-1",
                &crate::types::FileRecord {
                    path: "gone.txt".into(),
                    size: 1,
                    mtime_unix_nanos: 1,
                    version: Default::default(),
                    blocks: vec![],
                    deleted: false,
                },
            )
            .unwrap();

        VerifiedRoot::open(&root, "group-1", &state)
            .expect_err("no link row must not weaken the bare-root refusal");
        assert!(!root.join(ROOT_MARKER_FILE_NAME).exists(), "the refusal must not have adopted");
    }

    #[test]
    fn peer_verification_never_adopts_an_unmarked_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        state.add_link(&root.to_string_lossy(), "group-1").unwrap();

        VerifiedRoot::verify(&root, "group-1", &state)
            .expect_err("peer verification must require a prior explicit/startup adoption");
        assert!(!root.join(ROOT_MARKER_FILE_NAME).exists());
        assert_eq!(state.link_root_token_for_group("group-1").unwrap(), None);

        VerifiedRoot::open(&root, "group-1", &state).unwrap();
        VerifiedRoot::verify(&root, "group-1", &state).unwrap();
    }
}
