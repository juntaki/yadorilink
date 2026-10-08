//! Remote-only recovery items: heads this replica holds that the target lacks are
//! saved durably before the barrier, survive everything the rebootstrap does, are
//! deleted only by an explicit discard and come back only as an ordinary put.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_rebootstrap::{
    rebootstrap_status, recover_after_restart, BeginError, BlockedReason, Crash, Failpoint,
    PreservationFailure, Preserved, RebootstrapState, RecoveryContentSource, RestartOutcome,
};
use crate::native_rebootstrap_install::{InstallError, InstallPoint};
use crate::native_rebootstrap_recovery::RecoveryArea;
use crate::native_recovery_items::{
    discard_recovery_item, list_recovery_items, read_item_content, restore_recovery_item,
    ItemContent, ItemKind, RestoreError,
};

use super::history_lifecycle_red::{
    environment, incarnation_of, offline_base, put_op, rem, seed_versions, signed, Offline,
};
use super::rebootstrap_install::{install, install_with, FsRoot};
use super::rebootstrap_preserve::{
    begin_custom, begin_with, items_root_of, no_hook, private_tempdir, SeedContent, Setup, Writer,
};
use super::*;

struct NoContent;

impl RecoveryContentSource for NoContent {
    fn read_version(&self, _version: &FileVersion) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn held_blocks(&self, _version: &FileVersion) -> Result<Vec<BlockHash>, String> {
        Ok(Vec::new())
    }
}

/// `B` holds `A/1` (`x` = v1), which the target (`A/1`, `A/2`: `x` = v4) supersedes:
/// `A/1`'s head is the one remote-only head.
fn one_remote_only_head() -> Offline {
    offline_base(true)
}

fn items_of(c: &Connection) -> Vec<crate::native_recovery_items::RecoveryItem> {
    list_recovery_items(c, &group()).unwrap()
}

fn item_rows(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM native_recovery_item", [], |row| row.get(0)).unwrap()
}

/// The directories of the item store of the group, one per item.
fn item_dirs(items_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for group_dir in fs::read_dir(items_root).into_iter().flatten().flatten() {
        out.extend(
            fs::read_dir(group_dir.path()).into_iter().flatten().flatten().map(|e| e.path()),
        );
    }
    out
}

fn crash_at(point: Failpoint) -> impl FnMut(Failpoint) -> Result<(), Crash> {
    move |reached| if reached == point { Err(Crash) } else { Ok(()) }
}

// --- the plan and the items ---------------------------------------------------------------

#[test]
fn a_remote_only_head_is_a_durable_complete_item_before_the_barrier() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let mut before_barrier = None;
    let mut hook = |point: Failpoint| {
        if point == Failpoint::BeforeManifest {
            before_barrier = Some((
                rebootstrap_status(&o.b, &group()).unwrap().unwrap().state,
                list_recovery_items(&o.b, &group()).unwrap(),
            ));
        }
        Ok(())
    };

    let preserved = begin_with(&o.b, built(&o.sealer), area.path(), &mut hook).unwrap();

    let (state, items) = before_barrier.expect("the manifest stage was reached");
    assert_eq!(state, RebootstrapState::Preserving, "the barrier was already crossed");
    assert_eq!(items.len(), 1, "the item was not durable before the barrier: {items:?}");
    let item = &items[0];
    assert_eq!(item.kind, ItemKind::RemoteOnly);
    assert_eq!(item.content, ItemContent::Complete);
    assert_eq!(item.path.as_str(), "x");
    assert_eq!(item.version, version(1).version_hash);
    assert_eq!(item.dot.author, o.a);
    assert_eq!(item.dot.seq.get(), 1);
    assert_eq!(
        read_item_content(&o.b, &items_root_of(area.path()), &group(), &item.item_id).unwrap(),
        vec![1u8],
        "the bytes are the version's"
    );
    let manifest = RecoveryArea::open_dir(&preserved.dir).unwrap().read_intent().unwrap().manifest;
    assert_eq!(manifest.remote_only.len(), 1, "the manifest does not name the item");
    assert_eq!(manifest.remote_only[0].item_id, item.item_id);
}

#[test]
fn a_head_the_target_contains_is_not_saved() {
    let o = offline_base(false);
    let area = private_tempdir();
    begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    assert!(items_of(&o.b).is_empty(), "{:?}", items_of(&o.b));
    assert!(item_dirs(&items_root_of(area.path())).is_empty());
}

#[test]
fn a_head_above_the_target_closure_cutoff_is_saved_and_marked() {
    let o = offline_base(false);
    // The replica has a second delta of A that the target, which closes A at its first,
    // does not admit.
    let a2 = signed(&o.a, 2, Some(o.a1), vec![put_op("z", 5, Vec::new())]);
    publish(&o.b, &o.a, &device_key(1), a2);
    close_author(&o.sealer, &group(), &o.a);
    let area = private_tempdir();

    begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();

    let items = items_of(&o.b);
    assert_eq!(items.len(), 1, "only the head beyond the cutoff: {items:?}");
    assert_eq!(items[0].kind, ItemKind::BeyondClosureCutoff);
    assert_eq!(items[0].path.as_str(), "z");
    assert_eq!(items[0].version, version(5).version_hash);
    assert_eq!(
        read_item_content(&o.b, &items_root_of(area.path()), &group(), &items[0].item_id).unwrap(),
        vec![5u8]
    );
}

#[test]
fn content_that_is_not_held_is_a_typed_item_and_does_not_block() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let setup = Setup { content: &NoContent, ..Setup::default() };

    begin_custom(&o.b, built(&o.sealer), area.path(), &setup, &mut no_hook).unwrap();

    let items = items_of(&o.b);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].content, ItemContent::Unavailable);
}

#[test]
fn a_head_whose_version_record_is_missing_is_a_hash_only_item_and_does_not_block() {
    let o = one_remote_only_head();
    o.b.execute(
        "DELETE FROM file_versions WHERE version_hash = ?1",
        [&version(1).version_hash.0[..]],
    )
    .unwrap();
    let area = private_tempdir();

    begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();

    let items = items_of(&o.b);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].content, ItemContent::RecordUnavailable);
    assert_eq!(items[0].version, version(1).version_hash);
}

// --- the barrier is not reachable with an incomplete set ---------------------------------------

fn blocked_unpreserved(outcome: Result<Preserved, BeginError>) {
    match outcome {
        Err(BeginError::Blocked(BlockedReason::RemoteOnlyUnpreserved { .. })) => {}
        other => panic!("expected Blocked(RemoteOnlyUnpreserved), got {other:?}"),
    }
}

#[test]
fn preserved_is_not_reachable_when_an_item_row_is_missing() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let mut hook = |point: Failpoint| {
        if point == Failpoint::BeforeManifest {
            o.b.execute("DELETE FROM native_recovery_item", []).unwrap();
        }
        Ok(())
    };

    blocked_unpreserved(begin_with(&o.b, built(&o.sealer), area.path(), &mut hook));

    let status = rebootstrap_status(&o.b, &group()).unwrap().unwrap();
    assert!(matches!(status.state, RebootstrapState::Blocked(_)), "{:?}", status.state);
}

#[test]
fn preserved_is_not_reachable_when_an_item_file_is_missing() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let items_root = items_root_of(area.path());
    let mut hook = |point: Failpoint| {
        if point == Failpoint::BeforeManifest {
            for dir in item_dirs(&items_root) {
                fs::remove_dir_all(dir).unwrap();
            }
        }
        Ok(())
    };

    blocked_unpreserved(begin_with(&o.b, built(&o.sealer), area.path(), &mut hook));

    let status = rebootstrap_status(&o.b, &group()).unwrap().unwrap();
    assert!(matches!(status.state, RebootstrapState::Blocked(_)), "{:?}", status.state);
}

#[test]
fn a_rebootstrap_whose_items_cannot_be_written_is_blocked_and_destroys_nothing() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    // The place of the item store is a file: nothing can be saved there.
    fs::write(items_root_of(area.path()), b"not a directory").unwrap();
    let before = (roots_of(&o.b), crate::native_store::load_state(&o.b, &group()).unwrap());

    let outcome = begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook);

    assert!(
        matches!(
            outcome,
            Err(BeginError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::RecoveryAreaUnavailable { .. }
            )))
        ),
        "{outcome:?}"
    );
    let status = rebootstrap_status(&o.b, &group()).unwrap().unwrap();
    assert!(matches!(status.state, RebootstrapState::Blocked(_)));
    assert_eq!(before, (roots_of(&o.b), crate::native_store::load_state(&o.b, &group()).unwrap()));
    assert_eq!(item_rows(&o.b), 0);
}

// --- crashes while items are written -------------------------------------------------------------

#[test]
fn a_crash_at_each_step_of_item_writing_resumes_without_loss_or_duplication() {
    for (point, rows_after_crash) in
        [(Failpoint::AfterRemoteOnlyFiles(0), 0), (Failpoint::AfterRemoteOnlyRow(0), 1)]
    {
        let o = one_remote_only_head();
        let area = private_tempdir();
        let items_root = items_root_of(area.path());

        let outcome = begin_with(&o.b, built(&o.sealer), area.path(), &mut crash_at(point));
        assert!(matches!(outcome, Err(BeginError::Crashed)), "{point:?}: {outcome:?}");
        assert_eq!(item_rows(&o.b), rows_after_crash, "{point:?}: a row before its files");
        let outcome = recover_after_restart(&o.b, area.path(), &group()).unwrap();
        assert!(matches!(outcome, RestartOutcome::Abandoned { .. }), "{point:?}: {outcome:?}");
        assert_eq!(item_rows(&o.b), rows_after_crash, "{point:?}: abandoning deleted an item");
        assert_eq!(
            item_dirs(&items_root).len(),
            1,
            "{point:?}: abandoning removed the files of an item"
        );

        begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();

        let items = items_of(&o.b);
        assert_eq!(items.len(), 1, "{point:?}: lost or duplicated: {items:?}");
        assert_eq!(item_dirs(&items_root).len(), 1, "{point:?}: a stray directory");
        assert_eq!(
            read_item_content(&o.b, &items_root, &group(), &items[0].item_id).unwrap(),
            vec![1u8],
            "{point:?}"
        );
    }
}

// --- survival and deletion ----------------------------------------------------------------------------

#[test]
fn preserved_items_survive_restarts_and_rebootstrap_success() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let preserved = begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    let saved = items_of(&o.b);
    assert_eq!(saved.len(), 1);
    let items_root = items_root_of(area.path());

    let restarted = recover_after_restart(&o.b, area.path(), &group()).unwrap();
    assert!(matches!(restarted, RestartOutcome::Preserved(_)), "{restarted:?}");
    assert_eq!(items_of(&o.b), saved);

    install(&o.b, area.path(), &FsRoot::new(root.path())).unwrap();
    assert_eq!(items_of(&o.b), saved, "the install removed or changed an item");
    let restarted = recover_after_restart(&o.b, area.path(), &group()).unwrap();
    assert!(matches!(restarted, RestartOutcome::CatchingUp(_)), "{restarted:?}");

    super::rebootstrap_replay::complete_machine(&o.b, area.path(), &preserved.recovery_id, &Writer);
    RecoveryArea::remove(area.path(), &group(), &preserved.recovery_id).unwrap();
    assert_eq!(items_of(&o.b), saved, "finishing the rebootstrap removed or changed an item");
    assert_eq!(
        read_item_content(&o.b, &items_root, &group(), &saved[0].item_id).unwrap(),
        vec![1u8]
    );
}

#[test]
fn explicit_user_discard_is_the_only_deleter_of_preserved_items() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let items_root = items_root_of(area.path());

    // A crash and a retry, a second rebootstrap that supersedes the first.
    begin_with(&o.b, built(&o.sealer), area.path(), &mut crash_at(Failpoint::BeforeManifest))
        .unwrap_err();
    recover_after_restart(&o.b, area.path(), &group()).unwrap();
    begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    let preserved = begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    let saved = items_of(&o.b);
    assert_eq!(saved.len(), 1, "a retry duplicated or lost the item");

    install(&o.b, area.path(), &FsRoot::new(root.path())).unwrap();
    // While the group is frozen not even a discard runs.
    let refused = discard_recovery_item(&o.b, &items_root, &group(), &saved[0].item_id);
    assert!(matches!(refused, Err(SyncSqliteError::GroupFrozen { .. })), "{refused:?}");
    super::rebootstrap_replay::complete_machine(&o.b, area.path(), &preserved.recovery_id, &Writer);
    RecoveryArea::remove(area.path(), &group(), &preserved.recovery_id).unwrap();
    assert_eq!(items_of(&o.b), saved);
    assert_eq!(item_dirs(&items_root).len(), 1);

    assert!(discard_recovery_item(&o.b, &items_root, &group(), &saved[0].item_id).unwrap());
    assert!(items_of(&o.b).is_empty());
    assert!(item_dirs(&items_root).is_empty(), "the item's files outlived its discard");
    assert!(!discard_recovery_item(&o.b, &items_root, &group(), &saved[0].item_id).unwrap());
}

#[test]
fn an_item_that_vanished_after_the_barrier_stops_the_install_before_anything_is_cleared() {
    for remove_row in [true, false] {
        let o = one_remote_only_head();
        let area = private_tempdir();
        let root = tempfile::tempdir().unwrap();
        begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
        if remove_row {
            o.b.execute("DELETE FROM native_recovery_item", []).unwrap();
        } else {
            for dir in item_dirs(&items_root_of(area.path())) {
                fs::remove_dir_all(dir).unwrap();
            }
        }
        let before = (roots_of(&o.b), crate::native_store::load_state(&o.b, &group()).unwrap());

        let outcome = install(&o.b, area.path(), &FsRoot::new(root.path()));

        assert!(
            matches!(
                outcome,
                Err(InstallError::Blocked(BlockedReason::RemoteOnlyUnpreserved { .. }))
            ),
            "row removed {remove_row}: {outcome:?}"
        );
        assert_eq!(
            before,
            (roots_of(&o.b), crate::native_store::load_state(&o.b, &group()).unwrap())
        );
        // Not even the quarantine of the root began.
        let status = rebootstrap_status(&o.b, &group()).unwrap().unwrap();
        assert_eq!(status.state, RebootstrapState::Preserved);
    }
}

#[test]
fn an_item_that_vanishes_after_the_quarantine_began_still_stops_the_clear() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    let before = (roots_of(&o.b), crate::native_store::load_state(&o.b, &group()).unwrap());

    let outcome =
        install_with(&o.b, area.path(), &FsRoot::new(root.path()), &Writer, &mut |point| {
            if point == InstallPoint::AfterBeginQuarantine {
                o.b.execute("DELETE FROM native_recovery_item", []).unwrap();
            }
            Ok(())
        });

    assert!(
        matches!(outcome, Err(InstallError::Blocked(BlockedReason::RemoteOnlyUnpreserved { .. }))),
        "{outcome:?}"
    );
    assert_eq!(before, (roots_of(&o.b), crate::native_store::load_state(&o.b, &group()).unwrap()));
}

// --- restore ---------------------------------------------------------------------------------------------

/// A finished rebootstrap of `one_remote_only_head`: the group is open again.
fn finished() -> (Offline, tempfile::TempDir, String) {
    let o = one_remote_only_head();
    let area = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let preserved = begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    install(&o.b, area.path(), &FsRoot::new(root.path())).unwrap();
    super::rebootstrap_replay::complete_machine(&o.b, area.path(), &preserved.recovery_id, &Writer);
    (o, area, preserved.recovery_id)
}

#[test]
fn restoring_an_item_authors_one_ordinary_put_with_a_new_dot_and_keeps_the_item() {
    let (o, area, _) = finished();
    let saved = items_of(&o.b);
    let author = crate::author_incarnation::current_author(&o.b).unwrap();
    let key = device_key(2);
    let local = LocalAuthor { author: author.clone(), signing_key: &key, capture: None };
    let mut imported = Vec::new();

    restore_recovery_item(
        &o.b,
        &items_root_of(area.path()),
        &group(),
        &saved[0].item_id,
        &local,
        &mut |version, bytes| {
            imported.push((version.version_hash, bytes.to_vec()));
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(imported, vec![(version(1).version_hash, vec![1u8])]);
    let state = crate::native_store::load_state(&o.b, &group()).unwrap();
    let restored: Vec<_> = state.heads[&SyncPath("x".into())]
        .iter()
        .filter(|(dot, payload)| dot.author == author && payload.version == version(1).version_hash)
        .collect();
    assert_eq!(restored.len(), 1, "no ordinary put of the item's version: {state:?}");
    assert_ne!(*restored[0].0, saved[0].dot, "the original dot was restored");
    assert_eq!(items_of(&o.b), saved, "restoring removed the item");
}

#[test]
fn restoring_is_refused_while_the_group_is_frozen() {
    let o = one_remote_only_head();
    let area = private_tempdir();
    begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    let saved = items_of(&o.b);
    let author = crate::author_incarnation::current_author(&o.b).unwrap();
    let key = device_key(2);
    let local = LocalAuthor { author, signing_key: &key, capture: None };

    let outcome = restore_recovery_item(
        &o.b,
        &items_root_of(area.path()),
        &group(),
        &saved[0].item_id,
        &local,
        &mut |_, _| Ok(()),
    );

    assert!(
        matches!(outcome, Err(RestoreError::Store(SyncSqliteError::GroupFrozen { .. }))),
        "{outcome:?}"
    );
}

#[test]
fn restoring_an_item_without_bytes_or_record_authors_nothing() {
    for (record_missing, expect_record) in [(false, false), (true, true)] {
        let o = one_remote_only_head();
        if record_missing {
            o.b.execute(
                "DELETE FROM file_versions WHERE version_hash = ?1",
                [&version(1).version_hash.0[..]],
            )
            .unwrap();
        }
        let area = private_tempdir();
        let root = tempfile::tempdir().unwrap();
        let setup = Setup { content: &NoContent, ..Setup::default() };
        let preserved =
            begin_custom(&o.b, built(&o.sealer), area.path(), &setup, &mut no_hook).unwrap();
        install(&o.b, area.path(), &FsRoot::new(root.path())).unwrap();
        super::rebootstrap_replay::complete_machine(
            &o.b,
            area.path(),
            &preserved.recovery_id,
            &Writer,
        );
        let saved = items_of(&o.b);
        let author = crate::author_incarnation::current_author(&o.b).unwrap();
        let key = device_key(2);
        let local = LocalAuthor { author, signing_key: &key, capture: None };
        let before = roots_of(&o.b);

        let outcome = restore_recovery_item(
            &o.b,
            &items_root_of(area.path()),
            &group(),
            &saved[0].item_id,
            &local,
            &mut |_, _| panic!("nothing to import"),
        );

        if expect_record {
            assert!(matches!(outcome, Err(RestoreError::RecordUnavailable)), "{outcome:?}");
        } else {
            assert!(matches!(outcome, Err(RestoreError::ContentUnavailable)), "{outcome:?}");
        }
        assert_eq!(before, roots_of(&o.b), "a refused restore authored");
        assert_eq!(items_of(&o.b), saved);
    }
}

// --- blocks an item keeps alive ----------------------------------------------------------------

const BLOCK_A: u8 = 0xA1;
const BLOCK_B: u8 = 0xB2;
const BLOCK_C: u8 = 0xC3;

fn three_block_version() -> FileVersion {
    FileVersion::new(
        [BLOCK_A, BLOCK_B, BLOCK_C]
            .into_iter()
            .map(|seed| VersionBlock { hash: BlockHash(vec![seed; 32]), size: 4 })
            .collect(),
        12,
        FileMeta {
            mtime_unix_nanos: 9,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn block_hex(seed: u8) -> String {
    hex::encode([seed; 32])
}

/// Holds the blocks whose seed it names, never a whole version.
struct HoldsBlocks(Vec<u8>);

impl RecoveryContentSource for HoldsBlocks {
    fn read_version(&self, _version: &FileVersion) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn held_blocks(&self, version: &FileVersion) -> Result<Vec<BlockHash>, String> {
        Ok(version
            .blocks
            .iter()
            .filter(|b| self.0.contains(&b.hash.0[0]))
            .map(|b| b.hash.clone())
            .collect())
    }
}

/// Like `one_remote_only_head`, but the head is the three-block version.
fn three_block_head() -> Offline {
    let b = conn();
    let b1 =
        crate::author_incarnation::ensure_incarnation(&b, &environment("device-b")).unwrap().author;
    let sealer = conn();
    seed_versions(&b);
    seed_versions(&sealer);
    let version = three_block_version();
    crate::dag_store::put_file_version(&b, GROUP, &version).unwrap();
    crate::dag_store::put_file_version(&sealer, GROUP, &version).unwrap();
    let a = incarnation_of("device-a", 1);
    let op = DeltaOp {
        path: SyncPath("x".into()),
        removes: Vec::new(),
        put: Some(DeltaPut { version: version.version_hash }),
        keeps: Vec::new(),
        keep_put: false,
    };
    let a1 = signed(&a, 1, None, vec![op]);
    let a1_hash = a1.delta_hash();
    publish(&sealer, &a, &device_key(1), a1.clone());
    publish(&b, &a, &device_key(1), a1);
    let a2 = signed(&a, 2, Some(a1_hash), vec![put_op("x", 4, vec![rem(&a, 1, a1_hash)])]);
    publish(&sealer, &a, &device_key(1), a2);
    Offline { sealer, b, b1, a, a1: a1_hash }
}

/// Saves the head under `content`, installs the target and finishes: the item is all that
/// still names the head's blocks.
fn saved_and_installed(content: &dyn RecoveryContentSource) -> (Offline, tempfile::TempDir) {
    let o = three_block_head();
    let area = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let setup = Setup { content, ..Setup::default() };
    let preserved =
        begin_custom(&o.b, built(&o.sealer), area.path(), &setup, &mut no_hook).unwrap();
    install(&o.b, area.path(), &FsRoot::new(root.path())).unwrap();
    super::rebootstrap_replay::complete_machine(&o.b, area.path(), &preserved.recovery_id, &Writer);
    RecoveryArea::remove(area.path(), &group(), &preserved.recovery_id).unwrap();
    (o, area)
}

fn swept_live(c: &Connection) -> std::collections::HashSet<String> {
    crate::materialization_state::live_set(c, || {}).unwrap()
}

#[test]
fn the_held_blocks_of_an_unavailable_item_survive_repeated_sweeps() {
    let (o, _area) = saved_and_installed(&HoldsBlocks(vec![BLOCK_A, BLOCK_B]));
    let items = items_of(&o.b);
    assert_eq!(items[0].content, ItemContent::Unavailable);
    assert_eq!(items[0].retained_blocks, vec![block_hex(BLOCK_A), block_hex(BLOCK_B)]);

    for _ in 0..3 {
        let live = swept_live(&o.b);
        assert!(live.contains(&block_hex(BLOCK_A)), "A was left to the sweep: {live:?}");
        assert!(live.contains(&block_hex(BLOCK_B)), "B was left to the sweep: {live:?}");
        assert!(!live.contains(&block_hex(BLOCK_C)), "a block never held is not rooted");
    }
}

#[test]
fn the_held_blocks_of_an_unavailable_item_survive_a_restart() {
    let (o, area) = saved_and_installed(&HoldsBlocks(vec![BLOCK_A, BLOCK_B]));
    let restarted = recover_after_restart(&o.b, area.path(), &group()).unwrap();
    assert!(
        matches!(restarted, RestartOutcome::Idle | RestartOutcome::CatchingUp(_)),
        "{restarted:?}"
    );
    let live = swept_live(&o.b);
    assert!(live.contains(&block_hex(BLOCK_A)) && live.contains(&block_hex(BLOCK_B)), "{live:?}");
}

#[test]
fn a_discarded_items_blocks_are_released_to_the_sweep() {
    let (o, area) = saved_and_installed(&HoldsBlocks(vec![BLOCK_A, BLOCK_B]));
    let item_id = items_of(&o.b)[0].item_id.clone();
    assert!(swept_live(&o.b).contains(&block_hex(BLOCK_A)));

    assert!(discard_recovery_item(&o.b, &items_root_of(area.path()), &group(), &item_id).unwrap());

    let live = swept_live(&o.b);
    assert!(!live.contains(&block_hex(BLOCK_A)) && !live.contains(&block_hex(BLOCK_B)), "{live:?}");
}

#[test]
fn a_complete_items_blocks_are_rooted_too() {
    let (o, _area) = saved_and_installed(&SeedContent);
    assert_eq!(items_of(&o.b)[0].content, ItemContent::Complete);
    let live = swept_live(&o.b);
    for seed in [BLOCK_A, BLOCK_B, BLOCK_C] {
        assert!(live.contains(&block_hex(seed)), "{seed:#x} was left to the sweep: {live:?}");
    }
}

#[test]
fn an_item_without_any_local_block_roots_nothing_and_does_not_break_the_sweep() {
    let (o, _area) = saved_and_installed(&NoContent);
    let items = items_of(&o.b);
    assert_eq!(items[0].content, ItemContent::Unavailable);
    assert!(items[0].retained_blocks.is_empty());
    let live = swept_live(&o.b);
    assert!(![BLOCK_A, BLOCK_B, BLOCK_C].iter().any(|s| live.contains(&block_hex(*s))), "{live:?}");
}
