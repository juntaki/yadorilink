//! Reconcile decides a path's physical state from the namespace, not from
//! the path alone.
//!
//! A filesystem is a tree: `a` cannot be a file while `a/x` lives, and a
//! directory that exists only to hold descendants goes when they go. So a
//! pass over `a/x` also decides `a`: a live descendant makes `a` a
//! directory and moves a file that was there beside it, under its
//! conflict-copy name; the last descendant's delete removes a directory
//! this device made only to hold it, and puts the file back. None of this
//! is a change anyone authored, and none of it may cost data: a directory
//! holding anything this device does not replicate is kept, and a file
//! that cannot go back to its own name stays where it is.

use super::*;
use yadorilink_replica_domain::conflict::{conflict_copy_source_path, is_conflict_copy_path};
use yadorilink_sync_sqlite::structural_origin::StructuralOriginStatus;

impl Harness {
    fn admit_many(&self, ops: Vec<Op>, versions: &[FileVersion]) -> Change {
        let change =
            dag_store::emit_local_change(&self.sender_db, GROUP, ops, &self.emitter).unwrap();
        let evidence = self.evidence_for(&change, &self.emitter);
        self.state
            .change_history_repository()
            .dag_admit_change_batch_with_versions(&[yadorilink_sync_sqlite::PendingAdmission {
                change: &change,
                versions,
                evidence: Some(&evidence),
            }])
            .remove(0)
            .unwrap();
        change
    }

    /// Emits `ops` by `emitter` onto exactly `parents` -- not the sender's
    /// heads -- and admits it: a change concurrent with everything outside
    /// `parents`' past, as a device that had not seen the rest writes it.
    fn admit_onto(
        &self,
        parents: Vec<yadorilink_replica_domain::ids::ChangeHash>,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Change {
        let change =
            dag_store::emit_local_change_onto(&self.sender_db, GROUP, parents, ops, emitter)
                .unwrap();
        let evidence = self.evidence_for(&change, emitter);
        self.state
            .change_history_repository()
            .dag_admit_change_batch_with_versions(&[yadorilink_sync_sqlite::PendingAdmission {
                change: &change,
                versions,
                evidence: Some(&evidence),
            }])
            .remove(0)
            .unwrap();
        change
    }

    /// Ignores every conflict-copy name on this device.
    fn ignore_copy_names(&self) {
        std::fs::write(self.root.path().join(".yadorilinkignore"), b"*conflicted copy*\n").unwrap();
        self.convergence.rewind_ignore_set_cache_for_tests(
            GROUP,
            super::super::IGNORE_SET_REFRESH_INTERVAL + std::time::Duration::from_secs(1),
        );
        assert!(
            self.convergence.is_locally_ignored(GROUP, "f (conflicted copy, 1, d, 00)"),
            "sanity: the rule applies"
        );
    }

    async fn pass(&self, paths: &[&str]) -> ProjectionAttempt {
        self.convergence
            .reconcile_paths(GROUP, paths.iter().map(|p| p.to_string()).collect())
            .await
            .unwrap()
            .expect("a live link runs the pass")
    }

    fn structural_status(&self, path: &str) -> StructuralOriginStatus {
        let origin = self.state.sqlite().dag_structural_directory_origin(GROUP, path).unwrap();
        let observed = yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
            &self.root.path().join(path),
        )
        .ok();
        origin.status(
            observed.as_ref(),
            yadorilink_root_authority::fs_identity::TimestampGranularity::Fine,
        )
    }

    /// Every conflict-copy-shaped name beside `source`, with its bytes.
    fn copies_of(&self, source: &str) -> Vec<(String, Vec<u8>)> {
        let parent = match source.rsplit_once('/') {
            Some((parent, _)) => self.root.path().join(parent),
            None => self.root.path().to_path_buf(),
        };
        let prefix = source.rsplit_once('/').map(|(p, _)| format!("{p}/")).unwrap_or_default();
        let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| format!("{prefix}{}", entry.unwrap().file_name().to_string_lossy()))
            .filter(|path| is_conflict_copy_path(path) && conflict_copy_source_path(path) == source)
            .map(|path| {
                let bytes = std::fs::read(self.root.path().join(&path)).unwrap();
                (path, bytes)
            })
            .collect();
        out.sort();
        out
    }

    async fn retire_copies(&self) {
        self.convergence.retire_unjustified_ephemeral_conflict_copies(GROUP, 0).await.unwrap();
    }

    /// The tree under the root, directories included, with file bytes.
    fn tree(&self) -> Vec<(String, Option<Vec<u8>>)> {
        fn walk(
            root: &std::path::Path,
            dir: &std::path::Path,
            out: &mut Vec<(String, Option<Vec<u8>>)>,
        ) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                if rel.starts_with(".yadorilink") {
                    continue;
                }
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    out.push((rel, None));
                    walk(root, &path, out);
                } else {
                    out.push((rel, Some(std::fs::read(&path).unwrap())));
                }
            }
        }
        let mut out = Vec::new();
        walk(self.root.path(), self.root.path(), &mut out);
        out.sort();
        out
    }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

/// Places File `a` and then `a/x`, each reconciled on arrival, and checks
/// the structural-wins tree.
async fn file_then_descendant(h: &Harness) {
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit("a", &a, &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);
    let attempt = h.pass(&["a/x"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(attempt.is_settled("a/x"));
}

fn assert_structural_wins(h: &Harness) {
    assert!(std::fs::symlink_metadata(h.root.path().join("a")).unwrap().is_dir());
    assert_eq!(std::fs::read(h.root.path().join("a/x")).unwrap(), b"file a/x");
    let copies = h.copies_of("a");
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(copies[0].1, b"file a");
}

/// The staging bug, as one device sees it: a peer's `rm -rf linux/` arrives
/// as point deletes of the files. The directories this device created only
/// to hold them go with them.
#[tokio::test]
async fn rm_rf_of_a_peer_tree_removes_the_directories_created_for_it() {
    let h = Harness::new();
    let makefile = version_for(&h.state, &h.store, b"all:");
    let setup = version_for(&h.state, &h.store, b"int main;");
    h.admit_many(
        vec![create_op("linux/Makefile", &makefile), create_op("linux/arch/setup.c", &setup)],
        &[makefile.clone(), setup.clone()],
    );
    assert!(h.pass(&["linux/Makefile", "linux/arch/setup.c"]).await.retry.is_empty());
    assert_eq!(h.structural_status("linux/arch"), StructuralOriginStatus::Structural);

    h.admit_many(vec![delete("linux/Makefile"), delete("linux/arch/setup.c")], &[]);
    let attempt = h.pass(&["linux/Makefile", "linux/arch/setup.c"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(
        std::fs::symlink_metadata(h.root.path().join("linux")).is_err(),
        "left behind: {:?}",
        h.tree()
    );
}

/// The same delete split across passes, the shallower file first: the pass
/// that removes the last file removes both directories.
#[tokio::test]
async fn rm_rf_across_separate_passes_removes_the_directories_with_the_last_file() {
    let h = Harness::new();
    let makefile = version_for(&h.state, &h.store, b"all:");
    let setup = version_for(&h.state, &h.store, b"int main;");
    h.admit_many(
        vec![create_op("linux/Makefile", &makefile), create_op("linux/arch/setup.c", &setup)],
        &[makefile.clone(), setup.clone()],
    );
    assert!(h.pass(&["linux/Makefile", "linux/arch/setup.c"]).await.retry.is_empty());
    h.admit_many(vec![delete("linux/Makefile"), delete("linux/arch/setup.c")], &[]);

    assert!(h.pass(&["linux/Makefile"]).await.retry.is_empty());
    assert!(h.root.path().join("linux/arch").is_dir(), "still holds a live file");
    let attempt = h.pass(&["linux/arch/setup.c"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(std::fs::symlink_metadata(h.root.path().join("linux")).is_err(), "{:?}", h.tree());
}

/// A structural directory holding something this device does not
/// replicate stays, with it, and the pass settles without retrying.
#[tokio::test]
async fn a_structural_directory_holding_untracked_content_is_kept() {
    let h = Harness::new();
    let setup = version_for(&h.state, &h.store, b"int main;");
    h.admit("linux/arch/setup.c", &setup, &h.emitter);
    assert!(h.pass(&["linux/arch/setup.c"]).await.retry.is_empty());
    std::fs::write(h.root.path().join("linux/arch/.DS_Store"), b"finder").unwrap();

    h.admit_delete("linux/arch/setup.c", &h.emitter);
    let attempt = h.pass(&["linux/arch/setup.c"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert_eq!(std::fs::read(h.root.path().join("linux/arch/.DS_Store")).unwrap(), b"finder");
    assert!(!h.root.path().join("linux/arch/setup.c").exists());
}

/// A directory the user made is never this device's to remove, however
/// empty the replicated state leaves it.
#[tokio::test]
async fn a_directory_this_device_did_not_create_is_never_pruned() {
    let h = Harness::new();
    std::fs::create_dir(h.root.path().join("mine")).unwrap();
    let file = version_for(&h.state, &h.store, b"placed into the user's directory");
    h.admit("mine/f", &file, &h.emitter);
    assert!(h.pass(&["mine/f"]).await.retry.is_empty());

    h.admit_delete("mine/f", &h.emitter);
    let attempt = h.pass(&["mine/f"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(h.root.path().join("mine").is_dir(), "the user's directory must stay");
}

/// Structural wins, the file first: a live `a/x` turns `a` into its
/// container, and File `a` moves beside it under its conflict-copy name.
/// Nothing is lost and nothing is retried.
#[tokio::test]
async fn a_live_descendant_turns_its_ancestor_into_a_directory_and_relocates_the_file() {
    let h = Harness::new();
    file_then_descendant(&h).await;

    assert_structural_wins(&h);
    assert_eq!(h.structural_status("a"), StructuralOriginStatus::Structural);
    let again = h.pass(&["a", "a/x"]).await;
    assert!(again.retry.is_empty(), "{:?}", again.retry);
    assert_structural_wins(&h);
}

/// File `a` and `a/x` written concurrently on two devices, each
/// reconciled on arrival in the given order.
async fn concurrent_file_and_descendant(h: &Harness, descendant_first: bool) {
    let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[5u8; 32]));
    let a = version_for(&h.state, &h.store, b"file a");
    let x = version_for(&h.state, &h.store, b"file a/x");
    let file = || {
        h.admit_onto(vec![], vec![create_op("a", &a)], std::slice::from_ref(&a), &h.emitter);
        "a"
    };
    let descendant = || {
        h.admit_onto(vec![], vec![create_op("a/x", &x)], std::slice::from_ref(&x), &peer);
        "a/x"
    };
    let order: [&dyn Fn() -> &'static str; 2] =
        if descendant_first { [&descendant, &file] } else { [&file, &descendant] };
    for arrive in order {
        let path = arrive();
        let attempt = h.pass(&[path]).await;
        assert!(attempt.retry.is_empty(), "{path}: {:?} {:?}", attempt.retry, h.tree());
        assert!(attempt.is_settled(path), "{attempt:?}");
    }
}

/// Structural wins over truly concurrent heads, whichever side arrives
/// first, and both arrival orders build the same tree.
#[tokio::test]
async fn structural_wins_whichever_side_arrives_first() {
    let first = Harness::new();
    concurrent_file_and_descendant(&first, false).await;
    assert_structural_wins(&first);

    let h = Harness::new();
    concurrent_file_and_descendant(&h, true).await;

    assert_structural_wins(&h);
    assert_eq!(h.tree(), first.tree(), "both arrival orders must build one tree");
}

/// The reverse transition: once the last descendant is gone, the directory
/// made to hold it goes and the file returns to its own name. The copy
/// that held it meanwhile is no longer justified, and retires.
#[tokio::test]
async fn last_descendant_deleted_moves_the_relocated_file_back() {
    let h = Harness::new();
    file_then_descendant(&h).await;

    h.admit_delete("a/x", &h.emitter);
    let attempt = h.pass(&["a/x"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    h.retire_copies().await;

    assert_eq!(std::fs::read(h.root.path().join("a")).unwrap(), b"file a", "{:?}", h.tree());
    assert!(h.copies_of("a").is_empty(), "{:?}", h.tree());
    assert_eq!(h.structural_status("a"), StructuralOriginStatus::OriginUnknown);
}

/// The reverse transition over a directory that holds something this
/// device does not replicate (Finder's `.DS_Store`): the directory stays,
/// so the file cannot go back to its name. It stays at its copy name, the
/// copy is not retired, and neither this pass nor the next retries.
#[tokio::test]
async fn reverse_transition_over_untracked_content_keeps_the_file_at_its_copy_name() {
    let h = Harness::new();
    file_then_descendant(&h).await;
    std::fs::write(h.root.path().join("a/.DS_Store"), b"finder").unwrap();

    h.admit_delete("a/x", &h.emitter);
    let attempt = h.pass(&["a/x"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    h.retire_copies().await;

    assert!(std::fs::symlink_metadata(h.root.path().join("a")).unwrap().is_dir());
    assert_eq!(std::fs::read(h.root.path().join("a/.DS_Store")).unwrap(), b"finder");
    let copies = h.copies_of("a");
    assert_eq!(copies.len(), 1, "{:?}", h.tree());
    assert_eq!(copies[0].1, b"file a");
    for _ in 0..2 {
        let again = h.pass(&["a", "a/x"]).await;
        assert!(again.retry.is_empty(), "a held file must not retry: {:?}", again.retry);
        assert!(again.is_settled("a"));
    }
    assert_eq!(h.copies_of("a").len(), 1, "{:?}", h.tree());
}

/// A directory replaced by a file on a peer (`rm -rf a; echo > a`): the
/// file takes the name once the tree under it is gone.
#[tokio::test]
async fn a_directory_replaced_by_a_file_becomes_the_file() {
    let h = Harness::new();
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit_many(
        vec![create_op("a", &FileVersion::directory(None)), create_op("a/x", &x)],
        &[FileVersion::directory(None), x.clone()],
    );
    assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());

    let file = version_for(&h.state, &h.store, b"now a file");
    h.admit_many(vec![delete("a/x"), create_op("a", &file)], std::slice::from_ref(&file));
    let attempt = h.pass(&["a", "a/x"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert_eq!(std::fs::read(h.root.path().join("a")).unwrap(), b"now a file", "{:?}", h.tree());
    assert!(h.copies_of("a").is_empty(), "{:?}", h.tree());
}

/// A deleted explicit directory whose child is still live stays as that
/// child's container, and is recorded as structural (adopted): from now on
/// it is derived state, which capture must never author back. Once the
/// last child goes, it goes too.
#[tokio::test]
async fn a_deleted_directory_with_a_live_child_is_adopted_then_pruned_with_the_last_child() {
    let h = Harness::new();
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit_many(
        vec![create_op("a", &FileVersion::directory(None)), create_op("a/x", &x)],
        &[FileVersion::directory(None), x.clone()],
    );
    assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());
    let y = version_for(&h.state, &h.store, b"a concurrent child");
    h.admit("a/y", &y, &h.emitter);
    h.admit_delete("a", &h.emitter);

    let attempt = h.pass(&["a", "a/y"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(h.root.path().join("a").is_dir());
    assert_eq!(std::fs::read(h.root.path().join("a/y")).unwrap(), b"a concurrent child");
    assert_eq!(std::fs::read(h.root.path().join("a/x")).unwrap(), b"file a/x");
    assert_eq!(h.structural_status("a"), StructuralOriginStatus::Structural);

    h.admit_many(vec![delete("a/x"), delete("a/y")], &[]);
    let attempt = h.pass(&["a/x", "a/y"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(std::fs::symlink_metadata(h.root.path().join("a")).is_err(), "{:?}", h.tree());
}

/// Retirement asks the namespace, not only the per-path resolver, whether
/// a copy is justified: a relocated file's copy is the only place its
/// bytes are on disk.
#[tokio::test]
async fn retirement_keeps_a_relocated_copy() {
    let h = Harness::new();
    file_then_descendant(&h).await;

    h.retire_copies().await;

    assert_structural_wins(&h);
}

/// A relocation is a projection, not a fork: repair has nothing to author
/// for it and no obligation to mint at the copy name.
#[tokio::test]
async fn retroactive_repair_does_not_mint_obligation_for_relocated_copy() {
    let h = Harness::new();
    concurrent_file_and_descendant(&h, false).await;
    let copy = h.copies_of("a").remove(0).0;
    let emitter = ChangeEmitter::new("device-local", SigningKey::from_bytes(&[3u8; 32]));

    let outcome = h.state.repair_retroactive_conflict_copy_obligations(GROUP, &emitter, 0).unwrap();

    assert!(
        !matches!(
            outcome,
            yadorilink_replica_domain::session_state::RetroactiveRepairOutcome::Repaired { .. }
        ),
        "{outcome:?}"
    );
    let obligation = h
        .state
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::projection_obligations::lookup_projection_obligation(
                conn, GROUP, &copy,
            )
        })
        .unwrap();
    assert!(obligation.is_none(), "{obligation:?}");
    assert_structural_wins(&h);
}

/// A proof that `a` holds File `a` says nothing once `a/x` is live: the
/// path now has to be a directory. The zero-work close must not settle it.
#[tokio::test]
async fn zero_work_close_declines_a_file_whose_name_a_live_descendant_needs() {
    let h = Harness::new();
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit("a", &a, &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    assert!(
        h.convergence.zero_work_settlement_for_path(GROUP, "a").unwrap().is_some(),
        "sanity: the file's own proof settles it while nothing is below it"
    );
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);

    assert!(h.convergence.zero_work_settlement_for_path(GROUP, "a").unwrap().is_none());
}

/// On a volume that folds case (APFS, NTFS), File `A` and a live `a/x`
/// cannot both keep their names: `a` has to be a directory and `A` is the
/// same name. The projection is fold-free -- every device computes the
/// same tree -- so this device resolves the collision locally: `a` becomes
/// the directory and `A` moves beside it under its conflict-copy name.
/// Both survive, and nothing retries.
#[tokio::test]
async fn case_fold_ancestor_collision_file_upper_a_vs_a_slash_x_keeps_both() {
    let h = Harness::new();
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(h.root.path()) {
        eprintln!("skipped: this volume does not fold case");
        return;
    }
    let upper = version_for(&h.state, &h.store, b"file A");
    h.admit("A", &upper, &h.emitter);
    assert!(h.pass(&["A"]).await.is_settled("A"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);

    let attempt = h.pass(&["a/x"]).await;

    assert!(attempt.retry.is_empty(), "{:?} {:?}", attempt.retry, h.tree());
    assert_eq!(std::fs::read(h.root.path().join("a/x")).unwrap(), b"file a/x");
    let copies = h.copies_of("A");
    assert_eq!(copies.len(), 1, "{:?}", h.tree());
    assert_eq!(copies[0].1, b"file A");
    let again = h.pass(&["A", "a/x"]).await;
    assert!(again.retry.is_empty(), "{:?}", again.retry);
    assert_eq!(h.copies_of("A").len(), 1, "{:?}", h.tree());
}

fn case_folds(h: &Harness) -> bool {
    let folds = yadorilink_peer_session::hazard::is_case_insensitive_filesystem(h.root.path());
    if !folds {
        eprintln!("skipped: this volume does not fold case");
    }
    folds
}

/// Every file under the root holding exactly `bytes`.
fn holding(h: &Harness, bytes: &[u8]) -> Vec<String> {
    h.tree()
        .into_iter()
        .filter(|(_, content)| content.as_deref() == Some(bytes))
        .map(|(path, _)| path)
        .collect()
}

/// A peer's `a/x` that was created and deleted again before it arrived
/// needs no directory `a`: File `A` keeps its own name on a volume that
/// folds case.
#[tokio::test]
async fn case_fold_a_descendant_that_is_already_deleted_displaces_nothing() {
    let h = Harness::new();
    if !case_folds(&h) {
        return;
    }
    let upper = version_for(&h.state, &h.store, b"file A");
    h.admit("A", &upper, &h.emitter);
    assert!(h.pass(&["A"]).await.is_settled("A"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);
    h.admit_delete("a/x", &h.emitter);

    let attempt = h.pass(&["a/x"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert_eq!(holding(&h, b"file A"), vec!["A".to_string()], "{:?}", h.tree());
    assert!(h.copies_of("A").is_empty(), "{:?}", h.tree());
}

/// The reverse of the case-fold collision: once `a/x` is gone, directory
/// `a` goes with it and File `A` returns to its own name. The copy that
/// held it meanwhile retires.
#[tokio::test]
async fn case_fold_last_descendant_deleted_moves_the_file_back() {
    let h = Harness::new();
    if !case_folds(&h) {
        return;
    }
    let upper = version_for(&h.state, &h.store, b"file A");
    h.admit("A", &upper, &h.emitter);
    assert!(h.pass(&["A"]).await.is_settled("A"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);
    assert!(h.pass(&["a/x"]).await.retry.is_empty());
    assert_eq!(h.copies_of("A").len(), 1, "{:?}", h.tree());

    h.admit_delete("a/x", &h.emitter);
    let attempt = h.pass(&["a/x"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    h.retire_copies().await;

    assert_eq!(holding(&h, b"file A"), vec!["A".to_string()], "{:?}", h.tree());
    assert!(h.copies_of("A").is_empty(), "{:?}", h.tree());
}

/// A copy name this device ignores never receives the relocated file, so
/// the file must not leave its own name: its bytes would be on no path on
/// this disk.
#[tokio::test]
async fn a_relocation_whose_copy_name_is_ignored_keeps_the_file() {
    let h = Harness::new();
    h.ignore_copy_names();
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit("a", &a, &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);

    let attempt = h.pass(&["a/x"]).await;

    assert!(!attempt.is_settled("a"), "{attempt:?}");
    assert_eq!(holding(&h, b"file a"), vec!["a".to_string()], "{:?}", h.tree());
}

/// A File that loses its name to a concurrent explicit Directory leaves
/// only once its conflict copy is on disk; a copy name this device ignores
/// never is.
#[tokio::test]
async fn a_file_displaced_by_a_directory_stays_until_its_copy_is_written() {
    let h = Harness::new();
    h.ignore_copy_names();
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit_onto(vec![], vec![create_op("a", &a)], std::slice::from_ref(&a), &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[5u8; 32]));
    let directory = FileVersion::directory(None);
    h.admit_onto(vec![], vec![create_op("a", &directory)], std::slice::from_ref(&directory), &peer);

    let attempt = h.pass(&["a"]).await;

    assert!(!attempt.is_settled("a"), "{attempt:?}");
    assert_eq!(holding(&h, b"file a"), vec!["a".to_string()], "{:?}", h.tree());
}

/// A File and an explicit Directory written concurrently at one name: the
/// Directory takes the name whichever head the per-path order prefers,
/// and the File lives beside it at its copy name.
#[tokio::test]
async fn a_concurrent_directory_takes_the_name_and_the_file_moves_beside_it() {
    for directory_first in [false, true] {
        let h = Harness::new();
        let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[5u8; 32]));
        let a = version_for(&h.state, &h.store, b"file a");
        let directory = FileVersion::directory(None);
        let file_op = || create_op("a", &a);
        let dir_op = || create_op("a", &directory);
        if directory_first {
            h.admit_onto(vec![], vec![dir_op()], std::slice::from_ref(&directory), &peer);
            h.admit_onto(vec![], vec![file_op()], std::slice::from_ref(&a), &h.emitter);
        } else {
            h.admit_onto(vec![], vec![file_op()], std::slice::from_ref(&a), &h.emitter);
            h.admit_onto(vec![], vec![dir_op()], std::slice::from_ref(&directory), &peer);
        }

        let attempt = h.pass(&["a"]).await;

        assert!(attempt.retry.is_empty(), "{:?} {:?}", attempt.retry, h.tree());
        assert!(std::fs::symlink_metadata(h.root.path().join("a")).unwrap().is_dir());
        let copies = h.copies_of("a");
        assert_eq!(copies.len(), 1, "{:?}", h.tree());
        assert_eq!(copies[0].1, b"file a");
    }
}

/// `rm -rf a; echo > a` on one peer while another adds `a/y`: `a` stays
/// the directory `a/y` needs, and the Directory entry it was is settled
/// as superseded, so the path's obligation can close.
#[tokio::test]
async fn a_superseded_directory_kept_for_a_concurrent_child_is_no_longer_its_entry() {
    let h = Harness::new();
    let x = version_for(&h.state, &h.store, b"file a/x");
    let base = h.admit_many(
        vec![create_op("a", &FileVersion::directory(None)), create_op("a/x", &x)],
        &[FileVersion::directory(None), x.clone()],
    );
    assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());
    let file = version_for(&h.state, &h.store, b"now a file");
    h.admit_many(vec![delete("a/x"), create_op("a", &file)], std::slice::from_ref(&file));
    let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[5u8; 32]));
    let y = version_for(&h.state, &h.store, b"a concurrent child");
    h.admit_onto(
        vec![base.change_hash()],
        vec![create_op("a/y", &y)],
        std::slice::from_ref(&y),
        &peer,
    );

    let attempt = h.pass(&["a", "a/x", "a/y"]).await;

    assert!(attempt.retry.is_empty(), "{:?} {:?}", attempt.retry, h.tree());
    assert!(h.root.path().join("a").is_dir());
    assert_eq!(std::fs::read(h.root.path().join("a/y")).unwrap(), b"a concurrent child");
    assert_eq!(holding(&h, b"now a file").len(), 1, "{:?}", h.tree());
    assert!(
        h.state.get_file(GROUP, "a").unwrap().is_none_or(|row| row.deleted),
        "a live Directory row at a structural directory makes its proof unpublishable"
    );
    assert_eq!(h.structural_status("a"), StructuralOriginStatus::Structural);

    h.admit_delete("a/y", &h.emitter);
    let attempt = h.pass(&["a/y"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    h.retire_copies().await;
    assert_eq!(std::fs::read(h.root.path().join("a")).unwrap(), b"now a file", "{:?}", h.tree());
    assert!(h.copies_of("a").is_empty(), "{:?}", h.tree());
}

/// Once the directory that held an entry's name is gone, the entry takes
/// its name again and the copy that held it meanwhile retires: a retained
/// record of the old directory no longer justifies it.
#[tokio::test]
async fn a_file_written_back_to_its_name_retires_its_held_copy() {
    let h = Harness::new();
    file_then_descendant(&h).await;
    std::fs::write(h.root.path().join("a/.DS_Store"), b"finder").unwrap();
    h.admit_delete("a/x", &h.emitter);
    assert!(h.pass(&["a/x"]).await.retry.is_empty());
    assert_eq!(h.copies_of("a").len(), 1);

    std::fs::remove_file(h.root.path().join("a/.DS_Store")).unwrap();
    std::fs::remove_dir(h.root.path().join("a")).unwrap();
    let attempt = h.pass(&["a"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    h.retire_copies().await;

    assert_eq!(holding(&h, b"file a"), vec!["a".to_string()], "{:?}", h.tree());
}

/// A sibling whose live version has not arrived yet leaves the level
/// undecidable: the path that needs it retries, and the pass goes on.
#[tokio::test]
async fn an_unresolvable_sibling_retries_the_path_not_the_pass() {
    let h = Harness::new();
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit("a", &a, &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    let missing = version_for(&h.state, &h.store, b"a version this device lacks");
    h.admit("b", &missing, &h.emitter);
    // Its version has not arrived here.
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                rusqlite::params![GROUP, &missing.version_hash.0[..]],
            )?;
            Ok(())
        })
        .unwrap();
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);

    let attempt = h
        .convergence
        .reconcile_paths(GROUP, ["a/x".to_string()].into_iter().collect())
        .await
        .expect("one undecidable sibling must not fail the pass")
        .expect("a live link runs the pass");

    assert!(!attempt.is_settled("a"), "{attempt:?}");
    assert_eq!(holding(&h, b"file a"), vec!["a".to_string()], "{:?}", h.tree());
}

/// `rm -rf a; echo > a` split across passes: while tracked children of
/// the replaced directory still wait for their deletes, the directory is
/// not "untracked content" -- the path retries, and the pass that removes
/// the last child puts the file in place.
#[tokio::test]
async fn a_directory_still_holding_tracked_children_is_not_retained() {
    let h = Harness::new();
    let x = version_for(&h.state, &h.store, b"file a/x");
    let y = version_for(&h.state, &h.store, b"file a/y");
    h.admit_many(
        vec![
            create_op("a", &FileVersion::directory(None)),
            create_op("a/x", &x),
            create_op("a/y", &y),
        ],
        &[FileVersion::directory(None), x.clone(), y.clone()],
    );
    assert!(h.pass(&["a", "a/x", "a/y"]).await.retry.is_empty());
    let file = version_for(&h.state, &h.store, b"now a file");
    h.admit_many(
        vec![delete("a/x"), delete("a/y"), create_op("a", &file)],
        std::slice::from_ref(&file),
    );

    let attempt = h.pass(&["a", "a/x"]).await;
    assert!(!attempt.is_settled("a"), "{attempt:?}");
    assert!(h.copies_of("a").is_empty(), "{:?}", h.tree());
    assert_eq!(h.state.retained_directory_reason(GROUP, "a").unwrap(), None);

    let attempt = h.pass(&["a/y"]).await;
    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert_eq!(std::fs::read(h.root.path().join("a")).unwrap(), b"now a file", "{:?}", h.tree());
    assert!(h.copies_of("a").is_empty(), "{:?}", h.tree());
}

/// A file this device never captured, standing where a directory has to
/// go, is never removed: the descendant waits, and the file is intact.
#[tokio::test]
async fn an_uncaptured_file_where_a_directory_must_go_is_never_removed() {
    let h = Harness::new();
    std::fs::write(h.root.path().join("a"), b"the user's own file").unwrap();
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);

    let attempt = h.pass(&["a/x"]).await;

    assert!(!attempt.is_settled("a/x"), "{attempt:?}");
    assert_eq!(std::fs::read(h.root.path().join("a")).unwrap(), b"the user's own file");
}

/// A delete of a path that never reached this disk, below a name a File
/// holds: nothing can be at `a/x` while `a` is a file, which is an
/// observed absence, not a reason to retry.
#[tokio::test]
async fn a_delete_below_a_file_settles_as_absent() {
    let h = Harness::new();
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit("a", &a, &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);
    h.admit_delete("a/x", &h.emitter);

    let attempt = h.pass(&["a/x"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert_eq!(std::fs::read(h.root.path().join("a")).unwrap(), b"file a", "{:?}", h.tree());
}

/// A symlink version to `target`, recorded in the platform's own captured
/// target encoding (UTF-16LE code units on Windows).
fn symlink_to(target: &str) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: Some(yadorilink_root_authority::fs_identity::target_to_bytes(
                std::path::Path::new(target),
            )),
            record_kind: RecordKind::Symlink,
            xattrs: Vec::new(),
        },
    )
}

/// Every entry directly under the root that is a symlink to `target`.
fn links_to(h: &Harness, target: &str) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(h.root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| std::fs::read_link(path).is_ok_and(|to| to == std::path::Path::new(target)))
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// Symlink `A` (to `target`) and a live `a/x` on a volume that folds
/// case: the lookup of `a` finds the link itself, never what it points to,
/// so the link is recognised as the leaf in the way and moves beside `a`
/// under its copy name. Nothing retries.
async fn case_fold_symlink_vs_descendant(h: &Harness, target: &str) {
    let link = symlink_to(target);
    h.admit("A", &link, &h.emitter);
    assert!(h.pass(&["A"]).await.is_settled("A"));
    assert_eq!(links_to(h, target), vec!["A".to_string()], "sanity: {:?}", h.tree());
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);

    let attempt = h.pass(&["a/x"]).await;

    assert!(attempt.retry.is_empty(), "{:?} {:?}", attempt.retry, h.tree());
    assert_eq!(std::fs::read(h.root.path().join("a/x")).unwrap(), b"file a/x");
    let links = links_to(h, target);
    assert_eq!(links.len(), 1, "{links:?}");
    assert!(
        is_conflict_copy_path(&links[0]) && conflict_copy_source_path(&links[0]) == "A",
        "{links:?}"
    );
    let again = h.pass(&["A", "a/x"]).await;
    assert!(again.retry.is_empty(), "{:?}", again.retry);
    assert_eq!(links_to(h, target), links);
}

#[tokio::test]
async fn case_fold_symlink_upper_a_vs_a_slash_x_keeps_both() {
    let h = Harness::new();
    if !case_folds(&h) {
        return;
    }
    let t = version_for(&h.state, &h.store, b"link target");
    h.admit("t", &t, &h.emitter);
    assert!(h.pass(&["t"]).await.is_settled("t"));
    case_fold_symlink_vs_descendant(&h, "t").await;
}

#[tokio::test]
async fn case_fold_dangling_symlink_upper_a_vs_a_slash_x_keeps_both() {
    let h = Harness::new();
    if !case_folds(&h) {
        return;
    }
    case_fold_symlink_vs_descendant(&h, "nowhere").await;
}

use super::super::namespace_steps::displacement_crash::{self, Stage, Stop};

/// Moving File `a` aside for `a/x` stops partway -- with its copy written
/// and its delete intent open, or with `a` unlinked and its index row not
/// yet erased -- by a crash that ends the pass, or by an error the pass
/// goes on past. Then startup repair runs, as after a restart, and a pass
/// over the same paths. The file's bytes are on disk at every point, and
/// the next pass converges to the tree an uninterrupted pass builds,
/// authoring nothing and leaving no stray copy.
async fn displacement_stopped_then_restarted(stage: Stage, stop: Stop) {
    let h = Harness::new();
    let a = version_for(&h.state, &h.store, b"file a");
    h.admit("a", &a, &h.emitter);
    assert!(h.pass(&["a"]).await.is_settled("a"));
    let x = version_for(&h.state, &h.store, b"file a/x");
    h.admit("a/x", &x, &h.emitter);
    let heads = h.state.dag_group_heads(GROUP).unwrap();
    // The pass may see the root under either spelling (macOS tempdirs sit
    // behind the /var -> /private/var symlink). Where both are the same
    // path, arming it twice would leave one stop armed after the pass
    // fired the other, so arm each distinct path once.
    let mut leaves = vec![h.root.path().join("a"), h.root.path().canonicalize().unwrap().join("a")];
    leaves.dedup();
    for leaf in &leaves {
        displacement_crash::arm(leaf, stage, stop);
    }

    let convergence = h.convergence.clone();
    let stopped = tokio::spawn(async move {
        convergence.reconcile_paths(GROUP, ["a/x".to_string()].into()).await.map(|_| ())
    })
    .await;

    assert!(
        leaves.iter().any(|leaf| !displacement_crash::is_armed(leaf, stage)),
        "{stage:?}: the pass never reached the stop"
    );
    for leaf in &leaves {
        displacement_crash::disarm(leaf, stage);
    }
    assert_eq!(stopped.is_err(), stop == Stop::Crash, "{stage:?} {stop:?}: {stopped:?}");
    let what = format!("{stage:?} {stop:?}");
    assert!(!holding(&h, b"file a").is_empty(), "{what}: lost at the stop: {:?}", h.tree());

    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        h.state.as_ref(),
        h.store.as_ref(),
        h.root.path(),
        GROUP,
        yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert!(!holding(&h, b"file a").is_empty(), "{what}: lost by repair: {:?}", h.tree());

    let attempt = h.pass(&["a", "a/x"]).await;
    assert!(attempt.retry.is_empty(), "{what}: {:?} {:?}", attempt.retry, h.tree());
    let again = h.pass(&["a", "a/x"]).await;
    assert!(again.retry.is_empty(), "{what}: {:?}", again.retry);
    assert_eq!(
        h.tree(),
        vec![
            ("a".to_string(), None),
            (h.copies_of("a")[0].0.clone(), Some(b"file a".to_vec())),
            ("a/x".to_string(), Some(b"file a/x".to_vec())),
        ],
        "{what}"
    );
    assert_eq!(h.state.dag_group_heads(GROUP).unwrap(), heads, "{what}: authored a change");
    assert!(
        !h.state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "a")
            .unwrap(),
        "{what}: the interrupted intent is still open"
    );
}

#[tokio::test]
async fn a_crash_after_the_copy_is_written_converges_on_restart() {
    displacement_stopped_then_restarted(Stage::BeforeUnlink, Stop::Crash).await;
}

#[tokio::test]
async fn a_crash_after_the_unlink_converges_on_restart() {
    displacement_stopped_then_restarted(Stage::BeforeRowErase, Stop::Crash).await;
}

#[tokio::test]
async fn an_error_after_the_copy_is_written_converges_on_the_next_pass() {
    displacement_stopped_then_restarted(Stage::BeforeUnlink, Stop::Error).await;
}

#[tokio::test]
async fn an_error_after_the_unlink_converges_on_the_next_pass() {
    displacement_stopped_then_restarted(Stage::BeforeRowErase, Stop::Error).await;
}

// --- P9-C: directory materialization steps, stopped and restarted --------
//
// Every step of materializing the namespace's directories that writes the
// disk and the index separately: making a structural container, adopting
// a superseded directory entry's directory as structural, and removing a
// directory made for descendants or one an entry supersedes. Each is
// stopped right after its disk write -- by a crash that ends the pass (then
// startup repair runs, as after a restart), or by an error the pass goes
// on past -- and the passes after it must converge to the tree an
// uninterrupted pass builds, authoring nothing, leaving no directory
// record (structural or retained) for a directory that is gone and no
// intent open.

/// Stops the pass over `crashing` at `stage` on the path `at`, then runs
/// startup repair and two passes over `restart`, each of which must settle
/// every path. Returns a label for the stop.
async fn namespace_step_stopped_then_restarted(
    h: &Harness,
    stage: Stage,
    stop: Stop,
    at: &str,
    crashing: &[&str],
    restart: &[&str],
) -> String {
    let what = format!("{stage:?} {stop:?} at {at}");
    let heads = h.state.dag_group_heads(GROUP).unwrap();
    // As in `displacement_stopped_then_restarted`: where the root is already
    // canonical (Linux tempdirs) both spellings are one path, and arming it
    // twice would leave one stop armed after the pass fired the other.
    let mut targets = vec![h.root.path().join(at), h.root.path().canonicalize().unwrap().join(at)];
    targets.dedup();
    for target in &targets {
        displacement_crash::arm(target, stage, stop);
    }
    let convergence = h.convergence.clone();
    let paths: std::collections::BTreeSet<String> =
        crashing.iter().map(|path| path.to_string()).collect();
    let stopped =
        tokio::spawn(async move { convergence.reconcile_paths(GROUP, paths).await.map(|_| ()) })
            .await;
    let reached = targets.iter().any(|target| !displacement_crash::is_armed(target, stage));
    for target in &targets {
        displacement_crash::disarm(target, stage);
    }
    assert!(reached, "{what}: the pass never reached the stop: {:?}", h.tree());
    if stop == Stop::Crash {
        assert!(stopped.is_err(), "{what}: {stopped:?}");
    }

    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        h.state.as_ref(),
        h.store.as_ref(),
        h.root.path(),
        GROUP,
        yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    let attempt = h.pass(restart).await;
    assert!(attempt.retry.is_empty(), "{what}: {:?} {:?}", attempt.retry, h.tree());
    let again = h.pass(restart).await;
    assert!(again.retry.is_empty(), "{what}: {:?}", again.retry);
    assert_eq!(h.state.dag_group_heads(GROUP).unwrap(), heads, "{what}: authored a change");
    for path in crashing.iter().chain(restart) {
        assert!(
            !h.state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, path)
                .unwrap(),
            "{what}: an interrupted intent is still open at {path}"
        );
    }
    what
}

/// No directory record -- structural origin or retained -- for `path`,
/// which holds no directory any more.
fn assert_no_directory_record(h: &Harness, path: &str, what: &str) {
    assert!(
        matches!(
            h.state.sqlite().dag_structural_directory_origin(GROUP, path).unwrap(),
            yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin::None
        ),
        "{what}: {path} holds no directory and is still recorded as structural"
    );
    assert_eq!(
        h.state.sqlite().retained_directory_reason(GROUP, path).unwrap(),
        None,
        "{what}: {path} holds no directory and is still recorded as retained"
    );
}

const STOPS: [Stop; 2] = [Stop::Crash, Stop::Error];

/// Making the structural container File `a` leaves for `a/x`, stopped
/// right after the `mkdir`: the container stays structural, and goes (with
/// the file back at its name) once `a/x` is deleted.
#[tokio::test]
async fn a_structural_container_stopped_after_its_mkdir_converges() {
    for stop in STOPS {
        let h = Harness::new();
        let a = version_for(&h.state, &h.store, b"file a");
        h.admit("a", &a, &h.emitter);
        assert!(h.pass(&["a"]).await.is_settled("a"));
        let x = version_for(&h.state, &h.store, b"file a/x");
        h.admit("a/x", &x, &h.emitter);

        let what = namespace_step_stopped_then_restarted(
            &h,
            Stage::AfterStructuralMkdir,
            stop,
            "a",
            &["a/x"],
            &["a", "a/x"],
        )
        .await;

        assert_eq!(
            h.tree(),
            vec![
                ("a".to_string(), None),
                (h.copies_of("a")[0].0.clone(), Some(b"file a".to_vec())),
                ("a/x".to_string(), Some(b"file a/x".to_vec())),
            ],
            "{what}"
        );
        assert_eq!(h.structural_status("a"), StructuralOriginStatus::Structural, "{what}");

        h.admit_delete("a/x", &h.emitter);
        assert!(h.pass(&["a/x"]).await.retry.is_empty(), "{what}");
        h.retire_copies().await;
        assert_eq!(holding(&h, b"file a"), vec!["a".to_string()], "{what}: {:?}", h.tree());
    }
}

/// A peer's `rm -rf`, stopped right after the deepest directory made for
/// it is removed: the rest of the tree still goes, and no record of either
/// directory is left.
#[tokio::test]
async fn a_structural_rmdir_stopped_before_its_record_is_forgotten_converges() {
    for stop in STOPS {
        let h = Harness::new();
        let makefile = version_for(&h.state, &h.store, b"all:");
        let setup = version_for(&h.state, &h.store, b"int main;");
        h.admit_many(
            vec![create_op("linux/Makefile", &makefile), create_op("linux/arch/setup.c", &setup)],
            &[makefile.clone(), setup.clone()],
        );
        assert!(h.pass(&["linux/Makefile", "linux/arch/setup.c"]).await.retry.is_empty());
        h.admit_many(vec![delete("linux/Makefile"), delete("linux/arch/setup.c")], &[]);

        let paths = ["linux/Makefile", "linux/arch/setup.c"];
        let what = namespace_step_stopped_then_restarted(
            &h,
            Stage::AfterStructuralRmdir,
            stop,
            "linux/arch",
            &paths,
            &paths,
        )
        .await;

        assert!(h.tree().is_empty(), "{what}: left behind: {:?}", h.tree());
        for path in ["linux", "linux/arch"] {
            assert_no_directory_record(&h, path, &what);
        }
    }
}

/// A replicated directory replaced by a file, stopped right after the
/// empty directory is removed: the file takes the name, and no record of
/// the directory is left. `a` is an explicit entry here and never had a
/// structural or retained record, so the last assertion only guards
/// against one appearing; the retained record a stop can leave behind is
/// the next test's.
#[tokio::test]
async fn a_superseded_directory_rmdir_stopped_before_its_record_is_forgotten_converges() {
    for stop in STOPS {
        let h = Harness::new();
        let x = version_for(&h.state, &h.store, b"file a/x");
        h.admit_many(
            vec![create_op("a", &FileVersion::directory(None)), create_op("a/x", &x)],
            &[FileVersion::directory(None), x.clone()],
        );
        assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());
        let file = version_for(&h.state, &h.store, b"now a file");
        h.admit_many(vec![delete("a/x"), create_op("a", &file)], std::slice::from_ref(&file));

        let what = namespace_step_stopped_then_restarted(
            &h,
            Stage::AfterSupersededRmdir,
            stop,
            "a",
            &["a", "a/x"],
            &["a", "a/x"],
        )
        .await;

        assert_eq!(h.tree(), vec![("a".to_string(), Some(b"now a file".to_vec()))], "{what}");
        assert!(h.copies_of("a").is_empty(), "{what}: {:?}", h.tree());
        assert_no_directory_record(&h, "a", &what);
    }
}

/// A replicated directory replaced by a file while the user's own file
/// kept it on disk: it is retained, removable once empty, and the file
/// waits at its copy name. Once the user's file is gone, the pass removes
/// the directory and is stopped before the retained record is forgotten:
/// the restart must forget it, the file takes the name and its copy
/// retires.
#[tokio::test]
async fn a_retained_superseded_directory_rmdir_stopped_before_its_record_is_forgotten_converges() {
    for stop in STOPS {
        let h = Harness::new();
        let x = version_for(&h.state, &h.store, b"file a/x");
        h.admit_many(
            vec![create_op("a", &FileVersion::directory(None)), create_op("a/x", &x)],
            &[FileVersion::directory(None), x.clone()],
        );
        assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());
        std::fs::write(h.root.path().join("a/.DS_Store"), b"finder").unwrap();
        let file = version_for(&h.state, &h.store, b"now a file");
        h.admit_many(vec![delete("a/x"), create_op("a", &file)], std::slice::from_ref(&file));
        assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());
        assert!(
            h.state.sqlite().retained_directory_reason(GROUP, "a").unwrap().is_some(),
            "{stop:?}: the directory the user's file keeps is not retained: {:?}",
            h.tree()
        );
        assert_eq!(h.copies_of("a").len(), 1, "{stop:?}: {:?}", h.tree());

        std::fs::remove_file(h.root.path().join("a/.DS_Store")).unwrap();
        let what = namespace_step_stopped_then_restarted(
            &h,
            Stage::AfterSupersededRmdir,
            stop,
            "a",
            &["a"],
            &["a"],
        )
        .await;

        h.retire_copies().await;
        assert_eq!(holding(&h, b"now a file"), vec!["a".to_string()], "{what}: {:?}", h.tree());
        assert_no_directory_record(&h, "a", &what);
    }
}

/// A superseded explicit Directory entry kept for a concurrent child,
/// stopped after its directory is adopted as structural and before the
/// entry's row is erased: the next pass erases it, the directory stays
/// structural, and it goes (with the file back) after the last child.
#[tokio::test]
async fn a_superseded_directory_entry_stopped_before_it_is_retired_converges() {
    for stop in STOPS {
        let h = Harness::new();
        let x = version_for(&h.state, &h.store, b"file a/x");
        let base = h.admit_many(
            vec![create_op("a", &FileVersion::directory(None)), create_op("a/x", &x)],
            &[FileVersion::directory(None), x.clone()],
        );
        assert!(h.pass(&["a", "a/x"]).await.retry.is_empty());
        let file = version_for(&h.state, &h.store, b"now a file");
        h.admit_many(vec![delete("a/x"), create_op("a", &file)], std::slice::from_ref(&file));
        let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[5u8; 32]));
        let y = version_for(&h.state, &h.store, b"a concurrent child");
        h.admit_onto(
            vec![base.change_hash()],
            vec![create_op("a/y", &y)],
            std::slice::from_ref(&y),
            &peer,
        );

        let paths = ["a", "a/x", "a/y"];
        let what = namespace_step_stopped_then_restarted(
            &h,
            Stage::BeforeEntryRetired,
            stop,
            "a",
            &paths,
            &paths,
        )
        .await;

        assert!(h.root.path().join("a").is_dir(), "{what}: {:?}", h.tree());
        assert_eq!(std::fs::read(h.root.path().join("a/y")).unwrap(), b"a concurrent child");
        assert_eq!(holding(&h, b"now a file").len(), 1, "{what}: {:?}", h.tree());
        assert!(
            h.state.get_file(GROUP, "a").unwrap().is_none_or(|row| row.deleted),
            "{what}: the superseded Directory row is still live"
        );
        assert_eq!(h.structural_status("a"), StructuralOriginStatus::Structural, "{what}");

        h.admit_delete("a/y", &h.emitter);
        assert!(h.pass(&["a/y"]).await.retry.is_empty(), "{what}");
        h.retire_copies().await;
        assert_eq!(
            std::fs::read(h.root.path().join("a")).unwrap(),
            b"now a file",
            "{what}: {:?}",
            h.tree()
        );
        assert_no_directory_record(&h, "a", &what);
    }
}

/// What sits at a conflict-copy name of `source` directly beside it:
/// `(name, is_directory)`, sorted. `symlink_metadata`, so a dangling link
/// is listed as itself.
fn copy_nodes_of(h: &Harness, source: &str) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = std::fs::read_dir(h.root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| is_conflict_copy_path(name) && conflict_copy_source_path(name) == source)
        .map(|name| {
            let is_directory =
                std::fs::symlink_metadata(h.root.path().join(&name)).unwrap().is_dir();
            (name, is_directory)
        })
        .collect();
    out.sort();
    out
}

/// One arrival of the File/Symlink-vs-Directory race below.
#[derive(Clone, Copy, Debug)]
enum Arrival {
    Leaf,
    Directory,
    Descendant,
}

/// DIR-1 on the live reconcile path. A File or Symlink at `a` races a
/// peer's `mkdir a` and `a/x`, in either rank order, and the three arrive
/// in every order: the Directory before `a/x` and after it, the leaf
/// first, in the middle and last. The Directory keeps `a` every time, `a/x`
/// lives in it, and the leaf sits beside it at its copy name. No directory
/// is ever written at a copy name: not by reconcile, and not by
/// retroactive repair, which carries the Directory forward at `a` and
/// owes the leaf, not the Directory, its copy.
#[tokio::test]
async fn an_explicit_directory_keeps_its_name_against_a_leaf_in_every_arrival_order() {
    use Arrival::{Descendant, Directory, Leaf};
    // All six: the leaf first, in the middle, and last.
    let orders: [[Arrival; 3]; 6] = [
        [Leaf, Directory, Descendant],
        [Leaf, Descendant, Directory],
        [Directory, Leaf, Descendant],
        [Descendant, Leaf, Directory],
        [Directory, Descendant, Leaf],
        [Descendant, Directory, Leaf],
    ];
    for leaf_is_symlink in [false, true] {
        for leaf_ranks_higher in [true, false] {
            for order in orders {
                leaf_vs_directory(leaf_is_symlink, leaf_ranks_higher, order).await;
            }
        }
    }
}

/// One case of the race below, on a fresh replica.
async fn leaf_vs_directory(leaf_is_symlink: bool, leaf_ranks_higher: bool, order: [Arrival; 3]) {
    use Arrival::{Descendant, Directory, Leaf};
    let label = format!("symlink: {leaf_is_symlink}, leaf higher: {leaf_ranks_higher}, {order:?}");
    let h = Harness::new();
    let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[5u8; 32]));
    // `a/x` comes from a third device, so each author's changes
    // stay one chain whatever the order.
    let third = ChangeEmitter::new("device-third", SigningKey::from_bytes(&[6u8; 32]));
    let leaf = if leaf_is_symlink {
        symlink_to("target")
    } else {
        version_for(&h.state, &h.store, b"file a")
    };
    let directory = FileVersion::directory(None);
    let x = version_for(&h.state, &h.store, b"file a/x");
    // Only raises the higher side's Lamport.
    let filler = version_for(&h.state, &h.store, b"filler");
    let (filler_path, filler_emitter) =
        if leaf_ranks_higher { ("filler-leaf", &h.emitter) } else { ("filler-dir", &peer) };
    let raised = h
        .admit_onto(
            vec![],
            vec![create_op(filler_path, &filler)],
            std::slice::from_ref(&filler),
            filler_emitter,
        )
        .change_hash();
    let (leaf_parents, dir_parents) =
        if leaf_ranks_higher { (vec![raised], vec![]) } else { (vec![], vec![raised]) };
    for arrival in order {
        let path = match arrival {
            Leaf => {
                h.admit_onto(
                    leaf_parents.clone(),
                    vec![create_op("a", &leaf)],
                    std::slice::from_ref(&leaf),
                    &h.emitter,
                );
                "a"
            }
            Directory => {
                h.admit_onto(
                    dir_parents.clone(),
                    vec![create_op("a", &directory)],
                    std::slice::from_ref(&directory),
                    &peer,
                );
                "a"
            }
            Descendant => {
                h.admit_onto(vec![], vec![create_op("a/x", &x)], std::slice::from_ref(&x), &third);
                "a/x"
            }
        };
        let _ = h.pass(&[path]).await;
    }
    let emitter = ChangeEmitter::new("device-local", SigningKey::from_bytes(&[3u8; 32]));
    h.state.repair_retroactive_conflict_copy_obligations(GROUP, &emitter, 0).unwrap();
    // The repair carries the Directory forward at `a` and makes the leaf's
    // copy durable, in either rank order: `a` has one live head left, the
    // Directory.
    let a_heads = h
        .state
        .database()
        .read(|conn| yadorilink_sync_sqlite::dag_store::live_path_heads(conn, GROUP, "a"))
        .unwrap();
    assert_eq!(
        a_heads
            .iter()
            .map(|head| head.content.as_ref().map(|content| content.version_hash))
            .collect::<Vec<_>>(),
        vec![Some(directory.version_hash.0)],
        "{label}: {a_heads:?}"
    );
    let mut paths = vec!["a".to_string(), "a/x".to_string()];
    paths.extend(copy_nodes_of(&h, "a").into_iter().map(|(name, _)| name));
    let projection = h
        .state
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::desired_state::desired_namespace_projection(conn, GROUP)
        })
        .unwrap();
    paths.extend(projection.nodes().keys().cloned());
    paths.sort();
    paths.dedup();
    let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
    let attempt = h.pass(&paths).await;
    assert!(attempt.retry.is_empty(), "{label}: {:?} {:?}", attempt.retry, h.tree());

    let directories: Vec<&String> = projection
        .nodes()
        .iter()
        .filter(|(_, node)| node.is_directory())
        .map(|(name, _)| name)
        .collect();
    assert_eq!(directories, vec!["a"], "{label}: {projection:?}");
    assert!(
        std::fs::symlink_metadata(h.root.path().join("a")).unwrap().is_dir(),
        "{label}: {:?}",
        h.tree()
    );
    assert_eq!(std::fs::read(h.root.path().join("a/x")).unwrap(), b"file a/x", "{label}");
    let copies = copy_nodes_of(&h, "a");
    assert_eq!(copies.len(), 1, "{label}: {copies:?}");
    assert!(!copies[0].1, "{label}: a directory at a copy name: {copies:?}");
    let copy = h.root.path().join(&copies[0].0);
    if leaf_is_symlink {
        assert_eq!(std::fs::read_link(&copy).unwrap(), std::path::Path::new("target"), "{label}");
    } else {
        assert_eq!(std::fs::read(&copy).unwrap(), b"file a", "{label}");
    }
}
