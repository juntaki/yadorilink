//! The directory lane: a Directory version
//! becomes a real directory, a Directory tombstone a non-recursive
//! `rmdir`, and a directory that is not empty when its entry is deleted is
//! kept -- with everything in it -- and settled as retained, never retried
//! forever: the sync engine deletes nothing it does not replicate.

use super::*;
use yadorilink_sync_sqlite::structural_origin::{
    StructuralDirectoryOrigin, StructuralOriginStatus, RETAINED_REPLACED_LOCALLY,
    RETAINED_UNTRACKED_CONTENT,
};

impl Harness {
    /// Emits and admits one change carrying every op in `ops`, the way a
    /// peer's recursive delete arrives: several point deletes in one
    /// change.
    fn admit_ops(&self, ops: Vec<Op>, versions: &[FileVersion]) -> Change {
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

    async fn reconcile(&self, paths: &[&str]) -> ProjectionAttempt {
        self.convergence
            .reconcile_paths(GROUP, paths.iter().map(|p| p.to_string()).collect())
            .await
            .unwrap()
            .expect("a live link runs the pass")
    }

    fn origin_status(&self, path: &str) -> StructuralOriginStatus {
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
}

fn delete_op(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

/// Under the on-demand policy a file becomes a placeholder, but a
/// directory has no content to defer. It is created for real.
#[tokio::test]
async fn an_on_demand_directory_version_materializes_as_a_real_directory() {
    let h = Harness::new();
    h.state
        .link_repository()
        .set_materialization_policy(
            &h.root.path().to_string_lossy(),
            MaterializationPolicy::OnDemand,
        )
        .unwrap();
    let directory = FileVersion::directory(None);
    h.admit("docs", &directory, &h.emitter);

    let attempt = h.reconcile(&["docs"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(
        matches!(
            attempt.evidence_for("docs"),
            Some(SettlementEvidence::ExactObject { kind: RecordKind::Directory, .. })
        ),
        "got {:?}",
        attempt.evidence_for("docs")
    );
    assert!(std::fs::symlink_metadata(h.root.path().join("docs")).unwrap().is_dir());
}

/// The directories created only to hold an explicit directory are
/// recorded as structural; the explicit directory itself is not.
#[tokio::test]
async fn a_nested_directory_version_records_only_its_created_ancestors_as_structural() {
    let h = Harness::new();
    h.admit("p/q/leaf", &FileVersion::directory(None), &h.emitter);

    let attempt = h.reconcile(&["p/q/leaf"]).await;

    assert!(attempt.is_settled("p/q/leaf"), "{:?}", attempt.retry);
    assert_eq!(h.origin_status("p"), StructuralOriginStatus::Structural);
    assert_eq!(h.origin_status("p/q"), StructuralOriginStatus::Structural);
    assert_eq!(
        h.state.sqlite().dag_structural_directory_origin(GROUP, "p/q/leaf").unwrap(),
        StructuralDirectoryOrigin::None
    );
}

/// The parents a file's materialization creates are structural as well.
#[tokio::test]
async fn a_files_created_parents_are_recorded_as_structural() {
    let h = Harness::new();
    let file = version_for(&h.state, &h.store, b"a file two levels down");
    h.admit("m/n/f.txt", &file, &h.emitter);

    let attempt = h.reconcile(&["m/n/f.txt"]).await;

    assert!(attempt.is_settled("m/n/f.txt"), "{:?}", attempt.retry);
    assert_eq!(h.origin_status("m"), StructuralOriginStatus::Structural);
    assert_eq!(h.origin_status("m/n"), StructuralOriginStatus::Structural);
}

/// A Directory tombstone removes the (empty) directory and settles
/// exact-absent.
#[tokio::test]
async fn directory_tombstone_removes_empty_directory_and_settles() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    assert!(h.root.path().join("a").is_dir());

    h.admit_delete("a", &h.emitter);
    let attempt = h.reconcile(&["a"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(
        matches!(attempt.evidence_for("a"), Some(SettlementEvidence::ExactAbsent { .. })),
        "got {:?}",
        attempt.evidence_for("a")
    );
    assert!(std::fs::symlink_metadata(h.root.path().join("a")).is_err());
}

/// A Directory tombstone over a directory holding
/// things this device does not replicate -- the `.DS_Store` every Finder
/// window leaves, a note the user has not had captured -- keeps the
/// directory and everything in it, and settles as retained. It is not
/// retried: a second pass settles the same way at once.
#[tokio::test]
async fn directory_tombstone_over_untracked_content_settles_retained_without_retry() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    std::fs::write(h.root.path().join("a/.DS_Store"), b"finder state").unwrap();
    std::fs::write(h.root.path().join("a/notes.txt"), b"not captured yet").unwrap();

    h.admit_delete("a", &h.emitter);
    let attempt = h.reconcile(&["a"]).await;

    assert!(attempt.retry.is_empty(), "a retained directory must not retry: {:?}", attempt.retry);
    assert!(
        matches!(attempt.evidence_for("a"), Some(SettlementEvidence::Retained { .. })),
        "got {:?}",
        attempt.evidence_for("a")
    );
    assert_eq!(std::fs::read(h.root.path().join("a/.DS_Store")).unwrap(), b"finder state");
    assert_eq!(std::fs::read(h.root.path().join("a/notes.txt")).unwrap(), b"not captured yet");
    assert_eq!(
        h.state.retained_directory_reason(GROUP, "a").unwrap().as_deref(),
        Some(RETAINED_UNTRACKED_CONTENT)
    );
    assert!(h.state.get_file(GROUP, "a").unwrap().is_some_and(|row| row.deleted));

    let again = h.reconcile(&["a"]).await;
    assert!(again.retry.is_empty(), "a second pass must not retry either: {:?}", again.retry);
    assert!(again.is_settled("a"));
    assert!(h.root.path().join("a/.DS_Store").exists());
}

/// Once what kept a retained directory is gone, the next pass over it
/// removes it.
#[tokio::test]
async fn a_retained_directory_is_removed_once_it_is_empty() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    std::fs::write(h.root.path().join("a/.DS_Store"), b"finder state").unwrap();
    h.admit_delete("a", &h.emitter);
    assert!(matches!(
        h.reconcile(&["a"]).await.evidence_for("a"),
        Some(SettlementEvidence::Retained { .. })
    ));

    std::fs::remove_file(h.root.path().join("a/.DS_Store")).unwrap();
    let attempt = h.reconcile(&["a"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(std::fs::symlink_metadata(h.root.path().join("a")).is_err());
    assert_eq!(h.state.retained_directory_reason(GROUP, "a").unwrap(), None);
}

/// A peer's `rm -rf a/` arrives as point deletes of `a/x.txt`
/// and `a`. Here `a` also holds a `.git` this device never replicated.
/// The replicated file goes, the `.git` and the directory holding it
/// stay, and both paths settle -- no retry loop, on this pass or the
/// next.
#[tokio::test]
async fn rm_rf_on_peer_with_ignored_dot_git_inside_settles_without_retry_loop() {
    let h = Harness::new();
    let file = version_for(&h.state, &h.store, b"tracked content");
    h.admit_ops(
        vec![create_op("a", &FileVersion::directory(None)), create_op("a/x.txt", &file)],
        &[FileVersion::directory(None), file.clone()],
    );
    let first = h.reconcile(&["a", "a/x.txt"]).await;
    assert!(first.retry.is_empty(), "{:?}", first.retry);
    std::fs::create_dir(h.root.path().join("a/.git")).unwrap();
    std::fs::write(h.root.path().join("a/.git/HEAD"), b"ref: refs/heads/main").unwrap();

    h.admit_ops(vec![delete_op("a/x.txt"), delete_op("a")], &[]);
    let attempt = h.reconcile(&["a", "a/x.txt"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(attempt.is_settled("a") && attempt.is_settled("a/x.txt"));
    assert!(!h.root.path().join("a/x.txt").exists(), "the replicated file must be deleted");
    assert_eq!(
        std::fs::read(h.root.path().join("a/.git/HEAD")).unwrap(),
        b"ref: refs/heads/main",
        "nothing this device does not replicate may be deleted"
    );
    let again = h.reconcile(&["a", "a/x.txt"]).await;
    assert!(again.retry.is_empty(), "{:?}", again.retry);
}

/// The same `rm -rf a/` with nothing untracked inside: children are
/// removed before their directory, so the directory is empty by the time
/// its own delete runs and is removed, not retained.
#[tokio::test]
async fn rm_rf_of_a_tracked_tree_removes_the_directory() {
    let h = Harness::new();
    let file = version_for(&h.state, &h.store, b"tracked content");
    h.admit_ops(
        vec![create_op("a", &FileVersion::directory(None)), create_op("a/x.txt", &file)],
        &[FileVersion::directory(None), file.clone()],
    );
    assert!(h.reconcile(&["a", "a/x.txt"]).await.retry.is_empty());

    h.admit_ops(vec![delete_op("a/x.txt"), delete_op("a")], &[]);
    let attempt = h.reconcile(&["a", "a/x.txt"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(std::fs::symlink_metadata(h.root.path().join("a")).is_err());
}

/// The crash windows around a structural mkdir, against the real ledger: an intent written
/// and then abandoned by a crash (before the `mkdir`, or after it but
/// before the identity was recorded) is dropped by startup recovery, never
/// completed, and the directory -- if the `mkdir` ran -- is left alone as
/// of unknown origin. A completed origin survives recovery.
#[tokio::test]
async fn materializer_mkdir_records_structural_origin_around_create() {
    let h = Harness::new();
    // Crash after the intent, before the mkdir.
    h.state.record_structural_directory_intent(GROUP, "before-mkdir").unwrap();
    // Crash after the mkdir, before the identity.
    h.state.record_structural_directory_intent(GROUP, "after-mkdir").unwrap();
    std::fs::create_dir(h.root.path().join("after-mkdir")).unwrap();
    // Completed.
    h.state.record_structural_directory_intent(GROUP, "completed").unwrap();
    std::fs::create_dir(h.root.path().join("completed")).unwrap();
    let identity = yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
        &h.root.path().join("completed"),
    )
    .unwrap();
    h.state.complete_structural_directory_origin(GROUP, "completed", &identity).unwrap();
    assert_eq!(h.origin_status("after-mkdir"), StructuralOriginStatus::IntentPending);

    let dropped = h.state.drop_interrupted_structural_intents_at_startup().unwrap();

    assert_eq!(
        dropped,
        vec![
            (GROUP.to_string(), "after-mkdir".to_string()),
            (GROUP.to_string(), "before-mkdir".to_string()),
        ]
    );
    assert_eq!(h.origin_status("before-mkdir"), StructuralOriginStatus::OriginUnknown);
    assert_eq!(h.origin_status("after-mkdir"), StructuralOriginStatus::OriginUnknown);
    assert!(h.root.path().join("after-mkdir").is_dir(), "recovery never removes a directory");
    assert_eq!(h.origin_status("completed"), StructuralOriginStatus::Structural);
    // The directory the interrupted mkdir may have made is recorded as of
    // lost provenance, so capture does not read it as a user's; where
    // nothing was made, nothing is recorded.
    let after_mkdir = yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
        &h.root.path().join("after-mkdir"),
    )
    .unwrap();
    assert_eq!(
        h.state.sqlite().dag_structural_directory_origin(GROUP, "after-mkdir").unwrap(),
        StructuralDirectoryOrigin::ProvenanceLost(after_mkdir)
    );
    assert_eq!(
        h.state.sqlite().dag_structural_directory_origin(GROUP, "before-mkdir").unwrap(),
        StructuralDirectoryOrigin::None
    );
}

/// The periodic backstop drops only intents old enough that no live
/// `mkdir` can still be between its two phases.
#[tokio::test]
async fn the_periodic_sweep_drops_only_stale_structural_intents() {
    let h = Harness::new();
    let now = super::super::types::now_unix_nanos();
    let stale_age = crate::replica_coordinator::STALE_STRUCTURAL_INTENT_AGE.as_nanos() as i64;
    h.state.sqlite().dag_record_structural_intent(GROUP, "stale", now - stale_age - 1).unwrap();
    h.state.record_structural_directory_intent(GROUP, "live").unwrap();

    let dropped = h.state.drop_stale_structural_intents().unwrap();

    assert_eq!(dropped, vec![(GROUP.to_string(), "stale".to_string())]);
    assert_eq!(h.origin_status("live"), StructuralOriginStatus::IntentPending);
}

/// A Directory version has no blocks. A full replica holding
/// one must still answer a peer's version-present query for it as
/// present -- current and retained alike -- or a directory could never be
/// counted as durably held, and a handoff that has to cover every root
/// would never complete.
#[tokio::test]
async fn blockless_directory_version_is_custody_confirmed() {
    let h = Harness::new();
    let directory = FileVersion::directory(Some(0o755));
    h.admit("a", &directory, &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    let engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &h.state,
        h.store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    );

    for for_handoff in [false, true] {
        let evaluation =
            engine.holds_version_durably(&yadorilink_replica_engine::DurableVersionQuery {
                folder_group_id: GROUP.to_string(),
                file_path: "a".to_string(),
                block_hashes: Vec::new(),
                for_handoff,
                version_hash: directory.version_hash.as_bytes().to_vec(),
                block_sizes: Vec::new(),
            });
        assert!(evaluation.present, "for_handoff={for_handoff}");
    }
    // And not a different directory version at the same path.
    let other = FileVersion::directory(Some(0o700));
    let evaluation =
        engine.holds_version_durably(&yadorilink_replica_engine::DurableVersionQuery {
            folder_group_id: GROUP.to_string(),
            file_path: "a".to_string(),
            block_hashes: Vec::new(),
            for_handoff: false,
            version_hash: other.version_hash.as_bytes().to_vec(),
            block_sizes: Vec::new(),
        });
    assert!(!evaluation.present);
}

/// A placeholder's parent directories are created by the daemon, through
/// the recording helper, before the placeholder is placed -- on Windows
/// the out-of-process CfAPI host that places it creates no directory at
/// all. So a placeholder's parents are structural like any others, on the
/// synchronous path and on the deferred one alike.
#[tokio::test]
async fn cfapi_placeholder_parent_directory_records_structural_origin() {
    let h = Harness::new();
    h.state
        .link_repository()
        .set_materialization_policy(
            &h.root.path().to_string_lossy(),
            MaterializationPolicy::OnDemand,
        )
        .unwrap();
    let file = version_for(&h.state, &h.store, b"content left on demand");
    h.admit("deep/er/f.txt", &file, &h.emitter);

    let attempt = h.reconcile(&["deep/er/f.txt"]).await;

    // Windows has no synchronous placeholder: every one is deferred to the
    // CfAPI host, so the pass settles nothing there and the parents are all
    // this assertion block can check.
    if cfg!(windows) {
        assert!(attempt.evidence_for("deep/er/f.txt").is_none());
    } else {
        assert!(
            matches!(
                attempt.evidence_for("deep/er/f.txt"),
                Some(SettlementEvidence::PolicyPlaceholder)
            ),
            "got {:?}",
            attempt.evidence_for("deep/er/f.txt")
        );
    }
    assert_eq!(h.origin_status("deep"), StructuralOriginStatus::Structural);
    assert_eq!(h.origin_status("deep/er"), StructuralOriginStatus::Structural);

    // The deferred path, as Windows takes it: nothing is written under the
    // placeholder's name, so only the daemon can have made its parents.
    let deferred = version_for(&h.state, &h.store, b"placed later by the host");
    h.admit("far/down/g.txt", &deferred, &h.emitter);
    // Armed under both spellings of the root: the seam matches the exact
    // path the write is handed, and a temp root may sit behind a symlink.
    let out_path = h.root.path().join("far/down/g.txt");
    let armed = [out_path.clone(), h.root.path().canonicalize().unwrap().join("far/down/g.txt")];
    for path in &armed {
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            path, true,
        );
    }
    let _ = h.reconcile(&["far/down/g.txt"]).await;
    for path in &armed {
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            path, false,
        );
    }

    assert!(
        std::fs::symlink_metadata(&out_path).is_err(),
        "sanity: the deferred placeholder write must genuinely write nothing"
    );
    assert!(h.root.path().join("far/down").is_dir(), "the parent must exist before the host");
    assert_eq!(h.origin_status("far"), StructuralOriginStatus::Structural);
    assert_eq!(h.origin_status("far/down"), StructuralOriginStatus::Structural);
}

/// A file's tombstone that finds a directory where the file was -- a
/// local change of kind nothing has captured -- keeps the directory, even
/// an empty one: only a directory the index holds as replicated is ever
/// removed.
#[tokio::test]
async fn a_file_tombstone_keeps_an_uncaptured_directory_at_its_path() {
    let h = Harness::new();
    let file = version_for(&h.state, &h.store, b"a file that becomes a directory locally");
    h.admit("a", &file, &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    std::fs::remove_file(h.root.path().join("a")).unwrap();
    std::fs::create_dir(h.root.path().join("a")).unwrap();

    h.admit_delete("a", &h.emitter);
    let attempt = h.reconcile(&["a"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(
        matches!(attempt.evidence_for("a"), Some(SettlementEvidence::Retained { .. })),
        "got {:?}",
        attempt.evidence_for("a")
    );
    assert!(h.root.path().join("a").is_dir(), "an uncaptured directory must not be removed");

    // Nor on any later pass over the path: the delete never saw this
    // directory, so nothing licenses removing it once it is empty.
    let again = h.reconcile(&["a"]).await;
    assert!(again.retry.is_empty(), "{:?}", again.retry);
    assert!(h.root.path().join("a").is_dir(), "a later pass must not remove it either");
}

/// A Directory tombstone removes only the directory this device
/// materialized for the entry. The user replacing it with a new, empty
/// directory at the same name before the peer's delete is applied made
/// that directory theirs: the delete keeps it, settles retained without
/// retry, and no later pass removes it.
#[tokio::test]
async fn a_directory_tombstone_keeps_a_directory_that_replaced_the_materialized_one() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    // The new directory is made before the old one goes, so it can never
    // reuse the materialized directory's inode.
    std::fs::rename(h.root.path().join("a"), h.root.path().join("a.old")).unwrap();
    std::fs::create_dir(h.root.path().join("a")).unwrap();
    std::fs::remove_dir(h.root.path().join("a.old")).unwrap();

    h.admit_delete("a", &h.emitter);
    let attempt = h.reconcile(&["a"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(
        matches!(
            attempt.evidence_for("a"),
            Some(SettlementEvidence::Retained { reason }) if reason == RETAINED_REPLACED_LOCALLY
        ),
        "got {:?}",
        attempt.evidence_for("a")
    );
    assert!(h.root.path().join("a").is_dir(), "the user's replacement must not be removed");

    let again = h.reconcile(&["a"]).await;
    assert!(again.retry.is_empty(), "{:?}", again.retry);
    assert!(h.root.path().join("a").is_dir(), "a later pass must not remove it either");
}

/// Admits a Directory `a` holding `count` tracked files, reconciles it
/// into place, then admits a peer's `rm -rf a/` as one change of point
/// deletes. Returns every path involved, `a` first.
async fn tracked_tree_then_rm_rf(h: &Harness, count: usize) -> Vec<String> {
    let mut paths = vec!["a".to_string()];
    let mut ops = vec![create_op("a", &FileVersion::directory(None))];
    let mut versions = vec![FileVersion::directory(None)];
    for i in 1..=count {
        let path = format!("a/f{i}");
        let version = version_for(&h.state, &h.store, format!("tracked {i}").as_bytes());
        ops.push(create_op(&path, &version));
        versions.push(version);
        paths.push(path);
    }
    h.admit_ops(ops, &versions);
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();
    let placed = h.reconcile(&all).await;
    assert!(placed.retry.is_empty(), "{:?}", placed.retry);
    h.admit_ops(paths.iter().map(|path| delete_op(path)).collect(), &[]);
    paths
}

/// An `rm -rf a/` wider than one commit chunk: `a` sorts first and lands
/// in the first chunk with only some of its children, so its `rmdir`
/// finds it not empty. Once the later chunk deletes the rest, the pass
/// must still remove `a` -- nothing else will ever reconcile it again.
#[tokio::test]
async fn rm_rf_wider_than_one_commit_chunk_removes_the_directory() {
    let h = Harness::new();
    let paths = tracked_tree_then_rm_rf(&h, 9).await;
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();

    let attempt = h.reconcile(&all).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(
        std::fs::symlink_metadata(h.root.path().join("a")).is_err(),
        "the emptied directory must be removed in the same pass"
    );
    assert_eq!(h.state.retained_directory_reason(GROUP, "a").unwrap(), None);
}

/// The same delete reconciled in separate calls, the directory first --
/// as the engine's bounded calls can split it. The directory is retained
/// while its children are there, and removed by the call that deletes the
/// last of them.
#[tokio::test]
async fn a_retained_directory_is_removed_by_the_pass_that_empties_it() {
    let h = Harness::new();
    let paths = tracked_tree_then_rm_rf(&h, 3).await;

    let first = h.reconcile(&["a"]).await;
    assert!(
        matches!(first.evidence_for("a"), Some(SettlementEvidence::Retained { .. })),
        "got {:?}",
        first.evidence_for("a")
    );
    let children: Vec<&str> = paths[1..].iter().map(String::as_str).collect();
    let second = h.reconcile(&children).await;

    assert!(second.retry.is_empty(), "{:?}", second.retry);
    assert!(
        std::fs::symlink_metadata(h.root.path().join("a")).is_err(),
        "deleting the last child must remove the retained directory"
    );
}

/// A directory made at a path after the path's delete settled is the
/// user's, not anything a delete aimed at: no pass removes it, even empty.
#[tokio::test]
async fn a_directory_made_after_its_paths_delete_is_never_removed() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    h.admit_delete("a", &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    assert!(std::fs::symlink_metadata(h.root.path().join("a")).is_err());

    std::fs::create_dir(h.root.path().join("a")).unwrap();
    for _ in 0..2 {
        let attempt = h.reconcile(&["a"]).await;
        assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
        assert!(h.root.path().join("a").is_dir(), "the user's directory must stay");
    }
}

/// A retained directory is bound to the object that was retained. The
/// user replacing it with a new, empty directory at the same path gives
/// that new directory nothing: a re-driven delete leaves it alone.
#[tokio::test]
async fn a_retained_directory_replaced_by_a_new_one_is_not_removed() {
    let h = Harness::new();
    h.admit("proj", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["proj"]).await.is_settled("proj"));
    std::fs::create_dir(h.root.path().join("proj/.git")).unwrap();
    h.admit_delete("proj", &h.emitter);
    assert!(matches!(
        h.reconcile(&["proj"]).await.evidence_for("proj"),
        Some(SettlementEvidence::Retained { .. })
    ));

    std::fs::remove_dir_all(h.root.path().join("proj")).unwrap();
    std::fs::create_dir(h.root.path().join("proj")).unwrap();
    let attempt = h.reconcile(&["proj"]).await;

    assert!(attempt.retry.is_empty(), "{:?}", attempt.retry);
    assert!(h.root.path().join("proj").is_dir(), "a new directory inherits nothing");
}

impl Harness {
    /// This device's local capture of `rel`, as the link's watcher drives
    /// it after a `CreatedOrModified` event.
    async fn capture_directory_event(&self, rel: &str) {
        // Canonical, as the watcher reports it (`/private/var`, not `/var`).
        let root = &self.root.path().canonicalize().unwrap();
        let lock = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root).unwrap();
        let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::new(
            lock,
            GROUP.to_string(),
            1,
        ));
        let processor = yadorilink_local_capture::LocalChangeProcessor::new(
            self.state.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                self.store.clone(),
            )),
            "device-local".to_string(),
            lease,
        )
        .with_change_emitter(Arc::new(ChangeEmitter::new(
            "device-local",
            SigningKey::from_bytes(&[7u8; 32]),
        )));
        processor
            .process_event(
                GROUP,
                root,
                &yadorilink_filesystem_sync::watcher::FsChangeEvent {
                    path: root.join(rel),
                    kind: yadorilink_filesystem_sync::watcher::FsChangeKind::CreatedOrModified,
                },
            )
            .await
            .unwrap();
    }

    fn live_directory_row(&self, rel: &str) -> bool {
        self.state.get_file(GROUP, rel).unwrap().is_some_and(|row| !row.deleted)
            && self.state.get_record_kind(GROUP, rel).unwrap() == Some(RecordKind::Directory)
    }
}

/// A peer's Directory tombstone keeps a directory the user put in place
/// of the materialized one (kept for good). That directory is the user's:
/// capture authors it as an explicit entry of its own, rather than reading
/// the retained record as "not a user's" and never replicating it.
#[tokio::test]
async fn a_user_directory_kept_by_a_peer_tombstone_is_captured_as_explicit() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    std::fs::rename(h.root.path().join("a"), h.root.path().join("a.old")).unwrap();
    std::fs::create_dir(h.root.path().join("a")).unwrap();
    std::fs::remove_dir(h.root.path().join("a.old")).unwrap();
    h.admit_delete("a", &h.emitter);
    assert!(matches!(
        h.reconcile(&["a"]).await.evidence_for("a"),
        Some(SettlementEvidence::Retained { reason }) if reason == RETAINED_REPLACED_LOCALLY
    ));

    h.capture_directory_event("a").await;

    assert!(h.live_directory_row("a"), "the user's directory must be authored");
}

/// The other half: the very directory a peer's delete aimed at, kept
/// because it holds untracked content, is not authored back.
#[tokio::test]
async fn the_directory_a_peer_tombstone_retained_is_not_authored_back() {
    let h = Harness::new();
    h.admit("a", &FileVersion::directory(None), &h.emitter);
    assert!(h.reconcile(&["a"]).await.is_settled("a"));
    std::fs::write(h.root.path().join("a/.DS_Store"), b"finder state").unwrap();
    h.admit_delete("a", &h.emitter);
    assert!(matches!(
        h.reconcile(&["a"]).await.evidence_for("a"),
        Some(SettlementEvidence::Retained { .. })
    ));

    h.capture_directory_event("a").await;

    assert!(!h.live_directory_row("a"), "the retained directory must not be authored back");
}

/// An interrupted structural `mkdir` whose group has no live link at
/// startup cannot be resolved to the directory it may have made: its
/// intent is kept (the directory stays in flight, never a user's) instead
/// of being dropped with nothing in its place, and resolved once the root
/// is there.
#[tokio::test]
async fn an_interrupted_structural_intent_whose_root_is_unavailable_is_kept() {
    let h = Harness::new();
    const UNLINKED: &str = "group-without-a-live-link";
    h.state.record_structural_directory_intent(UNLINKED, "a").unwrap();
    let missing_root = h.root.path().join("not-mounted");
    h.state.link_repository().add_link(&missing_root.to_string_lossy(), "group-unmounted").unwrap();
    h.state.record_structural_directory_intent("group-unmounted", "a").unwrap();

    let dropped = h.state.drop_interrupted_structural_intents_at_startup().unwrap();

    assert_eq!(dropped, Vec::<(String, String)>::new());
    for group in [UNLINKED, "group-unmounted"] {
        assert_eq!(
            h.state.sqlite().dag_structural_directory_origin(group, "a").unwrap(),
            StructuralDirectoryOrigin::IntentPending,
            "{group}"
        );
    }

    // The volume comes up with the directory the interrupted mkdir made.
    std::fs::create_dir_all(missing_root.join("a")).unwrap();
    let made =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&missing_root.join("a"))
            .unwrap();
    let dropped = h.state.drop_interrupted_structural_intents_at_startup().unwrap();
    assert_eq!(dropped, vec![("group-unmounted".to_string(), "a".to_string())]);
    assert_eq!(
        h.state.sqlite().dag_structural_directory_origin("group-unmounted", "a").unwrap(),
        StructuralDirectoryOrigin::ProvenanceLost(made)
    );
}
