#![cfg(test)]

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_local_storage::{BlockStore as _, SegmentBlockStore};
use yadorilink_peer_session::peer_session::*;
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

const GROUP: &str = "c4-6-ordinary-batch-group";

fn create_op(path: &str, version: &FileVersion) -> Op {
    Op::Put {
        path: SyncPath(path.into()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    }
}

/// Puts `content` into `store` AND records this group's provenance for
/// the resulting block -- `ensure_blocks_present` treats a physically-
/// present-but-unprovenanced block as needing a peer fetch (correctly:
/// see its own "a physical hit may belong only to another group"
/// comment), so a test seeding content directly into the store must
/// also seed provenance, or every `prepare_ordinary_projected_upsert`
/// call here would try to fetch from this harness's unconnected peer
/// end and report `all_present = false`.
fn version_for(
    state: &ReplicaCoordinator,
    store: &SegmentBlockStore,
    content: &[u8],
) -> FileVersion {
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash), size: content.len() as u32 }],
        content.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// One session over a real, in-memory `ReplicaCoordinator`, a real
/// `SegmentBlockStore` and a real sync-root tempdir -- `prepare_ordinary_projected_upsert`/
/// `try_commit_ordinary_batch` do real disk I/O by design (see
/// `PreparedProjectedUpsert`'s own doc comment), so neither can be
/// faked away.
struct Harness {
    _session: Arc<PeerSyncSession>,
    convergence: Arc<super::LocalConvergenceExecutor>,
    /// The activity provider the executor was built with, which the
    /// session used to hand back through a private accessor of its own.
    activity_provider: Arc<dyn BlockWriteActivityProvider>,
    state: Arc<ReplicaCoordinator>,
    store: Arc<SegmentBlockStore>,
    _store_dir: tempfile::TempDir,
    root: tempfile::TempDir,
    sender_db: rusqlite::Connection,
    emitter: ChangeEmitter,
    /// The last checkpoint sequence this harness signed. One counter for
    /// every emitter, so each device's own sequence is strictly
    /// increasing, as real issuance's is.
    checkpoint_seq: std::sync::atomic::AtomicU64,
}

impl Harness {
    fn new() -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let local_path = root.path().to_string_lossy().to_string();
        state.link_repository().add_link(&local_path, GROUP).unwrap();
        // Symlink materialization on Windows is per-link opt-in; without it
        // every received symlink here would be a policy skip that never
        // settles, so the symlink scenarios opt in to run the real write.
        #[cfg(windows)]
        state.link_repository().set_windows_symlink_opt_in(&local_path, true).unwrap();
        state
            .link_repository()
            .set_materialization_policy(&local_path, MaterializationPolicy::Eager)
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let (channel, _peer_end) =
            yadorilink_peer_session::ports::InMemoryPeerChannel::connected_pair();
        let transports = yadorilink_peer_session::ports::in_memory_transports(&channel);
        let deps = yadorilink_peer_session::peer_session::PeerSyncSessionDeps::test_permissive();
        let sync_roots = HashMap::from([(GROUP.to_string(), root.path().to_path_buf())]);
        let session = PeerSyncSession::over_substrate(
            "device-local".to_string(),
            "device-remote".to_string(),
            state.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            crate::replica_coordinator::engine_ports::build_peer_replica_engine(
                &state,
                store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            ),
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            vec![GROUP.to_string()],
            sync_roots.clone(),
            transports,
            None,
            deps.clone(),
        );
        let convergence = super::LocalConvergenceExecutor::new(
            state.clone(),
            "device-local".to_string(),
            deps.root_commit_authority_provider.clone(),
            deps.pending_local_change_flush.clone(),
            sync_roots,
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            deps.block_write_activity_provider.clone(),
            super::HeadroomPolicy::disabled(),
        );
        let sender_db = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender_db).unwrap();
        let emitter = ChangeEmitter::new("device-remote", SigningKey::from_bytes(&[9u8; 32]));
        Self {
            _session: session,
            convergence,
            activity_provider: deps.block_write_activity_provider.clone(),
            state,
            store,
            _store_dir: store_dir,
            root,
            sender_db,
            emitter,
            checkpoint_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Evidence for `change`, signed by `emitter`'s own key and verified
    /// against the admission contract -- what admission would have
    /// checked before the store ever saw the change.
    fn evidence_for(
        &self,
        change: &Change,
        emitter: &ChangeEmitter,
    ) -> yadorilink_replica_engine::ports::ChangeEvidence {
        let seq = self.checkpoint_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        super::published_fixture::verified_evidence(emitter.signing_key(), seq, change)
    }

    /// Emits (against this harness's own throwaway `sender_db`, so
    /// successive calls chain parent -> child automatically) and admits
    /// (into `self.state`, unapplied) a change writing `version` at
    /// `path`, authored by `emitter`.
    fn admit(&self, path: &str, version: &FileVersion, emitter: &ChangeEmitter) -> Change {
        let change = dag_store::emit_local_change(
            &self.sender_db,
            GROUP,
            vec![create_op(path, version)],
            emitter,
        )
        .unwrap();
        let evidence = self.evidence_for(&change, emitter);
        self.state
            .change_history_repository()
            .dag_admit_change_batch_with_versions(&[yadorilink_sync_sqlite::PendingAdmission {
                change: &change,
                versions: std::slice::from_ref(version),
                evidence: Some(&evidence),
            }])
            .remove(0)
            .unwrap();
        change
    }

    /// Same chaining discipline as [`Self::admit`], but for a tombstone
    /// (`Op::Delete`) instead of a `Put` -- used by the batched delete-
    /// revalidation regression test to build a tombstone whose winning
    /// resolution a later, descendant `Put` (a "recreate after delete")
    /// then supersedes.
    fn admit_delete(&self, path: &str, emitter: &ChangeEmitter) -> Change {
        let change = dag_store::emit_local_change(
            &self.sender_db,
            GROUP,
            vec![Op::Delete { path: SyncPath(path.into()) }],
            emitter,
        )
        .unwrap();
        let evidence = self.evidence_for(&change, emitter);
        self.state
            .change_history_repository()
            .dag_admit_change_batch_with_versions(&[yadorilink_sync_sqlite::PendingAdmission {
                change: &change,
                versions: &[],
                evidence: Some(&evidence),
            }])
            .remove(0)
            .unwrap();
        change
    }

    /// The current winning content head for `path`, exactly as
    /// `reconcile_group_paths`'s own fixpoint would resolve it.
    fn winner_head(&self, path: &str) -> PathHead {
        let heads = self.convergence.combined_heads(GROUP, path, None).unwrap();
        match resolve_path_heads(path, &heads) {
            PathResolution::Present { winner, .. } => heads[winner].clone(),
            PathResolution::Absent => panic!("{path}: expected a live content head"),
        }
    }

    async fn prepare<'a>(
        &self,
        path: &str,
        head: &PathHead,
        activity_provider: &'a dyn BlockWriteActivityProvider,
    ) -> Option<(Box<dyn Send + 'a>, yadorilink_peer_session::ports::PreparedProjectedUpsert)> {
        // A fresh batch per call: none of this module's existing tests
        // exercise cross-file provenance dedup (that is `block_
        // provenance_batching_tests`'s own job below), and every
        // `Upsert` this produces still carries its own `newly_fetched_
        // block_hashes` for `try_commit_ordinary_batch` to flush.
        let reconcile_batch = ReconcileProvenanceBatch::new();
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        self.convergence
            .prepare_ordinary_projected_upsert(
                GROUP,
                path,
                path,
                head,
                MaterializationPolicy::Eager,
                None,
                activity_provider,
                &reconcile_batch,
                &call_timer,
            )
            .await
            .unwrap()
    }
}

/// A batched upsert's metadata (unix mode, xattrs) must actually land:
/// `open_projected_upserts_batch` applies it in the same transaction as
/// the row, not `revalidate_ordinary_upsert` per-candidate. Nothing else
/// in this module exercises non-default metadata, so this is the only
/// coverage that batching does not silently drop it.
#[tokio::test]
async fn a_batched_upserts_metadata_is_applied_atomically_with_its_row() {
    let h = Harness::new();
    let hash =
        hex::decode(h.store.put(b"content with real metadata to carry through").unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash), size: 44 }],
        44,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: Some(0o640),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: vec![("user.test".to_string(), b"value".to_vec())],
        },
    );
    h.admit("meta.txt", &version, &h.emitter);
    let head1 = h.winner_head("meta.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h
        .prepare("meta.txt", &head1, activity_provider.as_ref())
        .await
        .expect("an ordinary eager content upsert must classify as batch-eligible");
    assert_eq!(prepared.metadata.unix_mode, Some(0o640));

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();
    assert!(retry.is_empty());
    assert!(settled.contains_key("meta.txt"));

    assert_eq!(h.state.get_unix_mode(GROUP, "meta.txt").unwrap(), Some(0o640));
    assert_eq!(
        h.state.get_xattrs(GROUP, "meta.txt").unwrap(),
        vec![("user.test".to_string(), b"value".to_vec())]
    );
}

/// (1) A local edit admitted after this candidate was prepared, but
/// before the batch that carries it commits, must not be silently
/// overwritten by the stale peer content -- it must be dropped to
/// retry instead.
#[tokio::test]
async fn a_local_edit_admitted_after_prepare_but_before_batch_commit_is_not_committed_as_stale() {
    let h = Harness::new();
    let v1 = version_for(&h.state, &h.store, b"peer content, prepared but never safe to publish");
    h.admit("a.txt", &v1, &h.emitter);
    let head1 = h.winner_head("a.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h
        .prepare("a.txt", &head1, activity_provider.as_ref())
        .await
        .expect("an ordinary eager content upsert must classify as batch-eligible");

    // Simulates a local edit landing in the window between prepare and
    // this batch's commit: a new change supersedes the prepared head.
    let local_emitter = ChangeEmitter::new("device-local", SigningKey::from_bytes(&[3u8; 32]));
    let v2 = version_for(&h.state, &h.store, b"a local edit that landed after prepare");
    h.admit("a.txt", &v2, &local_emitter);

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(retry.contains("a.txt"), "the stale prepared upsert must be retried, not committed");
    assert!(!settled.contains_key("a.txt"));
    assert!(
        !h.root.path().join("a.txt").exists(),
        "the stale peer content must never be published to disk"
    );
}

/// (2) Same mechanism as (1), triggered by a DIFFERENT peer's newer
/// admitted change instead of a local edit -- `revalidate_ordinary_
/// upsert`'s freshness recheck does not care which kind of change
/// superseded the prepared candidate, only that one did.
#[tokio::test]
async fn a_different_peers_newer_change_admitted_before_batch_commit_is_not_committed_as_stale() {
    let h = Harness::new();
    let v1 = version_for(&h.state, &h.store, b"peer-a's content");
    h.admit("b.txt", &v1, &h.emitter);
    let head1 = h.winner_head("b.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h.prepare("b.txt", &head1, activity_provider.as_ref()).await.unwrap();

    let other_peer = ChangeEmitter::new("device-other-peer", SigningKey::from_bytes(&[5u8; 32]));
    let v2 = version_for(&h.state, &h.store, b"a different peer's newer content");
    h.admit("b.txt", &v2, &other_peer);

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(retry.contains("b.txt"));
    assert!(!settled.contains_key("b.txt"));
    assert!(!h.root.path().join("b.txt").exists());
}

/// The deferred-delete counterpart to
/// tests (1)/(2) above. A tombstone classified `Absent` (with no lock
/// held) that sits in `pending_batch` behind other candidates must
/// still detect a local "recreate after delete" that lands before this
/// batch acquires its lock -- `still_live` alone cannot distinguish
/// that from the ordinary "genuinely still deleted" case, since a
/// racing create also leaves the row live. Without re-resolving the
/// DAG fresh under the lock, this tombstone would unlink the brand-new
/// file and overwrite its live row with `deleted: true`.
#[tokio::test]
async fn a_local_recreate_landing_after_absent_classification_but_before_batch_commit_is_not_deleted(
) {
    let h = Harness::new();
    h.state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "d.txt".to_string(),
                size: 3,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let delete_change = h.admit_delete("d.txt", &h.emitter);
    let stale_tombstone_author = delete_change.change_hash();

    // Simulates a local recreate landing in the window between this
    // path's unlocked `Absent` classification (which happened before
    // this item was pushed into `pending_batch`) and the batch's lock
    // acquisition: a new `Put`, descending from the tombstone, revives
    // the path.
    let recreate_emitter = ChangeEmitter::new("device-local", SigningKey::from_bytes(&[7u8; 32]));
    let v_recreate = version_for(&h.state, &h.store, b"recreated locally after the delete");
    h.admit("d.txt", &v_recreate, &recreate_emitter);

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Delete("d.txt".to_string(), stale_tombstone_author, None)],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(retry.contains("d.txt"), "the stale tombstone must be retried, not committed");
    assert!(!settled.contains_key("d.txt"));
    let row = h.state.get_file(GROUP, "d.txt").unwrap().expect("the recreated row must survive");
    assert!(!row.deleted, "the recreated file must not be deleted by the stale tombstone");
}

/// A genuinely already-settled tombstone (row exists, already deleted,
/// authoring hash already this exact tombstone) must cost zero
/// `set_authoring_change_hash` calls -- the same "fully settled costs
/// zero writer_gate acquisitions" principle the content-identical fast
/// path follows, applied here to the delete side.
#[tokio::test]
async fn a_genuinely_settled_tombstone_with_matching_authoring_hash_costs_zero_writes() {
    let h = Harness::new();
    h.state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "settled-tombstone.txt".to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: true,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let delete_change = h.admit_delete("settled-tombstone.txt", &h.emitter);
    let tombstone_author = delete_change.change_hash();
    // Seed the row's authoring hash to already match exactly, mirroring
    // what a prior, already-successful run of this same code would have
    // left behind.
    crate::replica_coordinator::ReplicaCoordinator::set_authoring_change_hash(
        h.state.as_ref(),
        GROUP,
        "settled-tombstone.txt",
        &tombstone_author,
    )
    .unwrap();
    let calls_before = h
        .state
        .test_observers
        .set_authoring_change_hash_calls
        .load(std::sync::atomic::Ordering::SeqCst);

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Delete(
                "settled-tombstone.txt".to_string(),
                tombstone_author,
                None,
            )],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(settled.contains_key("settled-tombstone.txt"));
    assert!(retry.is_empty());
    assert_eq!(
        h.state
            .test_observers
            .set_authoring_change_hash_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        calls_before,
        "an already-fully-settled tombstone must not call set_authoring_change_hash again"
    );
}

/// The counterpart to the zero-write test above -- when
/// the tombstone's authoring hash genuinely differs from what's
/// recorded (a newer or different tombstone re-driving the same
/// already-deleted path), exactly one update must still happen so the
/// row's authoring identity stays correct.
#[tokio::test]
async fn a_settled_tombstone_with_a_different_authoring_hash_updates_exactly_once() {
    let h = Harness::new();
    h.state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "reauthored-tombstone.txt".to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: true,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let old_hash = ChangeHash([1u8; 32]);
    crate::replica_coordinator::ReplicaCoordinator::set_authoring_change_hash(
        h.state.as_ref(),
        GROUP,
        "reauthored-tombstone.txt",
        &old_hash,
    )
    .unwrap();
    let delete_change = h.admit_delete("reauthored-tombstone.txt", &h.emitter);
    let new_tombstone_author = delete_change.change_hash();
    assert_ne!(old_hash, new_tombstone_author, "sanity: the two hashes must actually differ");
    let calls_before = h
        .state
        .test_observers
        .set_authoring_change_hash_calls
        .load(std::sync::atomic::Ordering::SeqCst);

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Delete(
                "reauthored-tombstone.txt".to_string(),
                new_tombstone_author,
                None,
            )],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(settled.contains_key("reauthored-tombstone.txt"));
    assert!(retry.is_empty());
    assert_eq!(
        h.state
            .test_observers
            .set_authoring_change_hash_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        calls_before + 1,
        "a genuinely differing authoring hash must still be written exactly once"
    );
    assert_eq!(
        h.state.get_authoring_change_hash(GROUP, "reauthored-tombstone.txt").unwrap(),
        Some(new_tombstone_author)
    );
}

/// (3) A new change can reaffirm BYTE-IDENTICAL content (the same
/// `FileVersion`/blocks) under a genuinely different, newer authoring
/// change hash. A revalidation that compared blocks/bytes alone would
/// miss this -- it must compare authoring identity.
#[tokio::test]
async fn a_new_change_reaffirming_byte_identical_content_under_a_new_authoring_hash_is_detected_as_stale(
) {
    let h = Harness::new();
    let v1 = version_for(&h.state, &h.store, b"same bytes, admitted under two different changes");
    h.admit("c.txt", &v1, &h.emitter);
    let head1 = h.winner_head("c.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h.prepare("c.txt", &head1, activity_provider.as_ref()).await.unwrap();

    // A second, later change lands referencing the EXACT SAME
    // FileVersion -- byte-identical content, but a genuinely different
    // and newer authoring change.
    h.admit("c.txt", &v1, &h.emitter);

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(
        retry.contains("c.txt"),
        "staleness must be detected via authoring identity, not just byte content"
    );
    assert!(!settled.contains_key("c.txt"));
}

/// (4) A raw local write landing directly on disk (bypassing the index
/// entirely -- e.g. a not-yet-captured local edit) after prepare must
/// be caught by the same on-disk divergence guard `materialize()`'s own
/// eager-write branch runs, and must never be silently clobbered by the
/// batch's publish.
#[tokio::test]
async fn a_raw_disk_write_landing_after_prepare_is_detected_and_never_overwritten() {
    let h = Harness::new();
    let original = b"already-synced original content";
    let existing_version = version_for(&h.state, &h.store, original);
    let existing_record = file_record_from_version("d.txt", &existing_version);
    h.state
        .file_index_repository()
        .upsert_file(GROUP, &existing_record, &RootCommitPermit::for_tests())
        .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    h.state
        .set_materialization_state(GROUP, "d.txt", MaterializationState::Hydrated, &permit)
        .unwrap();
    std::fs::write(h.root.path().join("d.txt"), original).unwrap();

    let v2 = version_for(&h.state, &h.store, b"incoming peer content, different from the original");
    h.admit("d.txt", &v2, &h.emitter);
    let head2 = h.winner_head("d.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h.prepare("d.txt", &head2, activity_provider.as_ref()).await.unwrap();

    // A raw local edit lands directly on disk after prepare -- the
    // exact race `disk_content_comparison` exists to catch.
    let raw_edit = b"an unauthored local edit, landed after prepare, never indexed";
    std::fs::write(h.root.path().join("d.txt"), raw_edit).unwrap();

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(retry.contains("d.txt"));
    assert!(!settled.contains_key("d.txt"));
    assert_eq!(
        std::fs::read(h.root.path().join("d.txt")).unwrap(),
        raw_edit,
        "the unauthored local edit must survive untouched"
    );
}

/// (7) A bounded batch with exactly one stale path among several
/// otherwise-valid ones must commit every valid candidate and retry
/// only the stale one -- a partial-batch failure must not be
/// all-or-nothing.
#[tokio::test]
async fn a_mixed_batch_with_one_stale_path_commits_the_rest_and_retries_only_that_one() {
    let h = Harness::new();
    let activity_provider = h.activity_provider.clone();
    let mut paths_and_contents = Vec::new();
    let mut items = Vec::new();
    for i in 0..8u8 {
        let path = format!("f{i}.txt");
        let content = format!("content for {path}").into_bytes();
        let version = version_for(&h.state, &h.store, &content);
        h.admit(&path, &version, &h.emitter);
        let head = h.winner_head(&path);
        let (guard, prepared) = h.prepare(&path, &head, activity_provider.as_ref()).await.unwrap();
        items.push(OrdinaryBatchItem::Upsert(guard, Box::new(prepared)));
        paths_and_contents.push((path, content));
    }
    let stale_path = "f3.txt".to_string();
    // Every path above is already prepared; NOW make f3.txt stale.
    h.admit(
        &stale_path,
        &version_for(&h.state, &h.store, b"a superseding change for f3"),
        &h.emitter,
    );

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            items,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert_eq!(retry, std::collections::BTreeSet::from([stale_path.clone()]));
    assert_eq!(
        settled.len(),
        7,
        "every non-stale path in the batch must still commit: {settled:?}"
    );
    for (path, content) in &paths_and_contents {
        if *path == stale_path {
            assert!(!h.root.path().join(path).exists(), "the stale path must never be published");
        } else {
            assert_eq!(
                std::fs::read(h.root.path().join(path)).unwrap(),
                *content,
                "{path} must have committed its prepared content"
            );
        }
    }
}

/// (8) A failure in the batch's own final commit transaction must
/// propagate as an error -- never as an `Ok((settled, retry))` result
/// that could be misread as "this path is done" when nothing was
/// actually finalized.
#[tokio::test]
async fn a_finalize_transaction_failure_never_reports_a_path_as_settled() {
    let h = Harness::new();
    let v1 = version_for(&h.state, &h.store, b"content whose finalize is about to be made to fail");
    h.admit("e.txt", &v1, &h.emitter);
    let head1 = h.winner_head("e.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h.prepare("e.txt", &head1, activity_provider.as_ref()).await.unwrap();

    h.state
        .test_observers
        .finalize_projected_mutations_batch_fails
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let result = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await;

    assert!(
        result.is_err(),
        "a batch commit transaction failure must propagate as an error, never as an Ok(...) \
         claiming any path settled: {result:?}"
    );
    // The row+intent commit itself (`open_projected_upserts_batch`) ran
    // and succeeded BEFORE the injected failure -- exactly the same
    // recoverable, intent-protected state a real crash in this window
    // leaves (see the daemon crate's matching repair tests), not data
    // loss.
    assert!(
        h.state.get_file(GROUP, "e.txt").unwrap().is_some(),
        "the row commit itself (before the injected failure) must still be visible"
    );
}

/// `materialize_dag_content_head`'s serial fast path (not the batch path
/// this module otherwise tests). Once a path is
/// genuinely fully settled -- content, DB row, authoring identity,
/// origin, and disk metadata all already agree with the target
/// version -- re-examining it must cost ZERO additional
/// `apply_incoming_metadata_atomic` calls: under a large change burst,
/// most writer_gate load comes from paths re-examined repeatedly that
/// never actually need a write.
///
/// `apply_projected_row_atomic` is not asserted here: neither call in
/// this test reaches it (the first goes through the ordinary
/// `materialize()` path, the second finds nothing to write), so its
/// counter is zero throughout and an unchanged-count check could not
/// fail. [`a_row_only_disagreement_writes_the_row_once_then_never_again`]
/// covers it from a state that genuinely needs the write.
#[tokio::test]
async fn a_fully_settled_path_costs_zero_db_writes_on_re_examination() {
    let h = Harness::new();
    let version = version_for(&h.state, &h.store, b"already fully settled content");
    h.admit("settled.txt", &version, &h.emitter);
    let head = h.winner_head("settled.txt");

    // First call does the real write, through the ordinary unbatched
    // `materialize()` path (no current row exists yet) -- not through
    // either of the two new atomic primitives directly, though the
    // unconditional metadata-apply at this fn's tail still runs once
    // for a brand-new path.
    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "settled.txt",
            "settled.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, MaterializeResult::Settled(_)));
    let metadata_calls_after_first = h
        .state
        .test_observers
        .apply_incoming_metadata_atomic_calls
        .load(std::sync::atomic::Ordering::SeqCst);

    // Second call: everything already agrees -- must take the new
    // zero-write fast path, not increment either counter further.
    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "settled.txt",
            "settled.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, MaterializeResult::Settled(_)));
    assert_eq!(
        h.state
            .test_observers
            .apply_incoming_metadata_atomic_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        metadata_calls_after_first,
        "a truly no-op re-examination must not call apply_incoming_metadata_atomic again"
    );
}

/// The row-only repair on the serial fast path, and its zero-write
/// counterpart, in one test: the write happens exactly when it is
/// needed and not again once the path has settled.
///
/// The state that needs it is content and disk already matching the
/// desired version while the row's authoring identity does not -- the
/// fast path's `index_fully_matches` check fails on the authoring hash
/// alone, so it must repair the row with one `apply_projected_row_atomic`
/// call. After that the path is fully settled, and re-examining it must
/// not call it again.
#[tokio::test]
async fn a_row_only_disagreement_writes_the_row_once_then_never_again() {
    let h = Harness::new();
    let version = version_for(&h.state, &h.store, b"row-only disagreement content");
    h.admit("row-only.txt", &version, &h.emitter);
    let head = h.winner_head("row-only.txt");
    let materialize = || {
        h.convergence.materialize_dag_content_head(
            GROUP,
            "row-only.txt",
            "row-only.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
    };
    let row_calls = || {
        h.state
            .test_observers
            .apply_projected_row_atomic_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    };

    // Settle the path through the ordinary write first.
    assert!(matches!(materialize().await.unwrap(), MaterializeResult::Settled(_)));
    let desired = h
        .state
        .get_authoring_change_hash(GROUP, "row-only.txt")
        .unwrap()
        .expect("fixture check: a settled path carries its authoring hash");

    // Move only the row's authoring identity. Content, disk and the
    // fence are untouched, so what is left to do is a row write and
    // nothing else. Storage only accepts an authoring hash naming a
    // change this group actually holds, so the stale identity is a real
    // admitted change -- for another path, which is what a stale
    // projection would name.
    let other = version_for(&h.state, &h.store, b"an unrelated path's content");
    let stale = h.admit("unrelated.txt", &other, &h.emitter).compute_hash();
    assert_ne!(stale, desired);
    h.state
        .file_index_repository()
        .set_authoring_change_hash(GROUP, "row-only.txt", &stale)
        .unwrap();

    let before = row_calls();
    assert!(matches!(materialize().await.unwrap(), MaterializeResult::Settled(_)));
    assert_eq!(
        row_calls(),
        before + 1,
        "a row whose authoring identity disagrees with the desired version must be \
         repaired with exactly one apply_projected_row_atomic call"
    );
    assert_eq!(
        h.state.get_authoring_change_hash(GROUP, "row-only.txt").unwrap(),
        Some(desired),
        "the repair must leave the row naming the desired authoring identity"
    );

    let settled = row_calls();
    assert!(matches!(materialize().await.unwrap(), MaterializeResult::Settled(_)));
    assert_eq!(
        row_calls(),
        settled,
        "once the row agrees, re-examining the path must not write it again"
    );
}

/// A content-identical verification must SNAPSHOT the mutation fence,
/// never bump it -- bumping on a call that
/// wrote nothing would falsely invalidate a proof some OTHER, still-
/// current mutation is entitled to publish. Confirmed genuinely RED
/// against a version of this fix that called `dag_bump_mutation_fence`
/// instead of `dag_snapshot_mutation_fence` on the content-identical
/// path: that version made this test's second assertion fail (fence
/// advanced to 2 instead of staying at 1).
#[tokio::test]
async fn content_identical_verification_snapshots_the_fence_rather_than_bumping_it() {
    let h = Harness::new();
    let version = version_for(&h.state, &h.store, b"snapshot not bump content");
    h.admit("snapshot-not-bump.txt", &version, &h.emitter);
    let head = h.winner_head("snapshot-not-bump.txt");

    // First call: a real write, so the fence bumps from 0 to 1.
    let first = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "snapshot-not-bump.txt",
            "snapshot-not-bump.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    let first_generation = match first {
        MaterializeResult::Settled(SettlementEvidence::ExactObject {
            mutation_generation, ..
        }) => mutation_generation,
        other => panic!("expected a real write to settle as ExactObject, got {other:?}"),
    };
    assert_eq!(first_generation, 1, "the first, real write must bump the fence to 1");

    // Second call: content already matches -- the content-identical
    // fast path runs, which must SNAPSHOT (read, not advance) the
    // fence rather than bump it again.
    let second = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "snapshot-not-bump.txt",
            "snapshot-not-bump.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    let second_generation = match second {
        MaterializeResult::Settled(SettlementEvidence::ExactObject {
            mutation_generation, ..
        }) => mutation_generation,
        other => panic!(
            "expected the content-identical fast path to settle as ExactObject, got {other:?}"
        ),
    };
    assert_eq!(
        second_generation, first_generation,
        "a content-identical verification must snapshot the fence, never bump it -- \
         the second call's evidence must carry the SAME generation as the first"
    );
}

/// An on-demand (not eager/pinned) placeholder settlement is a
/// policy-authorized deferral, not proof of real content -- it must
/// never produce `SettlementEvidence::ExactObject`/`ExactAbsent`,
/// which is what the publication boundary uses to decide whether to
/// write `path_materialized_
/// generations`. Confirmed genuinely RED against a version of this fix
/// that returned `MaterializeResult::Settled(SettlementEvidence::
/// ExactObject { .. })` unconditionally for every `Settled` outcome:
/// that version made this test's `matches!` assertion fail.
// Windows defers every on-demand placeholder to the CfAPI host and retries;
// there is no synchronous placeholder settlement to classify there.
#[cfg(not(windows))]
#[tokio::test]
async fn on_demand_placeholder_settlement_produces_policy_placeholder_evidence_not_an_exact_object()
{
    let h = Harness::new();
    let version = version_for(&h.state, &h.store, b"on-demand deferred content");
    h.admit("on-demand.txt", &version, &h.emitter);
    let head = h.winner_head("on-demand.txt");

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "on-demand.txt",
            "on-demand.txt",
            &head,
            MaterializationPolicy::OnDemand,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(result, MaterializeResult::Settled(SettlementEvidence::PolicyPlaceholder)),
        "an on-demand placeholder settlement must carry PolicyPlaceholder evidence, \
         never ExactObject/ExactAbsent -- got {result:?}"
    );
}

/// The DB matching the target version only proves the
/// RECORDED mode/xattrs are right, not that the actual on-disk file's
/// mode still is -- e.g. a local chmod this device's own watcher
/// hasn't reconciled yet. A path in this state must still get zero DB
/// writes (the row/metadata columns already agree), but its on-disk
/// permissions must be repaired back to what's recorded.
#[tokio::test]
async fn a_disk_only_metadata_drift_is_repaired_with_zero_db_writes() {
    let h = Harness::new();
    let content: &[u8] = b"content whose recorded mode drifts on disk";
    let hash = hex::decode(h.store.put(content).unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash), size: content.len() as u32 }],
        content.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    h.admit("drifted.txt", &version, &h.emitter);
    let head = h.winner_head("drifted.txt");

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "drifted.txt",
            "drifted.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, MaterializeResult::Settled(_)));
    let metadata_calls_after_first = h
        .state
        .test_observers
        .apply_incoming_metadata_atomic_calls
        .load(std::sync::atomic::Ordering::SeqCst);

    // Simulate disk drift: something outside this device's own write
    // path (a local chmod) changed the actual on-disk permission bits
    // without going through the index at all.
    let out_path = h.root.path().join("drifted.txt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&out_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&out_path, perms).unwrap();
    }

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "drifted.txt",
            "drifted.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, MaterializeResult::Settled(_)));
    assert_eq!(
        h.state
            .test_observers
            .apply_incoming_metadata_atomic_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        metadata_calls_after_first,
        "the DB row/metadata already agree -- no DB write should happen"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the disk-only drift must be repaired back to the recorded mode");
    }
}

/// An empty regular file (zero blocks)
/// must not be trusted as "already present" purely from the index --
/// if the on-disk empty file was deleted by something outside this
/// device's own write path before the watcher/debounce pipeline
/// caught up, the fast path must fall through to a real write instead
/// of reporting `Settled` over a file that no longer exists.
#[tokio::test]
async fn an_empty_file_deleted_out_of_band_is_reconstructed_not_falsely_settled() {
    let h = Harness::new();
    let version = FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    h.admit("empty.txt", &version, &h.emitter);
    let head = h.winner_head("empty.txt");

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "empty.txt",
            "empty.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, MaterializeResult::Settled(_)));
    let out_path = h.root.path().join("empty.txt");
    assert!(out_path.exists(), "sanity: the first call must actually create the empty file");

    // Simulate an out-of-band delete the watcher/debounce pipeline
    // hasn't caught up to yet.
    std::fs::remove_file(&out_path).unwrap();

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "empty.txt",
            "empty.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, MaterializeResult::Settled(_)));
    assert!(
        out_path.exists(),
        "the fast path must not report Settled over a stale index row for a file that was \
         actually deleted"
    );
}

/// An index row marked deleted is not evidence that the path is absent
/// on disk, and `ExactAbsent` claims exactly that.
///
/// Nothing in this lane looks at disk: `still_live` reads the index and
/// nothing else, so a row that is already a tombstone settles as
/// `ExactAbsent` without this attempt ever observing an absence. Two
/// reachable ways to get there with a file actually present:
///
/// - Local capture marks a directory's orphaned children deleted while
///   holding no lock on the children themselves, and says so -- it
///   passes `publish_absent_proof = false` precisely because it cannot
///   vouch for their absence. The row is deleted regardless.
/// - An external process creates the file under an ignored path. The
///   live watcher returns early on `is_excluded_from_sync` and a full
///   scan does not walk ignored subtrees, so nothing adopts it and the
///   mutation fence never moves -- the stale proof is never invalidated.
///
/// The codebase already draws this line elsewhere:
/// `dag_zero_work_settlement_if_already_current` finds a usable
/// generation and still re-checks disk before authorizing skipped work,
/// requiring `symlink_metadata` to report NotFound for an absence. This
/// lane is the one that skips physical work on the index alone.
#[tokio::test]
async fn a_tombstoned_row_whose_file_is_back_on_disk_does_not_settle_as_absent() {
    let h = Harness::new();
    let path = "recreated-under-a-tombstone.txt";
    h.state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: true,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let delete_change = h.admit_delete(path, &h.emitter);
    let tombstone_author = delete_change.change_hash();
    crate::replica_coordinator::ReplicaCoordinator::set_authoring_change_hash(
        h.state.as_ref(),
        GROUP,
        path,
        &tombstone_author,
    )
    .unwrap();

    // The file is there, and this device has not observed it: exactly
    // what an ignored-path recreate, or a child orphaned by a directory
    // delete, leaves behind.
    std::fs::write(h.root.path().join(path), b"recreated out of band").unwrap();

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Delete(path.to_string(), tombstone_author, None)],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    assert!(
        !matches!(settled.get(path), Some(SettlementEvidence::ExactAbsent { .. })),
        "a path with a file on it must not settle as exactly absent when nothing in this \
         attempt ever looked at disk: settled={settled:?} retry={retry:?}"
    );
    assert!(
        retry.contains(path),
        "the path must come back for another pass -- deciding what to do with content this \
         device has not adopted belongs to local capture, not to this lane: \
         settled={settled:?} retry={retry:?}"
    );
    assert!(
        h.root.path().join(path).exists(),
        "and this lane must not have deleted it: the bytes may be a local edit nobody has \
         indexed yet"
    );
}

/// Prepares one ordinary upsert per `(path, version)` and returns the
/// batch items, in the order given.
async fn prepare_batch<'a>(
    h: &Harness,
    activity_provider: &'a dyn BlockWriteActivityProvider,
    paths: &[(&str, &FileVersion)],
) -> Vec<OrdinaryBatchItem<'a>> {
    let mut items = Vec::new();
    for (path, version) in paths {
        h.admit(path, version, &h.emitter);
        let head = h.winner_head(path);
        let (guard, prepared) = h
            .prepare(path, &head, activity_provider)
            .await
            .expect("an ordinary eager content upsert must classify as batch-eligible");
        items.push(OrdinaryBatchItem::Upsert(guard, Box::new(prepared)));
    }
    items
}

/// A path-local failure after one path's rename (its
/// `chmod` failed) belongs to that path: it is retried with its intent
/// open, and every other path in the batch still converges. Before the
/// fix the `?` returned the error from the whole batch, so the other
/// path's already-renamed bytes were never finalized.
#[tokio::test]
async fn one_paths_metadata_failure_does_not_stop_the_rest_of_its_batch_converging() {
    let h = Harness::new();
    let activity_provider = h.activity_provider.clone();
    let bad = version_for(&h.state, &h.store, b"content whose chmod will fail");
    let good = version_for(&h.state, &h.store, b"content that must still converge");
    let items =
        prepare_batch(&h, activity_provider.as_ref(), &[("a.txt", &bad), ("b.txt", &good)]).await;
    *h.state.test_observers.ordinary_batch_metadata_fault.lock().unwrap() =
        Some((GROUP.to_string(), "a.txt".to_string(), || {
            // What `apply_unix_mode`'s failed `set_permissions` returns.
            PeerSessionError::Storage(yadorilink_local_storage::StorageError::Io(
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            ))
        }));

    let result = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            items,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await;
    let (settled, retry) =
        result.expect("one path's metadata failure must not fail the whole batch");

    assert_eq!(retry, std::collections::BTreeSet::from(["a.txt".to_string()]));
    assert!(!settled.contains_key("a.txt"), "a path whose metadata failed must not settle");
    assert!(settled.contains_key("b.txt"), "the other path must settle: {settled:?}");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "b.txt").unwrap(),
        Some(MaterializationState::Hydrated),
        "the other path must be finalized"
    );
    assert_eq!(
        std::fs::read(h.root.path().join("b.txt")).unwrap(),
        b"content that must still converge"
    );
    assert!(
        h.state.has_materialization_intent(GROUP, "a.txt").unwrap(),
        "the failed path must keep its intent open for repair"
    );
    assert!(!h.state.has_materialization_intent(GROUP, "b.txt").unwrap());
}

/// Formerly pinned the opposite: a validly signed version claiming
/// `Directory` was written as a regular file by the batch, could never
/// prove its kind, and retried forever. A directory is never an ordinary
/// batch candidate -- it has no content to reconstruct -- and goes to the
/// directory lane, where it becomes a real directory carrying its mode
/// and settles exact. The file beside it still converges in the batch.
#[cfg(unix)]
#[tokio::test]
async fn a_directory_version_materializes_as_a_real_directory_and_settles() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Harness::new();
    let activity_provider = h.activity_provider.clone();
    let directory = FileVersion::directory(Some(0o750));
    let good = version_for(&h.state, &h.store, b"an ordinary file beside it");
    h.admit("a", &directory, &h.emitter);
    h.admit("b.txt", &good, &h.emitter);
    let head = h.winner_head("a");
    assert!(
        h.prepare("a", &head, activity_provider.as_ref()).await.is_none(),
        "a directory must never classify as an ordinary batch write"
    );

    let attempt = h
        .convergence
        .reconcile_paths(GROUP, ["a".to_string(), "b.txt".to_string()].into())
        .await
        .unwrap()
        .expect("a live link runs the pass");

    assert!(attempt.retry.is_empty(), "nothing may be left to retry: {:?}", attempt.retry);
    match attempt.evidence_for("a") {
        Some(SettlementEvidence::ExactObject { kind: RecordKind::Directory, version, .. }) => {
            assert_eq!(version, &directory.version_hash)
        }
        other => panic!("the directory must settle exact as a directory, got {other:?}"),
    }
    let out_path = h.root.path().join("a");
    let metadata = std::fs::symlink_metadata(&out_path).unwrap();
    assert!(metadata.is_dir(), "a directory version must be a real directory on disk");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o750);
    assert!(attempt.is_settled("b.txt"));
    assert_eq!(std::fs::read(h.root.path().join("b.txt")).unwrap(), b"an ordinary file beside it");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "a").unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert!(!h.state.has_materialization_intent(GROUP, "a").unwrap());
}

mod directory_lane;
mod namespace_closure;

/// The other side of the classification: an error that is
/// not about one path (a database or invariant failure, which is what
/// `CorruptState` carries) still aborts the whole batch, and nothing in
/// it is reported settled or finalized.
#[tokio::test]
async fn a_batch_wide_error_after_one_paths_write_still_aborts_the_whole_batch() {
    let h = Harness::new();
    let activity_provider = h.activity_provider.clone();
    let first = version_for(&h.state, &h.store, b"written before the batch-wide failure");
    let second = version_for(&h.state, &h.store, b"the path the failure surfaces on");
    let items =
        prepare_batch(&h, activity_provider.as_ref(), &[("a.txt", &first), ("b.txt", &second)])
            .await;
    *h.state.test_observers.ordinary_batch_metadata_fault.lock().unwrap() =
        Some((GROUP.to_string(), "b.txt".to_string(), || {
            PeerSessionError::CorruptState("injected database failure".to_string())
        }));

    let result = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            items,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await;

    assert!(
        matches!(result, Err(PeerSessionError::CorruptState(_))),
        "a batch-wide failure must abort the batch: {result:?}"
    );
    for path in ["a.txt", "b.txt"] {
        assert_eq!(
            h.state.get_materialization_state(GROUP, path).unwrap(),
            Some(MaterializationState::Hydrating),
            "{path}: nothing may be finalized once the batch aborts"
        );
        assert!(h.state.has_materialization_intent(GROUP, path).unwrap());
    }
}

/// Losing the group's live link mid-batch is not one path's
/// problem. `sync_root` reports it as `PathEscapesRoot`, the same variant a
/// genuinely escaping path would carry, so the two cannot be told apart
/// here and the error must abort the whole batch rather than be retried
/// path by path while every other path finalizes against a root that is
/// gone.
#[tokio::test]
async fn a_lost_link_after_one_paths_write_aborts_the_whole_batch() {
    let h = Harness::new();
    let activity_provider = h.activity_provider.clone();
    let first = version_for(&h.state, &h.store, b"written before the link was lost");
    let second = version_for(&h.state, &h.store, b"the path the lost link surfaces on");
    let items =
        prepare_batch(&h, activity_provider.as_ref(), &[("a.txt", &first), ("b.txt", &second)])
            .await;
    assert!(
        matches!(
            h.convergence.sync_root("a-group-with-no-link"),
            Err(PeerSessionError::PathEscapesRoot(_))
        ),
        "the injected error below must be the one a lost link really produces"
    );
    *h.state.test_observers.ordinary_batch_metadata_fault.lock().unwrap() =
        Some((GROUP.to_string(), "b.txt".to_string(), || {
            PeerSessionError::PathEscapesRoot(format!(
                "no live link for group {GROUP}; refusing to resolve a local path"
            ))
        }));

    let result = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            items,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await;

    assert!(
        matches!(result, Err(PeerSessionError::PathEscapesRoot(_))),
        "a lost link must abort the batch: {result:?}"
    );
    for path in ["a.txt", "b.txt"] {
        assert_eq!(
            h.state.get_materialization_state(GROUP, path).unwrap(),
            Some(MaterializationState::Hydrating),
            "{path}: nothing may be finalized once the batch aborts"
        );
        assert!(h.state.has_materialization_intent(GROUP, path).unwrap());
    }
}

/// A fresh write whose version names an owner-unreadable mode (0o200) and a
/// replicated `user.*` attribute must put the attribute on disk and settle
/// as an exact object. The attribute is confirmed inside the write, before
/// the mode that makes it unreadable is applied; changing the mode does not
/// change the attributes, so that confirmation is the proof.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_fresh_write_to_an_owner_unreadable_mode_lands_its_xattr_and_settles_exact() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let content = b"content of a write-only file";
    let hash = hex::decode(h.store.put(content).unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash), size: content.len() as u32 }],
        content.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: Some(0o200),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: xattrs.clone(),
        },
    );
    h.admit("write-only.txt", &version, &h.emitter);
    let head = h.winner_head("write-only.txt");

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            "write-only.txt",
            "write-only.txt",
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(result, MaterializeResult::Settled(SettlementEvidence::ExactObject { .. })),
        "a fresh write to mode 0o200 with an xattr must settle as ExactObject, got {result:?}"
    );

    let out_path = h.root.path().join("write-only.txt");
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs,
        "the replicated attribute must actually be on disk, not only claimed"
    );
}

/// The ordinary batch's own finish (`finish_ordinary_batch_write`) for a
/// version with an owner-unreadable mode and a replicated attribute: the
/// attribute must land and the path must settle, on the in-attempt check
/// rather than a re-read the final mode would make impossible.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_batched_upsert_to_an_owner_unreadable_mode_lands_its_xattr_and_settles() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let content = b"batched content of a write-only file";
    let hash = hex::decode(h.store.put(content).unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash), size: content.len() as u32 }],
        content.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: Some(0o200),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: xattrs.clone(),
        },
    );
    h.admit("batched-write-only.txt", &version, &h.emitter);
    let head = h.winner_head("batched-write-only.txt");
    let activity_provider = h.activity_provider.clone();
    let (guard, prepared) = h
        .prepare("batched-write-only.txt", &head, activity_provider.as_ref())
        .await
        .expect("an ordinary eager content upsert must classify as batch-eligible");

    let (settled, retry) = h
        .convergence
        .try_commit_ordinary_batch(
            GROUP,
            "device-a",
            vec![OrdinaryBatchItem::Upsert(guard, Box::new(prepared))],
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();
    assert!(retry.is_empty(), "the path must not be sent back for retry: {retry:?}");
    assert!(settled.contains_key("batched-write-only.txt"));

    let out_path = h.root.path().join("batched-write-only.txt");
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs
    );
}

/// Writes `path` fresh as a write-only (0o200) file carrying
/// `user.test=first`, settled exact, then admits a second version with the
/// same bytes and `user.test=second` on top of it. Returns that version and
/// its winning head, or `None` when the test runs as root (nothing is
/// unreadable to root, so there is nothing to test).
#[cfg(target_os = "linux")]
async fn write_only_file_then_an_xattr_change(
    h: &Harness,
    path: &str,
    content: &[u8],
) -> Option<(FileVersion, PathHead)> {
    use std::os::unix::fs::PermissionsExt;
    let hash = hex::decode(h.store.put(content).unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let version_with = |value: &[u8]| {
        FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash.clone()), size: content.len() as u32 }],
            content.len() as u64,
            FileMeta {
                mtime_unix_nanos: 0,
                unix_mode: Some(0o200),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: vec![("user.test".to_string(), value.to_vec())],
            },
        )
    };
    let first = version_with(b"first");
    h.admit(path, &first, &h.emitter);
    let head = h.winner_head(path);
    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            path,
            path,
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(result, MaterializeResult::Settled(SettlementEvidence::ExactObject { .. })),
        "sanity: the first version must land exact, got {result:?}"
    );
    let out_path = h.root.path().join(path);
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    if std::fs::File::open(&out_path).is_ok() {
        return None;
    }
    let second = version_with(b"second");
    h.admit(path, &second, &h.emitter);
    let head = h.winner_head(path);
    assert_eq!(
        head.content.as_ref().map(|content| content.version_hash),
        Some(second.version_hash.0),
        "sanity: the xattr change must be the winner"
    );
    Some((second, head))
}

/// An existing write-only file's bytes and replicated attributes, read
/// back through a temporary chmod in the test only; the mode is restored
/// before returning. The chmod moves ctime, so any identity comparison has
/// to be taken before this is called.
#[cfg(target_os = "linux")]
fn read_back_write_only_file(out_path: &std::path::Path) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(out_path).unwrap().permissions().mode();
    std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = std::fs::read(out_path).unwrap();
    let xattrs =
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(out_path).unwrap());
    std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(mode)).unwrap();
    (bytes, xattrs)
}

/// The projection of an xattr-only change onto a file that is already on
/// disk with an owner-unreadable mode. Its bytes cannot be verified and its
/// attributes can be neither read back nor set, so it used to fail the
/// pass with a raw permission error, retried forever. It must be held: the
/// file untouched (same inode, no chmod, same bytes and attribute), no
/// fence bump, no exact proof, and the reason recorded for status.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_xattr_change_to_an_existing_owner_unreadable_file_is_held_not_replaced() {
    let h = Harness::new();
    let path = "write-only.txt";
    let content = b"content of an existing write-only file";
    let Some((_, head)) = write_only_file_then_an_xattr_change(&h, path, content).await else {
        return;
    };
    let out_path = h.root.path().join(path);
    let identity_before =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    let fence_before = h.state.dag_snapshot_mutation_fence(GROUP, path).unwrap();

    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            path,
            path,
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();

    let reason = yadorilink_peer_session::hazard::metadata_unprovable_reason();
    match &result {
        MaterializeResult::Settled(SettlementEvidence::HazardHeld { reason: held }) => {
            assert_eq!(held, &reason);
        }
        other => panic!("an unreadable existing file must be held, got {other:?}"),
    }
    assert_eq!(
        h.state.get_held_state(GROUP, path).unwrap().map(|held| held.reason),
        Some(reason),
        "the hold must be recorded on the row, where status reads it"
    );
    assert_eq!(
        h.state.dag_snapshot_mutation_fence(GROUP, path).unwrap(),
        fence_before,
        "nothing was mutated, so the fence must not move"
    );
    let identity_after =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    assert_eq!(
        identity_after.object_id, identity_before.object_id,
        "the file must not be replaced"
    );
    assert_eq!(
        identity_after.metadata_fingerprint, identity_before.metadata_fingerprint,
        "the file must not be touched at all (mode, mtime, ctime)"
    );
    let (bytes, xattrs) = read_back_write_only_file(&out_path);
    assert_eq!(bytes, content);
    assert_eq!(xattrs, vec![("user.test".to_string(), b"first".to_vec())]);
}

/// The same xattr-only change arriving as a record through the metadata-only
/// fast path of `materialize_local` (the peer lane's route). Same outcome:
/// held with the reason, nothing written, no exact proof, no fence bump.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_metadata_only_update_of_an_existing_owner_unreadable_file_is_held_not_replaced() {
    let h = Harness::new();
    let path = "write-only-record.txt";
    let content = b"content of an existing write-only record";
    let Some((second, _)) = write_only_file_then_an_xattr_change(&h, path, content).await else {
        return;
    };
    let out_path = h.root.path().join(path);
    let identity_before =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    let fence_before = h.state.dag_snapshot_mutation_fence(GROUP, path).unwrap();

    let outcome = h
        .convergence
        .materialize_local(
            GROUP,
            &super::types::MaterializationPayload::from_version(path, second),
            path,
            MaterializationPolicy::Eager,
            "device-remote",
            None,
            None,
        )
        .await
        .unwrap();

    let reason = yadorilink_peer_session::hazard::metadata_unprovable_reason();
    match &outcome {
        super::types::LocalMaterializeOutcome::Concluded(MaterializeResult::Settled(
            SettlementEvidence::HazardHeld { reason: held },
        )) => assert_eq!(held, &reason),
        other => panic!("an unreadable existing file must be held, got {other:?}"),
    }
    assert_eq!(h.state.get_held_state(GROUP, path).unwrap().map(|held| held.reason), Some(reason));
    assert_eq!(h.state.dag_snapshot_mutation_fence(GROUP, path).unwrap(), fence_before);
    let identity_after =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
    assert_eq!(identity_after.object_id, identity_before.object_id);
    assert_eq!(identity_after.metadata_fingerprint, identity_before.metadata_fingerprint);
    let (bytes, xattrs) = read_back_write_only_file(&out_path);
    assert_eq!(bytes, content);
    assert_eq!(xattrs, vec![("user.test".to_string(), b"first".to_vec())]);
}

/// A metadata repair of an existing, readable file to a version whose mode
/// denies its owner read access (0o200) and whose mtime differs. The mtime
/// stamp opens the file, so it has to land before the final mode does, as
/// the attributes do; stamped after it, the open fails with a raw
/// permission error and the repair, having bumped the fence and changed
/// the mode, is retried against a file it has itself made unreadable.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_metadata_repair_to_an_owner_unreadable_mode_settles_with_its_mtime() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let path = "becomes-write-only.txt";
    let content = b"content of a file about to become write-only";
    let hash = hex::decode(h.store.put(content).unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let version_with = |unix_mode: u32, mtime_unix_nanos: i64, xattrs: Vec<(String, Vec<u8>)>| {
        FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash.clone()), size: content.len() as u32 }],
            content.len() as u64,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: Some(unix_mode),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs,
            },
        )
    };
    h.admit(path, &version_with(0o600, 0, Vec::new()), &h.emitter);
    let head = h.winner_head(path);
    let first = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            path,
            path,
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(first, MaterializeResult::Settled(SettlementEvidence::ExactObject { .. })));

    let mtime = 1_600_000_000_000_000_000;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];
    h.admit(path, &version_with(0o200, mtime, xattrs.clone()), &h.emitter);
    let head = h.winner_head(path);
    let result = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            path,
            path,
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await;

    let out_path = h.root.path().join(path);
    let metadata = std::fs::metadata(&out_path).unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        matches!(result, Ok(MaterializeResult::Settled(SettlementEvidence::ExactObject { .. }))),
        "the repair must settle exact, got {result:?}"
    );
    assert_eq!(metadata.permissions().mode() & 0o777, 0o200);
    assert_eq!(
        std::os::unix::fs::MetadataExt::mtime(&metadata) as i64 * 1_000_000_000
            + std::os::unix::fs::MetadataExt::mtime_nsec(&metadata),
        mtime
    );
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs
    );
}

/// The metadata-only fast path of `materialize_local` (the peer lane's
/// route) for the same repair: a readable file moved to 0o200 with a new
/// mtime and attribute must settle exact, with the mtime stamped before
/// the mode that makes the file unreadable.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_metadata_only_update_to_an_owner_unreadable_mode_settles_with_its_mtime() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let path = "record-becomes-write-only.txt";
    let content = b"content of a record about to become write-only";
    let hash = hex::decode(h.store.put(content).unwrap()).unwrap();
    h.state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let version_with = |unix_mode: u32, mtime_unix_nanos: i64, xattrs: Vec<(String, Vec<u8>)>| {
        FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash.clone()), size: content.len() as u32 }],
            content.len() as u64,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: Some(unix_mode),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs,
            },
        )
    };
    h.admit(path, &version_with(0o600, 0, Vec::new()), &h.emitter);
    let head = h.winner_head(path);
    let first = h
        .convergence
        .materialize_dag_content_head(
            GROUP,
            path,
            path,
            &head,
            MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(first, MaterializeResult::Settled(SettlementEvidence::ExactObject { .. })));

    let mtime = 1_600_000_000_000_000_000;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];
    let second = version_with(0o200, mtime, xattrs.clone());
    let author = h.admit(path, &second, &h.emitter).change_hash();
    // What the peer lane does before it materializes: the record's wire
    // metadata lands on the row first.
    super::types::apply_incoming_wire_metadata(
        h.state.as_ref(),
        GROUP,
        &super::types::file_record_from_version(path, &second),
        &super::types::IncomingWireMeta {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: Some(0o200),
            xattrs: xattrs.clone(),
            origin_device_id: Some("device-remote".to_string()),
            authoring_change_hash: Some(author),
        },
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    let outcome = h
        .convergence
        .materialize_local(
            GROUP,
            &super::types::MaterializationPayload::from_version(path, second),
            path,
            MaterializationPolicy::Eager,
            "device-remote",
            Some(&author),
            None,
        )
        .await;

    let out_path = h.root.path().join(path);
    let metadata = std::fs::metadata(&out_path).unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        matches!(
            outcome,
            Ok(super::types::LocalMaterializeOutcome::Concluded(MaterializeResult::Settled(
                SettlementEvidence::ExactObject { .. }
            )))
        ),
        "the update must settle exact, got {outcome:?}"
    );
    assert_eq!(metadata.permissions().mode() & 0o777, 0o200);
    assert_eq!(
        std::os::unix::fs::MetadataExt::mtime(&metadata) as i64 * 1_000_000_000
            + std::os::unix::fs::MetadataExt::mtime_nsec(&metadata),
        mtime
    );
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs
    );
}
