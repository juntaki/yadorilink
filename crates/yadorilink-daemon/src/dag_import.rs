//! First-run conversion of an existing file index into signed change
//! history.
//!
//! The change-history DAG is created empty by the schema migration, so an
//! installation that predates it keeps a fully materialized file index with
//! no history behind it. On the first run after the DAG is provisioned (the
//! device now has a signing key, hence a [`ChangeEmitter`]), each linked
//! group's current index is converted — once — into a chain of signed
//! "initial-import" changes, so history begins at the observed present
//! without fabricating a past that was never recorded.
//!
//! Every import change is authored and signed by the *local* device. It is
//! an assertion of what this device currently holds, not a reconstruction of
//! which device originally wrote each file: a change verifies against the
//! signing key named by its own `device_id`, so a change can only ever be
//! signed by the device it is attributed to, and attributing an imported
//! file to some other origin device would make it unverifiable everywhere
//! else. Live records become `Op::Put { origin: PutOrigin::Direct, .. }`,
//! tombstoned records become `Op::Delete`, and the content version hash of
//! each put is built exactly the way live emission builds it (block hashes +
//! size + mtime + exec bit + symlink target/kind) — so a file imported here
//! and the same file later re-emitted by a normal local edit hash to the same
//! version.
//!
//! Idempotency and crash-safety: the whole import for a group commits in one
//! transaction, and it runs only when the group's head set is still empty
//! (re-checked inside that transaction). A crash mid-import rolls the
//! transaction back, leaving the group un-imported so the next run redoes
//! it; a second start — or a concurrent one — observes the committed history
//! and does nothing. History is therefore never duplicated.
//!
//! Call ordering (the daemon's responsibility): [`ensure_initial_import`]
//! must complete for a group before that group's [`ChangeEmitter`] is wired
//! into local emission and before any change-DAG peer session for the group
//! runs, so import always establishes the root of history ahead of the first
//! live mutation or admitted peer change.
//!
//! Relocated here from `yadorilink-sync-core` (Phase 7D-10.5): every real
//! production caller ([`crate::daemon_state::DaemonState::
//! backfill_missing_change_history`], `crate::link_runtime::startup`) already
//! passed a `&ReplicaCoordinator`, not a `&SyncState` — this module's own
//! generic `DagImportSource` bound was already indifferent to which concrete
//! type it ran against, so moving the module itself is a pure change of
//! which crate it compiles in, not of behavior. During the transitional
//! dual-wiring period this module kept an `impl DagImportSource for
//! SyncState` purely for `yadorilink-local-capture`'s own test suite, which
//! exercised the daemon's restart-reconcile sequence against a `SyncState`
//! fixture directly; Phase 7D-10's final sync-core deletion pass repointed
//! that test suite onto `ReplicaCoordinator` instead (same dev-only
//! back-edge onto `yadorilink-daemon`, the same shape
//! `yadorilink-peer-session`'s own tests already used), so `ReplicaCoordinator`
//! (`replica_coordinator.rs`) is now this trait's sole implementor.
//! `IMPORT_BATCH_OP_LIMIT` itself did not move here: `yadorilink-local-
//! capture`'s own `RECONCILE_CHUNK_OP_LIMIT` (a real, non-test production
//! constant) needs it and sits below `yadorilink-daemon` in the dependency
//! graph, so it now lives at
//! `yadorilink_replica_domain::change::IMPORT_BATCH_OP_LIMIT`, shared by both
//! callers.

use std::path::Path;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::change::{
    encoded_op_len, Op, PutOrigin, IMPORT_BATCH_OP_LIMIT, MAX_CHANGE_OP_BYTES,
};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_root_authority::reserved_namespace::path_has_reserved_component;
use yadorilink_root_authority::sync_root_lock::is_sync_root_lock_relative_path;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

/// What [`ensure_initial_import`]/[`backfill_missing_history`] need from a
/// concrete replica-state type: read the file index, read/write the
/// change-history DAG, serialize per-path work in flight, and append signed
/// changes -- nothing else. Deliberately narrow, mirroring
/// `yadorilink_sync_core::recovery::RecoveryInventorySource`/
/// `yadorilink_sync_core::materialization::MaterializationIntentJournal`'s
/// established crate-local pattern: prove the type owns the repository/
/// registry handles this module needs, not the full `SyncState` surface.
/// Both `SyncState` and this crate's own `ReplicaCoordinator` construct
/// every one of these from the same shared `Arc<SyncDatabase>`, so any
/// implementation reaches the identical underlying tables -- this is a pure
/// generalization of which Rust value these functions are called through,
/// not a change to what gets read or written.
pub trait DagImportSource {
    fn sqlite(&self) -> &yadorilink_sync_sqlite::SqliteSyncStore;
    fn file_index_repository(&self) -> &yadorilink_sync_sqlite::file_index::FileIndexRepository;
    fn change_history_repository(&self) -> &yadorilink_sync_sqlite::ChangeHistoryRepository;
    /// Returns the shared lock for `(group_id, path)` -- see
    /// `PathLockRegistry::path_lock`'s own doc comment for the race it
    /// closes. Returns the lock directly rather than the registry itself:
    /// `SyncState` (`yadorilink-sync-core`) and `ReplicaCoordinator`
    /// (`yadorilink-daemon`) each own an independent, differently-typed
    /// `PathLockRegistry` (Phase 7D-10.11's "temporary coexistence"
    /// duplication), so this trait cannot name a single concrete registry
    /// type across both implementors -- the lock type itself
    /// (`Arc<tokio::sync::Mutex<()>>`) is identical either way.
    fn path_lock(&self, group_id: &str, path: &str) -> std::sync::Arc<tokio::sync::Mutex<()>>;
    /// See `SyncState::append_initial_import`'s own doc comment.
    fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<Option<usize>, SyncError>;
    /// See `SyncState::append_history_backfill`'s own doc comment.
    fn append_history_backfill(
        &self,
        group_id: &str,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<yadorilink_replica_domain::ids::ChangeHash, SyncError>;
}

/// Whether an indexed path must never enter change history: either the
/// reserved artefact namespace (`reserved_namespace`, defense-in-depth
/// against a pre-exclusion-era stale row) or this device's own sync-root
/// lock file (`sync_root_lock`, same rationale -- a database predating that
/// module's exclusion could hold an indexed row for it too, and importing it
/// would ship this device's process-management artefact into the group's
/// signed history exactly as wrongly as a transaction artefact would).
fn path_must_never_enter_history(path: &Path) -> bool {
    path_has_reserved_component(path) || is_sync_root_lock_relative_path(path)
}

/// What [`ensure_initial_import`] did for a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// The group already had change history; nothing was imported.
    AlreadyInitialized,
    /// The group's index was empty; there was nothing to convert.
    NothingToImport,
    /// Converted the index into `changes` signed changes carrying `ops`
    /// operations in total.
    Imported { changes: usize, ops: usize },
}

/// Result of the periodic history-coverage repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillOutcome {
    NothingMissing,
    Backfilled { paths: usize },
}

/// Appends current index records that have never appeared in this group's DAG.
///
/// This repairs the startup race where the initial import is withheld by stale
/// policy after the scan has already advanced the index. A later unrelated
/// change makes the head set non-empty, permanently closing the one-shot
/// initial-import path; path coverage, rather than an empty-head check, is the
/// retry trigger that remains valid in that state.
pub async fn backfill_missing_history<S: DagImportSource>(
    state: &S,
    group_id: &str,
    emitter: &ChangeEmitter,
) -> Result<BackfillOutcome, SyncError> {
    let known = state.change_history_repository().dag_group_history_paths(group_id)?;
    let candidates: Vec<String> = state
        .file_index_repository()
        .list_files(group_id)?
        .into_iter()
        .map(|r| r.path)
        .filter(|path| !known.contains(path))
        // A conflict-copy-shaped path that is indexed but absent from
        // history is NOT a coverage gap for this audit to close: projection
        // materializes (and indexes) a derived conflict copy on every device
        // that observes the concurrent heads, *before* any change carries
        // it, and the carrier op for it is owned by the retroactive
        // conflict-copy repair loop (`repair_retroactive_conflict_copy_
        // obligations`), which emits one deterministic `PutOrigin::
        // ConflictCopy` change. Minting a `Direct` create here instead is a
        // confirmed, reproduced convergence-killer: every device's own
        // periodic sweep independently emitted its own change for the same
        // copy path (observed live: three devices minting one path), so the
        // devices' frontiers diverged into disjoint per-author heads on
        // exactly the runs slow enough for the sweep to engage mid-run —
        // and each such resolution then spawned further conflict copies of
        // the copy, re-feeding this same audit. A user-created file that
        // merely mimics the marker is still covered by the ordinary
        // watcher/local-change path (which appends its change atomically
        // with the index row), so skipping it here does not orphan it.
        .filter(|path| !yadorilink_replica_domain::conflict::is_conflict_copy_path(path))
        .collect();
    // Every producer of a NEW index row already excludes a
    // reserved-component path before it is ever written
    // (`local_change::is_excluded_from_sync`), so ordinarily this finds
    // nothing. It is not purely defense-in-depth, though: a database from
    // before this exclusion existed can already hold an index row for a
    // path that happened to collide with the reserved shape while it was
    // still ordinary content — this is the one place that stale row is
    // caught before backfill would otherwise turn it into signed history.
    // Reported loudly rather than silently dropped (design's
    // `Blocked(ReservedNamespaceCollision)` requirement: a collision must
    // name the path, not vanish) — this device's own content is stuck
    // unsyncable under this name until it's renamed, which nothing else
    // in this crate is in a position to tell the user without this log.
    let (candidates, blocked): (Vec<String>, Vec<String>) =
        candidates.into_iter().partition(|path| !path_must_never_enter_history(Path::new(path)));
    for path in &blocked {
        tracing::warn!(
            group_id,
            path = %path,
            "indexed path collides with the reserved artefact namespace and cannot be added to \
             change history; rename it on disk to make it syncable again"
        );
    }
    let mut appended = 0usize;
    for path in candidates {
        let path_lock = state.path_lock(group_id, &path);
        let _guard = path_lock.lock().await;
        if state.change_history_repository().dag_group_history_paths(group_id)?.contains(&path) {
            continue;
        }
        let Some(record) = state.file_index_repository().get_file(group_id, &path)? else {
            continue;
        };
        let (op, versions) = if record.deleted {
            (Op::Delete { path: SyncPath(path.clone()) }, Vec::new())
        } else {
            let (op, version) = import_create_op(state, group_id, &record)?;
            (op, vec![version])
        };
        tracing::info!(
            group_id,
            path = %path,
            deleted = record.deleted,
            author = %emitter.device_id(),
            "backfilling indexed path missing from change history"
        );
        state.append_history_backfill(group_id, vec![op], &versions, emitter)?;
        appended += 1;
    }
    if appended == 0 {
        Ok(BackfillOutcome::NothingMissing)
    } else {
        Ok(BackfillOutcome::Backfilled { paths: appended })
    }
}

/// Converts `group_id`'s current index into initial-import changes, once.
///
/// Idempotent and crash-safe: the append is transactional and gated on the
/// group's history still being empty (see the module docs). Safe to call on
/// every daemon start for every linked group; only the first call that finds
/// an empty DAG for a non-empty index actually writes anything.
pub fn ensure_initial_import<S: DagImportSource>(
    state: &S,
    group_id: &str,
    emitter: &ChangeEmitter,
) -> Result<ImportOutcome, SyncError> {
    // Cheap pre-check outside any transaction: a group that already has a
    // head has history, so there is nothing to import and no reason to read
    // and convert its index. The authoritative check runs again inside the
    // write transaction in `SyncState::append_initial_import`, so this is
    // purely an optimization, not the correctness guard.
    if !state.sqlite().dag_group_heads(group_id)?.is_empty() {
        return Ok(ImportOutcome::AlreadyInitialized);
    }

    // Sort by path so the synthesized chain is reproducible from the same
    // index rather than depending on row iteration order.
    let mut records = state.file_index_repository().list_files(group_id)?;
    // Every producer of a NEW index row already excludes a
    // reserved-component path before it is ever written
    // (`local_change::is_excluded_from_sync`), so ordinarily this finds
    // nothing. It is not purely defense-in-depth, though: a database from
    // before this exclusion existed can already hold an index row for a
    // path that happened to collide with the reserved shape while it was
    // still ordinary content — this is the one place that stale row is
    // caught before the one-shot initial import would otherwise turn it
    // into signed history. Reported loudly rather than silently dropped
    // (design's `Blocked(ReservedNamespaceCollision)` requirement: a
    // collision must name the path, not vanish) — this device's own
    // content is stuck unsyncable under this name until it's renamed,
    // which nothing else in this crate is in a position to tell the user
    // without this log.
    let blocked: Vec<String> = records
        .iter()
        .filter(|r| path_must_never_enter_history(Path::new(&r.path)))
        .map(|r| r.path.clone())
        .collect();
    for path in &blocked {
        tracing::warn!(
            group_id,
            path = %path,
            "indexed path collides with the reserved artefact namespace and cannot be added to \
             change history; rename it on disk to make it syncable again"
        );
    }
    records.retain(|r| !path_must_never_enter_history(Path::new(&r.path)));
    records.sort_by(|a, b| a.path.cmp(&b.path));
    if records.is_empty() {
        return Ok(ImportOutcome::NothingToImport);
    }

    let mut ops = Vec::with_capacity(records.len());
    let mut versions: Vec<FileVersion> = Vec::new();
    for record in &records {
        if record.deleted {
            ops.push(Op::Delete { path: SyncPath(record.path.clone()) });
        } else {
            let (op, version) = import_create_op(state, group_id, record)?;
            ops.push(op);
            versions.push(version);
        }
    }
    let total_ops = ops.len();

    // Split the ops into chunks bounded by BOTH op count and canonical encoded
    // byte size, each of which becomes one signed import change. Op count alone
    // is not enough: a first import of <= IMPORT_BATCH_OP_LIMIT files with
    // pathologically long paths could still encode to several MiB — larger than
    // any single wire message can carry (a change cannot be wire-split), which
    // would strand that root change permanently un-propagatable and break
    // history replication for the whole group. The byte cap
    // (`change::MAX_CHANGE_OP_BYTES`) is shared with the startup reconcile so
    // whichever path first observes a bulk diff bounds it identically. At least
    // one op is always taken per chunk (`end == start`), so a single large op
    // can never wedge the loop. `append_initial_import` emits the batches in
    // order, each chaining onto the head the previous one committed, so the
    // chunks form one linear chain converging on a single head.
    let mut batches: Vec<Vec<Op>> = Vec::new();
    let mut start = 0usize;
    while start < ops.len() {
        let mut end = start;
        let mut chunk_bytes = 0usize;
        while end < ops.len() {
            let op_bytes = encoded_op_len(&ops[end]);
            if end > start
                && (end - start >= IMPORT_BATCH_OP_LIMIT
                    || chunk_bytes + op_bytes > MAX_CHANGE_OP_BYTES)
            {
                break;
            }
            chunk_bytes += op_bytes;
            end += 1;
        }
        batches.push(ops[start..end].to_vec());
        start = end;
    }

    match state.append_initial_import(group_id, &batches, &versions, emitter)? {
        Some(changes) => Ok(ImportOutcome::Imported { changes, ops: total_ops }),
        // Lost the race to another start that imported (or began emitting)
        // between the pre-check above and the transaction: its history now
        // stands, and this call correctly did nothing.
        None => Ok(ImportOutcome::AlreadyInitialized),
    }
}

/// Builds the direct `Op::Put` for a live record, deriving its content version
/// hash the same way local emission does so an imported file and a later
/// re-emission of the same file share a version. The symlink-target column
/// is populated only for symlink records, so its presence is exactly what
/// distinguishes a symlink from a regular file — matching how live emission
/// classifies the same record — and a symlink carries no exec bit, which the
/// column already reflects as `false`.
fn import_create_op<S: DagImportSource>(
    state: &S,
    group_id: &str,
    record: &FileRecord,
) -> Result<(Op, FileVersion), SyncError> {
    let blocks = record
        .blocks
        .iter()
        .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
        .collect();
    let symlink_target =
        state.file_index_repository().get_symlink_target(group_id, &record.path)?;
    let exec_bit = state.file_index_repository().get_exec_bit(group_id, &record.path)?;
    // The index is authoritative for the record type. In particular a
    // directory has neither blocks nor a symlink target, just like an empty
    // regular file, so inferring kind from `symlink_target` collapses it to a
    // file during the one-time DAG import.
    let record_kind = state
        .file_index_repository()
        .get_record_kind(group_id, &record.path)?
        .unwrap_or(RecordKind::File);
    let meta = FileMeta {
        mtime_unix_nanos: record.mtime_unix_nanos,
        exec_bit,
        symlink_target,
        record_kind,
    };
    let version = FileVersion::new(blocks, record.size, meta);
    let op = Op::Put {
        path: SyncPath(record.path.clone()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    };
    Ok((op, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica_coordinator::ReplicaCoordinator;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::ChangeAuth;
    use yadorilink_replica_domain::file::BlockInfo;
    fn emitter() -> ChangeEmitter {
        ChangeEmitter::new("device-A", SigningKey::from_bytes(&[9u8; 32]))
    }

    fn live(path: &str) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 3,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash: vec![1, 2, 3], offset: 0, size: 3 }],
            deleted: false,
        }
    }

    fn tombstone(path: &str) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 0,
            mtime_unix_nanos: 5,
            blocks: vec![],
            deleted: true,
        }
    }

    #[test]
    fn converts_live_and_tombstoned_records_in_one_change() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live("a.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &tombstone("gone.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 2 });

        // Exactly one root head, whose change carries a Create for the live
        // file and a Delete for the tombstone.
        let heads = state.sqlite().dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1);
        let change = state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
        assert_eq!(
            state.file_index_repository().get_authoring_change_hash("g", "a.txt").unwrap(),
            Some(heads[0])
        );
        assert_eq!(
            state.file_index_repository().get_authoring_change_hash("g", "gone.txt").unwrap(),
            Some(heads[0])
        );
        assert!(change.parents.is_empty());
        assert!(change
            .ops
            .iter()
            .any(|op| matches!(op, Op::Put { path, .. } if path.as_str() == "a.txt")));
        assert!(change
            .ops
            .iter()
            .any(|op| matches!(op, Op::Delete { path } if path.as_str() == "gone.txt")));
    }

    #[test]
    fn dag_backed_current_rows_require_a_verified_authoring_identity() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let seeded = live("seeded.txt");
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &seeded,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let (op, version) = import_create_op(&state, "g", &seeded).unwrap();
        let author = state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();

        let error = state
            .file_index_repository()
            .upsert_file(
                "g",
                &live("identity-less.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .map_err(SyncError::from)
            .expect_err("a DAG-backed group must reject a current row with no author");
        assert!(matches!(error, SyncError::Db(_)), "{error:?}");

        state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                "g",
                &live("identified.txt"),
                "device-A",
                &author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert_eq!(
            state.file_index_repository().get_authoring_change_hash("g", "identified.txt").unwrap(),
            Some(author)
        );
    }

    #[test]
    fn import_version_hash_matches_live_emission() {
        // The create op's version hash must equal what a normal local edit
        // would have emitted for the same record, so the two never diverge.
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let record = live("a.txt");
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let (op, _version) = import_create_op(&state, "g", &record).unwrap();
        let Op::Put { version, .. } = op else { panic!("expected a put op") };

        let expected = FileVersion::new(
            record
                .blocks
                .iter()
                .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
                .collect(),
            record.size,
            FileMeta {
                mtime_unix_nanos: record.mtime_unix_nanos,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
        .version_hash;
        assert_eq!(version, expected);
    }

    #[test]
    fn import_preserves_a_stored_directory_kind() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let mut record = live("folder");
        record.size = 0;
        record.blocks.clear();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .set_record_kind(
                "g",
                "folder",
                RecordKind::Directory,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let (_, version) = import_create_op(&state, "g", &record).unwrap();
        assert_eq!(version.meta.record_kind, RecordKind::Directory);
    }

    /// Regression test for a confirmed, reproduced convergence-killer (see
    /// `backfill_missing_history`'s own comment on the conflict-copy
    /// filter): a projection-derived conflict copy is indexed on every
    /// observing device before any change carries it, and the coverage
    /// audit used to read that window as "indexed path missing from
    /// history" and mint a per-device `Direct` create for it — several
    /// devices concurrently, for the same copy path. The carrier is the
    /// retroactive conflict-copy repair's to emit, so the audit must skip
    /// conflict-copy-shaped paths entirely (also on repeat calls: the path
    /// must not keep the audit reporting work forever), while still
    /// repairing an ordinary path in the same pass.
    #[tokio::test]
    async fn backfill_skips_a_derived_conflict_copy_path_but_repairs_an_ordinary_one() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.set_local_change_auth_provider(std::sync::Arc::new(|_| {
            Ok(ChangeAuth { auth_seq: 7, auth_epoch: 2, policy_head_hash: [4; 32] })
        }));
        // Seed one head so this exercises the mid-life coverage audit, not
        // initial import.
        let seeded = live("seeded.txt");
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &seeded,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let (op, version) = import_create_op(&state, "g", &seeded).unwrap();
        let seed_author =
            state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();

        let copy_path = yadorilink_replica_domain::conflict::conflict_copy_path(
            "chaos-05.bin",
            1_000,
            "device-B",
            &[0xf6, 0xca, 0xc4, 0xff],
        );
        state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                "g",
                &live(&copy_path),
                "device-A",
                &seed_author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                "g",
                &live("ordinary.bin"),
                "device-A",
                &seed_author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::Backfilled { paths: 1 }
        );
        let history = state.change_history_repository().dag_group_history_paths("g").unwrap();
        assert!(history.contains("ordinary.bin"), "the ordinary gap must still be repaired");
        assert!(
            !history.contains(&copy_path),
            "a derived conflict copy must never be minted into history by the coverage audit"
        );
        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::NothingMissing,
            "the skipped copy path must not keep the audit claiming outstanding work"
        );
    }

    /// The mid-life coverage audit's own version of the initial-import
    /// test above: a pre-existing index row that collides with the
    /// reserved artefact namespace must never be backfilled into history,
    /// while an ordinary coverage gap around it is still repaired, and the
    /// audit must not keep reporting outstanding work once the only
    /// remaining gap is the permanently-skipped collision.
    #[tokio::test]
    async fn backfill_skips_a_pre_existing_reserved_namespace_collision_but_repairs_an_ordinary_one(
    ) {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.set_local_change_auth_provider(std::sync::Arc::new(|_| {
            Ok(ChangeAuth { auth_seq: 7, auth_epoch: 2, policy_head_hash: [4; 32] })
        }));
        let seeded = live("seeded.txt");
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &seeded,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let (op, version) = import_create_op(&state, "g", &seeded).unwrap();
        let seed_author =
            state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();

        let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Backup,
            "cafef00d",
        )
        .unwrap();
        state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                "g",
                &live(&artefact_path),
                "device-A",
                &seed_author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                "g",
                &live("ordinary.bin"),
                "device-A",
                &seed_author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::Backfilled { paths: 1 }
        );
        let history = state.change_history_repository().dag_group_history_paths("g").unwrap();
        assert!(history.contains("ordinary.bin"), "the ordinary gap must still be repaired");
        assert!(
            !history.contains(&artefact_path),
            "a reserved-namespace collision must never be minted into history by the coverage audit"
        );
        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::NothingMissing,
            "the permanently-skipped collision must not keep the audit claiming outstanding work"
        );
    }

    #[tokio::test]
    async fn audit_repairs_policy_withheld_initial_import_after_another_path_creates_a_head() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let policy_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready = policy_ready.clone();
        state.set_local_change_auth_provider(std::sync::Arc::new(move |_| {
            if ready.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(ChangeAuth { auth_seq: 7, auth_epoch: 2, policy_head_hash: [4; 32] })
            } else {
                Err(yadorilink_replica_domain::change::PolicyUnavailable)
            }
        }));
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live("missed.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(matches!(
            ensure_initial_import(&state, "g", &emitter()),
            Err(SyncError::PolicyUnavailable)
        ));

        policy_ready.store(true, std::sync::atomic::Ordering::SeqCst);
        let other = live("later.txt");
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &other,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let (op, version) = import_create_op(&state, "g", &other).unwrap();
        state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();
        assert_eq!(state.sqlite().dag_group_heads("g").unwrap().len(), 1);

        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::Backfilled { paths: 1 }
        );
        assert!(state
            .change_history_repository()
            .dag_group_history_paths("g")
            .unwrap()
            .contains("missed.txt"));
        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::NothingMissing
        );
    }

    #[test]
    fn second_run_does_not_duplicate_history() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live("a.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        assert_eq!(
            ensure_initial_import(&state, "g", &emitter()).unwrap(),
            ImportOutcome::Imported { changes: 1, ops: 1 }
        );
        let head_after_first = state.sqlite().dag_group_heads("g").unwrap();

        assert_eq!(
            ensure_initial_import(&state, "g", &emitter()).unwrap(),
            ImportOutcome::AlreadyInitialized
        );
        // No second root injected: the head set is byte-identical.
        assert_eq!(state.sqlite().dag_group_heads("g").unwrap(), head_after_first);
    }

    /// A pre-upgrade database can already hold an index row for a path
    /// that collides with the reserved artefact namespace — it was
    /// ordinary content before this module's exclusion existed. Initial
    /// import must skip that one row (never turn it into signed history)
    /// while still importing every ordinary row around it, matching
    /// admission's own artefact-only rejection: the blocked path is
    /// reported (via a log line this test doesn't assert on directly) but
    /// import does not error or stall for the rest of the index.
    #[test]
    fn ensure_initial_import_skips_a_pre_existing_reserved_namespace_collision() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
            "deadbeef",
        )
        .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live("a.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live(&artefact_path),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 1 });

        let heads = state.sqlite().dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1);
        let change = state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
        assert!(
            change
                .ops
                .iter()
                .all(|op| !matches!(op, Op::Put { path, .. } if path.as_str() == artefact_path)),
            "the colliding path must never appear in signed history: {:?}",
            change.ops
        );
        assert!(change
            .ops
            .iter()
            .any(|op| matches!(op, Op::Put { path, .. } if path.as_str() == "a.txt")));
    }

    /// A database predating the sync-root lock's exclusion could hold an
    /// indexed row for it (see the module-level rationale on
    /// `path_must_never_enter_history`) — pins that the one-shot initial
    /// import still skips it exactly as it does a versioned artefact.
    #[test]
    fn ensure_initial_import_skips_a_pre_existing_sync_root_lock_row() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let lock_path = yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME;
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live("a.txt"),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live(lock_path),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 1 });

        let heads = state.sqlite().dag_group_heads("g").unwrap();
        let change = state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
        assert!(
            change
                .ops
                .iter()
                .all(|op| !matches!(op, Op::Put { path, .. } if path.as_str() == lock_path)),
            "the sync-root lock path must never appear in signed history: {:?}",
            change.ops
        );
    }

    #[test]
    fn empty_index_imports_nothing() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        assert_eq!(
            ensure_initial_import(&state, "g", &emitter()).unwrap(),
            ImportOutcome::NothingToImport
        );
        assert!(state.sqlite().dag_group_heads("g").unwrap().is_empty());
    }

    #[test]
    fn large_index_splits_into_bounded_chain() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let count = IMPORT_BATCH_OP_LIMIT + 5;
        for i in 0..count {
            state
                .file_index_repository()
                .upsert_file(
                    "g",
                    &live(&format!("f{i:05}.txt")),
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        }
        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 2, ops: count });
        // A linear chain converges to a single head regardless of how many
        // changes it took to carry every op.
        assert_eq!(state.sqlite().dag_group_heads("g").unwrap().len(), 1);
    }

    /// Walks the linear parent chain from `head` back to the root, returning
    /// every change on it (head-first). Asserts each non-root step has exactly
    /// one parent, so a non-linear DAG fails loudly rather than silently
    /// truncating the walk.
    fn linear_chain_to_root(
        state: &ReplicaCoordinator,
        head: yadorilink_replica_domain::ids::ChangeHash,
    ) -> Vec<yadorilink_replica_domain::change::Change> {
        let mut chain = Vec::new();
        let mut cursor = Some(head);
        while let Some(hash) = cursor {
            let change = state.sqlite().dag_get_change(&hash).unwrap().unwrap();
            cursor = match change.parents.as_slice() {
                [] => None,
                [parent] => Some(*parent),
                more => {
                    panic!("expected a linear chain, found a change with {} parents", more.len())
                }
            };
            chain.push(change);
        }
        chain
    }

    /// Byte cap: an initial import of FEWER than `IMPORT_BATCH_OP_LIMIT` files
    /// whose ops encode to more than `change::MAX_CHANGE_OP_BYTES` (long paths)
    /// must still split into MULTIPLE chained changes — proving the split is
    /// driven by encoded size, not op count alone. Op count alone would leave a
    /// single multi-hundred-KiB root change no wire message could deliver,
    /// stranding the whole group's history permanently un-propagatable.
    #[test]
    fn import_splits_by_encoded_bytes_into_a_chain() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        // ~289 bytes/op * 1000 ops ≈ 282 KiB > 256 KiB, yet 1000 < 1024 ops,
        // so only the byte cap can split this — the op-count cap cannot.
        let n = 1000usize;
        assert!(n < IMPORT_BATCH_OP_LIMIT, "this test must stay under the op-count cap");
        for i in 0..n {
            state
                .file_index_repository()
                .upsert_file(
                    "g",
                    &live(&format!("d/{:0>250}", i)),
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        }

        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        let ImportOutcome::Imported { changes, ops } = outcome else {
            panic!("expected an import, got {outcome:?}");
        };
        assert_eq!(ops, n, "every file must be imported exactly once");
        assert!(
            changes >= 2,
            "a >256 KiB import of {n} (< op-count-cap) files must split by bytes \
             into >= 2 changes, got {changes}"
        );

        // The chunk chain converges on a single head and is linear to the root.
        let heads = state.sqlite().dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1, "the chunk chain must converge on a single head");
        let chain = linear_chain_to_root(&state, heads[0]);
        assert_eq!(chain.len(), changes, "walked chain length must equal the emitted change count");

        let mut total_ops = 0usize;
        for change in &chain {
            assert!(
                change.ops.len() <= IMPORT_BATCH_OP_LIMIT,
                "every chunk must stay within the op-count bound"
            );
            let bytes: usize = change.ops.iter().map(encoded_op_len).sum();
            assert!(
                bytes <= MAX_CHANGE_OP_BYTES,
                "every chunk must stay within the byte bound, got {bytes}"
            );
            total_ops += change.ops.len();
        }
        assert_eq!(total_ops, n, "the chain's ops must cover every file exactly once");
    }

    /// Teeth for the byte cap: a normal small import — well within both bounds
    /// — must still be a SINGLE change, so the dual-bound loop never
    /// over-splits an ordinary folder into a needless chain.
    #[test]
    fn small_import_is_a_single_change() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        for i in 0..8 {
            state
                .file_index_repository()
                .upsert_file(
                    "g",
                    &live(&format!("f{i}.txt")),
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        }
        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 8 });
        assert_eq!(state.sqlite().dag_group_heads("g").unwrap().len(), 1);
    }
}
