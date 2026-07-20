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
//! else. Live records become `Op::Create`, tombstoned records become
//! `Op::Delete`, and the content version hash of each create is built
//! exactly the way live emission builds it (block hashes + size + mtime +
//! exec bit + symlink target/kind) — so a file imported here and the same
//! file later re-emitted by a normal local edit hash to the same version.
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

use crate::change::{
    encoded_op_len, BlockHash, FileMeta, FileVersion, Op, SyncPath, VersionBlock,
    MAX_CHANGE_OP_BYTES,
};
use crate::dag_store::ChangeEmitter;
use crate::error::SyncError;
use crate::index::SyncState;
use crate::types::{FileRecord, RecordKind};

/// Upper bound on how many operations a single synthesized import change
/// carries. A very large existing index converts into a chain of changes, each
/// no bigger than this, so an individual change stays comfortably small for
/// storage while the chain as a whole still captures the entire index. Chosen
/// to keep changes small without producing an excessive number of them for a
/// typical folder. This op-count cap alone does NOT bound a change's encoded
/// size — long paths can make a 1024-op change several MiB — so the import
/// additionally caps each change by canonical encoded byte size
/// (`change::MAX_CHANGE_OP_BYTES`); the two bounds apply together.
pub const IMPORT_BATCH_OP_LIMIT: usize = 1024;

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
pub async fn backfill_missing_history(
    state: &SyncState,
    group_id: &str,
    emitter: &ChangeEmitter,
) -> Result<BackfillOutcome, SyncError> {
    let known = state.dag_group_history_paths(group_id)?;
    let candidates: Vec<String> = state
        .list_files(group_id)?
        .into_iter()
        .map(|r| r.path)
        .filter(|path| !known.contains(path))
        .collect();
    let mut appended = 0usize;
    for path in candidates {
        let path_lock = state.path_lock(group_id, &path);
        let _guard = path_lock.lock().await;
        if state.dag_group_history_paths(group_id)?.contains(&path) {
            continue;
        }
        let Some(record) = state.get_file(group_id, &path)? else { continue };
        let (op, versions) = if record.deleted {
            (Op::Delete { path: SyncPath(path.clone()) }, Vec::new())
        } else {
            let (op, version) = import_create_op(state, group_id, &record)?;
            (op, vec![version])
        };
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
pub fn ensure_initial_import(
    state: &SyncState,
    group_id: &str,
    emitter: &ChangeEmitter,
) -> Result<ImportOutcome, SyncError> {
    // Cheap pre-check outside any transaction: a group that already has a
    // head has history, so there is nothing to import and no reason to read
    // and convert its index. The authoritative check runs again inside the
    // write transaction in `SyncState::append_initial_import`, so this is
    // purely an optimization, not the correctness guard.
    if !state.dag_group_heads(group_id)?.is_empty() {
        return Ok(ImportOutcome::AlreadyInitialized);
    }

    // Sort by path so the synthesized chain is reproducible from the same
    // index rather than depending on row iteration order.
    let mut records = state.list_files(group_id)?;
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

/// Builds the `Op::Create` for a live record, deriving its content version
/// hash the same way local emission does so an imported file and a later
/// re-emission of the same file share a version. The symlink-target column
/// is populated only for symlink records, so its presence is exactly what
/// distinguishes a symlink from a regular file — matching how live emission
/// classifies the same record — and a symlink carries no exec bit, which the
/// column already reflects as `false`.
fn import_create_op(
    state: &SyncState,
    group_id: &str,
    record: &FileRecord,
) -> Result<(Op, FileVersion), SyncError> {
    let blocks = record
        .blocks
        .iter()
        .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
        .collect();
    let symlink_target = state.get_symlink_target(group_id, &record.path)?;
    let exec_bit = state.get_exec_bit(group_id, &record.path)?;
    // The index is authoritative for the record type. In particular a
    // directory has neither blocks nor a symlink target, just like an empty
    // regular file, so inferring kind from `symlink_target` collapses it to a
    // file during the one-time DAG import.
    let record_kind = state.get_record_kind(group_id, &record.path)?.unwrap_or(RecordKind::File);
    let meta = FileMeta {
        mtime_unix_nanos: record.mtime_unix_nanos,
        exec_bit,
        symlink_target,
        record_kind,
    };
    let version = FileVersion::new(blocks, record.size, meta);
    let op = Op::Create { path: SyncPath(record.path.clone()), version: version.version_hash };
    Ok((op, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::ChangeAuth;
    use crate::types::BlockInfo;
    use crate::version_vector::VersionVector;
    use ed25519_dalek::SigningKey;

    fn vv(dev: &str) -> VersionVector {
        let mut v = VersionVector::new();
        v.increment(dev);
        v
    }

    fn emitter() -> ChangeEmitter {
        ChangeEmitter::new("device-A", SigningKey::from_bytes(&[9u8; 32]))
    }

    fn live(path: &str) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 3,
            mtime_unix_nanos: 1,
            version: vv("device-A"),
            blocks: vec![BlockInfo { hash: vec![1, 2, 3], offset: 0, size: 3 }],
            deleted: false,
        }
    }

    fn tombstone(path: &str) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 0,
            mtime_unix_nanos: 5,
            version: vv("device-A"),
            blocks: vec![],
            deleted: true,
        }
    }

    #[test]
    fn converts_live_and_tombstoned_records_in_one_change() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("g", &live("a.txt")).unwrap();
        state.upsert_file("g", &tombstone("gone.txt")).unwrap();

        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 2 });

        // Exactly one root head, whose change carries a Create for the live
        // file and a Delete for the tombstone.
        let heads = state.dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1);
        let change = state.dag_get_change(&heads[0]).unwrap().unwrap();
        assert!(change.parents.is_empty());
        assert!(change
            .ops
            .iter()
            .any(|op| matches!(op, Op::Create { path, .. } if path.as_str() == "a.txt")));
        assert!(change
            .ops
            .iter()
            .any(|op| matches!(op, Op::Delete { path } if path.as_str() == "gone.txt")));
    }

    #[test]
    fn import_version_hash_matches_live_emission() {
        // The create op's version hash must equal what a normal local edit
        // would have emitted for the same record, so the two never diverge.
        let state = SyncState::open_in_memory().unwrap();
        let record = live("a.txt");
        state.upsert_file("g", &record).unwrap();

        let (op, _version) = import_create_op(&state, "g", &record).unwrap();
        let Op::Create { version, .. } = op else { panic!("expected a create op") };

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
        let state = SyncState::open_in_memory().unwrap();
        let mut record = live("folder");
        record.size = 0;
        record.blocks.clear();
        state.upsert_file("g", &record).unwrap();
        state.set_record_kind("g", "folder", RecordKind::Directory).unwrap();

        let (_, version) = import_create_op(&state, "g", &record).unwrap();
        assert_eq!(version.meta.record_kind, RecordKind::Directory);
    }

    #[tokio::test]
    async fn audit_repairs_policy_withheld_initial_import_after_another_path_creates_a_head() {
        let state = SyncState::open_in_memory().unwrap();
        let policy_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready = policy_ready.clone();
        state.set_local_change_auth_provider(std::sync::Arc::new(move |_| {
            if ready.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(ChangeAuth { auth_seq: 7, auth_epoch: 2, policy_head_hash: [4; 32] })
            } else {
                Err(crate::change::PolicyUnavailable)
            }
        }));
        state.upsert_file("g", &live("missed.txt")).unwrap();
        assert!(matches!(
            ensure_initial_import(&state, "g", &emitter()),
            Err(SyncError::PolicyUnavailable)
        ));

        policy_ready.store(true, std::sync::atomic::Ordering::SeqCst);
        let other = live("later.txt");
        state.upsert_file("g", &other).unwrap();
        let (op, version) = import_create_op(&state, "g", &other).unwrap();
        state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();
        assert_eq!(state.dag_group_heads("g").unwrap().len(), 1);

        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::Backfilled { paths: 1 }
        );
        assert!(state.dag_group_history_paths("g").unwrap().contains("missed.txt"));
        assert_eq!(
            backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
            BackfillOutcome::NothingMissing
        );
    }

    #[test]
    fn second_run_does_not_duplicate_history() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("g", &live("a.txt")).unwrap();

        assert_eq!(
            ensure_initial_import(&state, "g", &emitter()).unwrap(),
            ImportOutcome::Imported { changes: 1, ops: 1 }
        );
        let head_after_first = state.dag_group_heads("g").unwrap();

        assert_eq!(
            ensure_initial_import(&state, "g", &emitter()).unwrap(),
            ImportOutcome::AlreadyInitialized
        );
        // No second root injected: the head set is byte-identical.
        assert_eq!(state.dag_group_heads("g").unwrap(), head_after_first);
    }

    #[test]
    fn empty_index_imports_nothing() {
        let state = SyncState::open_in_memory().unwrap();
        assert_eq!(
            ensure_initial_import(&state, "g", &emitter()).unwrap(),
            ImportOutcome::NothingToImport
        );
        assert!(state.dag_group_heads("g").unwrap().is_empty());
    }

    #[test]
    fn large_index_splits_into_bounded_chain() {
        let state = SyncState::open_in_memory().unwrap();
        let count = IMPORT_BATCH_OP_LIMIT + 5;
        for i in 0..count {
            state.upsert_file("g", &live(&format!("f{i:05}.txt"))).unwrap();
        }
        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 2, ops: count });
        // A linear chain converges to a single head regardless of how many
        // changes it took to carry every op.
        assert_eq!(state.dag_group_heads("g").unwrap().len(), 1);
    }

    /// Walks the linear parent chain from `head` back to the root, returning
    /// every change on it (head-first). Asserts each non-root step has exactly
    /// one parent, so a non-linear DAG fails loudly rather than silently
    /// truncating the walk.
    fn linear_chain_to_root(
        state: &SyncState,
        head: crate::change::ChangeHash,
    ) -> Vec<crate::change::Change> {
        let mut chain = Vec::new();
        let mut cursor = Some(head);
        while let Some(hash) = cursor {
            let change = state.dag_get_change(&hash).unwrap().unwrap();
            cursor = match change.parents.as_slice() {
                [] => None,
                [parent] => Some(parent.clone()),
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
        let state = SyncState::open_in_memory().unwrap();
        // ~289 bytes/op * 1000 ops ≈ 282 KiB > 256 KiB, yet 1000 < 1024 ops,
        // so only the byte cap can split this — the op-count cap cannot.
        let n = 1000usize;
        assert!(n < IMPORT_BATCH_OP_LIMIT, "this test must stay under the op-count cap");
        for i in 0..n {
            state.upsert_file("g", &live(&format!("d/{:0>250}", i))).unwrap();
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
        let heads = state.dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1, "the chunk chain must converge on a single head");
        let chain = linear_chain_to_root(&state, heads[0].clone());
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
        let state = SyncState::open_in_memory().unwrap();
        for i in 0..8 {
            state.upsert_file("g", &live(&format!("f{i}.txt"))).unwrap();
        }
        let outcome = ensure_initial_import(&state, "g", &emitter()).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 8 });
        assert_eq!(state.dag_group_heads("g").unwrap().len(), 1);
    }
}
