//! First-run conversion of an existing file index into signed change
//! history. The change-history DAG is created empty by the schema
//! migration, so an installation that predates it keeps a fully
//! materialized file index with no history behind it. On the first run
//! after the DAG is provisioned (the device now has a signing key, hence a
//! [`ChangeEmitter`]), each linked group's current index is converted —
//! once — into a chain of signed "initial-import" changes, so history
//! begins at the observed present without fabricating a past that was
//! never recorded. Every import change is authored and signed by the
//! *local* device. It is an assertion of what this device currently holds,
//! not a reconstruction of which device originally wrote each file: a
//! change verifies against the signing key named by its own `device_id`,
//! so a change can only ever be signed by the device it is attributed to,
//! and attributing an imported file to some other origin device would make
//! it unverifiable everywhere else. Live records become `Op::Put { origin:
//! PutOrigin::Direct, .. }`, tombstoned records become `Op::Delete`, and
//! the content version hash of each put is built exactly the way live
//! emission builds it (block hashes + size + mtime + exec bit + symlink
//! target/kind) — so a file imported here and the same file later
//! re-emitted by a normal local edit hash to the same version. Idempotency
//! and crash-safety: the whole import for a group commits in one
//! transaction, and it runs only when the group's head set is still empty
//! (re-checked inside that transaction). A crash mid-import rolls the
//! transaction back, leaving the group un-imported so the next run redoes
//! it; a second start — or a concurrent one — observes the committed
//! history and does nothing. History is therefore never duplicated. Call
//! ordering (the daemon's responsibility): [`ensure_initial_import`] must
//! complete for a group before that group's [`ChangeEmitter`] is wired
//! into local emission and before any change-DAG peer session for the
//! group runs, so import always establishes the root of history ahead of
//! the first live mutation or admitted peer change. Authorization: this
//! module signs and commits every change it writes, so it is bound by the
//! same local-authoring rule as a live watcher edit -- this device must
//! itself currently be a writer (Editor/Owner) under the group's current
//! signed policy chain, or the import must be withheld rather than
//! stamped. This module does not check that itself; both
//! [`ReplicaCoordinator::append_initial_import`] and
//! [`ReplicaCoordinator::append_history_backfill`] are required to route
//! through the SAME gate a normal local edit uses (`ReplicaCoordinator::
//! local_emission_auth`, which consults the daemon's `local_change_auth_
//! provider`) before committing anything, exactly the way `Replica
//! Coordinator`'s own implementation does. A device that is not currently
//! a writer -- including the whole pre-policy Bootstrap window, where any
//! device may stamp a PLACEHOLDER-authorized change, same as live emission
//! -- must have its import/backfill withheld (an `Err` from this module's
//! functions), not silently skipped as a no-op and not committed anyway:
//! otherwise a Viewer's first-run disk scan (or a later coverage-audit
//! sweep) would commit content to this device's own signed history that no
//! peer will ever accept, permanently diverging this device's local state
//! from the rest of the group for no benefit. See `daemon_state.rs`'s
//! `initial_import_and_backfill_withhold_a_viewers_pre_existing_content_
//! but_allow_an_editor` for the regression proof. `IMPORT_BATCH_OP_LIMIT`
//! itself did not move here: `yadorilink-local- capture`'s own
//! `RECONCILE_CHUNK_OP_LIMIT` (a real, non-test production constant) needs
//! it and sits below `yadorilink-daemon` in the dependency graph, so it
//! now lives at
//! `yadorilink_replica_domain::change::IMPORT_BATCH_OP_LIMIT`, shared by
//! both callers.

use std::path::Path;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::change::{
    encoded_op_len, Op, PutOrigin, IMPORT_BATCH_OP_LIMIT, MAX_CHANGE_OP_BYTES,
};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_root_authority::fs_identity::metadata_mtime_matches;
use yadorilink_root_authority::reserved_namespace::path_has_reserved_component;
use yadorilink_root_authority::sync_root_lock::is_sync_root_lock_relative_path;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::CanonicalCurrentRow;

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
pub async fn backfill_missing_history(
    state: &crate::replica_coordinator::ReplicaCoordinator,
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
        let path_lock = state.path_lock_registry().path_lock(group_id, &path);
        let _guard = path_lock.lock().await;
        if state.change_history_repository().dag_group_history_paths(group_id)?.contains(&path) {
            continue;
        }
        // ONE read, under the path lock this loop already holds: the
        // change appended below names a version, and the version has to
        // be the one the row actually is.
        let Some(row) = state.file_index_repository().canonical_current_row(group_id, &path)?
        else {
            continue;
        };
        let deleted = row.snapshot.deleted;
        let (op, versions) = if deleted {
            (Op::Delete { path: SyncPath(path.clone()) }, Vec::new())
        } else {
            let (op, version, _record_kind) = import_create_op(&path, &row);
            (op, vec![version])
        };
        tracing::info!(
            group_id,
            path = %path,
            deleted,
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

/// How many times [`ensure_initial_import`] will rebuild its snapshot and
/// retry after `append_initial_import` reports [`yadorilink_sync_sqlite::
/// ImportAppendOutcome::StaleSnapshot`]. The window a retry is closing --
/// another writer touching this group's index between this function's
/// snapshot read and its transaction's commit -- is normally microseconds
/// wide; this bound exists so a group under truly pathological, unending
/// concurrent write pressure fails loudly instead of retrying forever.
const MAX_SNAPSHOT_RETRIES: u32 = 5;

/// Converts `group_id`'s current index into initial-import changes.
///
/// Idempotent and crash-safe: each attempt's append is transactional, and
/// re-derives which rows still need binding from a FRESH read of the
/// database taken inside that same transaction -- never trusting a value
/// computed outside it. Safe to call on every daemon start for every linked
/// group, and safe to call again later for the same group: unlike the
/// group's-history-was-still-empty framing this function used to be gated
/// on, "does this group still have any current row lacking a verified
/// authoring identity" stays a well-defined, idempotent question regardless
/// of whether the group already has SOME history (from an earlier partial
/// import, `backfill_missing_history` claiming a path first, or live
/// emission) -- treating "any history at all" as "fully imported" was
/// exactly the race that would leave rows permanently unbound at real
/// scale.
pub fn ensure_initial_import(
    state: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
    emitter: &ChangeEmitter,
    root: Option<&Path>,
) -> Result<ImportOutcome, SyncError> {
    for _attempt in 0..MAX_SNAPSHOT_RETRIES {
        // Cheap pre-check outside any transaction: nothing to do if every
        // current row for this group already carries a verified authoring
        // identity. The authoritative check re-runs inside the write
        // transaction in `append_initial_import`, so this is purely an
        // optimization, not the correctness guard. Deliberately NOT "does
        // this group have a head at all" -- a group can hold some history
        // (one path `backfill_missing_history` already claimed, say) while
        // still holding other current rows this import must still bind.
        let unbound = state.file_index_repository().list_unauthored_current_paths(group_id)?;
        if unbound.is_empty() {
            return Ok(if state.sqlite().dag_group_heads(group_id)?.is_empty() {
                ImportOutcome::NothingToImport
            } else {
                ImportOutcome::AlreadyInitialized
            });
        }

        // Sort by path so the synthesized chain is reproducible from the same
        // index rather than depending on row iteration order.
        let mut records = state.file_index_repository().list_files(group_id)?;
        records.retain(|r| unbound.contains(&r.path));
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
        let blocked: std::collections::HashSet<String> = records
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
            // Every currently-unbound row was blocked above (the reserved-
            // namespace-collision case) -- nothing importable remains, even
            // though the schema-level unbound count may still be nonzero.
            // Pre-existing behavior, not something this fix changes: those
            // rows were never bindable before this function existed either.
            return Ok(ImportOutcome::NothingToImport);
        }

        let mut ops = Vec::with_capacity(records.len());
        let mut versions: Vec<FileVersion> = Vec::new();
        // Built as each record's op is, rather than recovered afterwards by
        // searching. Re-deriving which version and record kind belong to a
        // path by scanning the op and version lists is quadratic per record
        // and cubic over the import -- invisible at a hundred files, and the
        // dominant cost at ten thousand -- for an association that is known
        // for free at the moment the op is assembled.
        let mut prepared: std::collections::HashMap<String, PreparedImport> =
            std::collections::HashMap::new();
        for record in &records {
            if record.deleted {
                ops.push(Op::Delete { path: SyncPath(record.path.clone()) });
                continue;
            }
            // Re-read as ONE row rather than composing the version out of
            // `record` plus four point queries -- see `import_create_op`.
            // That is four reads per path fewer, not one more: the batch
            // listing above still decides WHICH paths are imported, and
            // this decides what each one's change says it is.
            let Some(row) =
                state.file_index_repository().canonical_current_row(group_id, &record.path)?
            else {
                continue;
            };
            if row.snapshot.deleted {
                ops.push(Op::Delete { path: SyncPath(record.path.clone()) });
                continue;
            }
            let (op, version, record_kind) = import_create_op(&record.path, &row);
            prepared.insert(
                record.path.clone(),
                PreparedImport {
                    version_hash: version.version_hash,
                    record_kind,
                    // The row the version was minted from, carried so the
                    // disk verification below checks the same incarnation.
                    record: FileRecord {
                        path: record.path.clone(),
                        size: row.snapshot.size,
                        mtime_unix_nanos: row.snapshot.mtime_unix_nanos,
                        blocks: row.snapshot.blocks.clone(),
                        deleted: false,
                    },
                },
            );
            ops.push(op);
            versions.push(version);
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

        // Observed here, immediately before the commit, for exactly the
        // paths this attempt is about to bind. A file already sitting in
        // the folder when it was linked is already materialized -- that is
        // what importing it means -- and recording that fact is what lets
        // this device settle its own obligations without asking a peer
        // about content it wrote itself. Anything unreadable is simply
        // left out: no proof is the status quo, a wrong proof is not.
        let mut actual_state = std::collections::HashMap::new();
        if let Some(root) = root {
            for record in &records {
                if record.deleted {
                    continue;
                }
                let absolute = root.join(&record.path);
                // The version about to go into history came from the index,
                // written when the folder was scanned. The identity below
                // is observed now. Those are two looks at the same path at
                // two different times, and nothing about the second one
                // says the bytes still match the first.
                //
                // That gap is the whole danger. An in-place overwrite keeps
                // the inode, so both halves still look individually sound --
                // a real version, and a real identity of a real object at
                // that path, which identity revalidation can even confirm.
                // The proof would then assert the path already holds the
                // old content and close the obligation to actually put it
                // there, leaving the wrong bytes on disk with nothing left
                // that would notice.
                //
                // So the proof is only adopted for a file that still looks
                // like the record being imported, and only if nothing
                // touches it across the observation itself. A mismatch
                // means no proof, never a wrong one, and never a refusal to
                // import: the path still enters history, it simply is not
                // vouched for as already materialized.
                // The row the version was minted from, NOT the batch
                // listing's `record`. They can differ: the listing chose
                // which paths to import, and a concurrent write can move a
                // row between that listing and the per-path canonical read
                // that decided what the change says. Verifying disk against
                // the listing while the proof names the canonical row's
                // version would vouch for the newer version on the strength
                // of the older bytes -- the proof would say the new content
                // is already materialized, and nothing would ever put it
                // there.
                let Some(prepared) = prepared.get(&record.path) else {
                    continue;
                };
                let record = &prepared.record;
                let Ok(before) = std::fs::symlink_metadata(&absolute) else {
                    continue;
                };
                // Cheap rejections first, so an ordinary import does not
                // read a file it can already tell has changed.
                if before.len() != record.size
                    || !metadata_mtime_matches(&before, record.mtime_unix_nanos)
                {
                    continue;
                }
                let fingerprint_before =
                    yadorilink_root_authority::fs_identity::disk_race_fingerprint(&absolute);
                if fingerprint_before.is_none() {
                    continue;
                }
                // Then the part that actually binds the two halves
                // together. Size and mtime are not evidence of content: an
                // in-place overwrite can keep the length and have its mtime
                // put back, and nothing about the file's metadata then says
                // it was touched. Bracketing the identity observation does
                // not help either -- it proves nothing changed *during* the
                // observation, which is true, because the change already
                // happened before it began.
                //
                // Reading the bytes and comparing them to the blocks the
                // index recorded is what establishes that the version about
                // to enter history and the identity about to vouch for it
                // describe the same content. Without it the proof is two
                // observations of one path at two different times with
                // nothing connecting them.
                //
                // This re-read is real cost, paid once per imported file.
                // It is here because correctness needs it now; the way to
                // stop paying it is to capture content, identity and
                // version in one pass at scan time rather than rediscover
                // them at import time.
                match yadorilink_local_storage::disk_verification::disk_bytes_match_indexed_blocks(
                    &absolute,
                    &record.blocks,
                ) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => continue,
                }
                let Some(observed) =
                    yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&absolute)
                        .ok()
                else {
                    continue;
                };
                // Closes the window around the read and the observation
                // together, the way local capture brackets its own.
                if yadorilink_root_authority::fs_identity::disk_race_fingerprint(&absolute)
                    != fingerprint_before
                {
                    continue;
                }
                actual_state.insert(
                    record.path.clone(),
                    yadorilink_sync_sqlite::file_index::ImportedActualState {
                        filesystem_identity: observed,
                        record_kind: prepared.record_kind,
                        version_hash: prepared.version_hash,
                    },
                );
            }
        }

        match state.append_initial_import(
            group_id,
            &batches,
            &versions,
            emitter,
            &blocked,
            &actual_state,
        )? {
            yadorilink_sync_sqlite::ImportAppendOutcome::Committed(changes) => {
                return Ok(ImportOutcome::Imported { changes, ops: total_ops });
            }
            // Every unbound row this attempt targeted got covered by
            // someone else between this attempt's pre-check and its
            // transaction's commit (another concurrent attempt, backfill,
            // live emission) -- its own commit correctly did nothing.
            yadorilink_sync_sqlite::ImportAppendOutcome::FullyCovered => {
                return Ok(ImportOutcome::AlreadyInitialized);
            }
            // A concurrent write changed the group's unbound-row set after
            // this attempt's snapshot was taken. Nothing was committed;
            // rebuild the snapshot and retry rather than let a stale
            // attempt commit an incomplete import.
            yadorilink_sync_sqlite::ImportAppendOutcome::StaleSnapshot => {}
        }
    }
    Err(SyncError::CorruptState(format!(
        "initial import for group {group_id} did not converge after {MAX_SNAPSHOT_RETRIES} \
         attempts -- the group's unbound-row set kept changing faster than an attempt could \
         commit"
    )))
}

/// Builds the direct `Op::Put` for a live record, deriving its content version
/// hash the same way local emission does so an imported file and a later
/// re-emission of the same file share a version. The symlink-target column
/// is populated only for symlink records, so its presence is exactly what
/// distinguishes a symlink from a regular file — matching how live emission
/// classifies the same record — and a symlink carries no exec bit, which the
/// column already reflects as `false`.
///
/// The `Op::Put` and `FileVersion` for one indexed path, built entirely
/// from `row` -- ONE incarnation of that path's current row.
///
/// Pure, and taking the row rather than fetching from it, because the
/// version it mints is what the emitted change *claims* the path is. It
/// used to take a `FileRecord` from the caller's own earlier read and
/// then issue four more: `get_symlink_target`, `get_unix_mode`,
/// `get_xattrs` and `get_record_kind`. Five reads, no isolation across
/// them -- so the blocks, size and mtime could come from one incarnation
/// and the mode, target, xattrs and kind from later ones, and the change
/// signed over the result named a version the index had never held.
/// One path's import decision: the version its change will name, the kind
/// that version is, and the row both were taken from.
///
/// The record travels with them because the disk verification has to
/// check the same incarnation the version was minted from. Keeping only
/// the hash and re-using the batch listing's record is how a proof ends
/// up vouching for one version on the strength of another's bytes.
struct PreparedImport {
    version_hash: yadorilink_replica_domain::ids::VersionHash,
    record_kind: RecordKind,
    record: FileRecord,
}

fn import_create_op(path: &str, row: &CanonicalCurrentRow) -> (Op, FileVersion, RecordKind) {
    // The index is authoritative for the record type. In particular a
    // directory has neither blocks nor a symlink target, just like an empty
    // regular file, so inferring kind from `symlink_target` collapses it to a
    // file during the one-time DAG import.
    let record_kind = row.snapshot.record_kind;
    // Minted through the one row-to-version reconstruction, so a directory
    // row's observed size and mtime never reach its identity.
    let version = FileVersion::from_index_row(
        row.snapshot.blocks.clone(),
        row.snapshot.size,
        row.snapshot.mtime_unix_nanos,
        record_kind,
        row.snapshot.unix_mode,
        row.snapshot.symlink_target.clone(),
        row.snapshot.xattrs.clone(),
    );
    let op = Op::Put {
        path: SyncPath(path.to_string()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    };
    (op, version, record_kind)
}

#[cfg(test)]
mod tests;
