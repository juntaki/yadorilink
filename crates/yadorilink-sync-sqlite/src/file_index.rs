//! `FileIndexRepository` owns the plain file-record CRUD subset of the
//! `files` table -- upserts, tombstones, version listing, and per-file
//! metadata columns (record kind, symlink target, exec bit, pinning,
//! last-accessed, block provenance queries that read `files` directly).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};

use crate::dag_store::{self, ChangeEmitter};
use crate::error::SyncSqliteError;
use crate::materialized_generation::MaterializedObjectKind;
use yadorilink_replica_domain::change::{encoded_op_len, Change, Op, MAX_CHANGE_OP_BYTES};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, SyncPath};
use yadorilink_replica_domain::recursive_operation::{
    EffectSetHash, RecursiveOperation, RecursiveOperationId, RecursiveOperationKind,
    RecursiveOperationRef, MAX_RECURSIVE_OPERATION_PARTS,
};
/// Re-exported from its home next to the types it hashes. It used to live
/// here, but the digest is now also computed by the peer-facing summary path
/// and by this crate's test doubles, and two definitions of one digest
/// eventually disagree about what they cover.
pub use yadorilink_replica_domain::session_state::durability_roots_digest;
use yadorilink_replica_domain::session_state::{
    ChangeContent, ConflictCopyFile, DurabilityRoot, DurabilityRoots, LocalFileMetaColumns,
    MaterializationState, PreparedLocalMutation, RootSetSummary, TrashedFile, VersionRecord,
    VersionState,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Capabilities and authorization shared by every local change emission.
/// Keeping them together prevents repository callers from accidentally
/// pairing an emitter with a permit or authorization stamp from another
/// operation while keeping mutation-specific data explicit.
#[derive(Clone, Copy)]
pub struct ChangeEmissionContext<'a> {
    pub emitter: &'a ChangeEmitter,
    pub permit: &'a RootCommitPermit<'a>,
}

/// Current wall-clock time in nanoseconds since the Unix epoch, or `None`
/// when this device's clock reads before the epoch.
///
/// The `None` case exists because the `admitted_at_unix_nanos` stamp cannot
/// tolerate the usual `unwrap_or(0)` fallback the sibling helpers below use.
/// A `0` there is not a harmlessly-wrong number: it reads as "admitted at
/// the epoch", which makes the row look present at every possible rewind
/// target and turns an unreadable clock into a confident wrong answer about
/// what a folder held at some past instant. NULL is the honest encoding of
/// "this device does not know when it admitted this row", and the planning
/// layer already has an explicit outcome for it -- see the column's own
/// migration comment in `yadorilink-sqlite-runtime`'s schema, which spells
/// out why neither `0` nor "now" is an acceptable substitute.
pub(crate) fn now_unix_nanos_checked() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i64)
}

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Same shape as this crate's
/// other `dag_store`/`materialization_job_repository`/`retention_roots`
/// copies. Not for `admitted_at_unix_nanos`: use
/// [`now_unix_nanos_checked`] there, for the reason given on it.
fn now_unix_nanos() -> i64 {
    now_unix_nanos_checked().unwrap_or(0)
}

pub struct FileIndexRepository {
    database: Arc<SyncDatabase>,
}

impl FileIndexRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Plain, origin-agnostic upsert — delegates to
    /// `upsert_file_with_origin` with an empty (unknown) origin. Kept for
    /// every existing caller (overwhelmingly test fixtures that don't care
    /// who "wrote" a record) so this signature never needed to change; see
    /// `upsert_file_with_origin`'s doc comment for the real semantics and
    /// which two production call sites use it directly instead.
    pub fn upsert_file(
        &self,
        group_id: &str,
        record: &FileRecord,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.upsert_file_with_origin(group_id, record, "", permit)
    }

    /// The version-retaining write path — see the free function `upsert_file_in_tx` (this
    /// method's entire implementation) for the exact supersede/trash/
    /// promote-scaffold logic. `origin_device_id` is the local device id
    /// for a local edit, or the sending peer's device id when adopting a
    /// remote version; an empty string means "unknown" (`upsert_file`'s
    /// default), recorded as SQL `NULL` rather than the literal empty
    /// string.
    pub fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, None)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Projected-row upsert that attaches the verified authoring change in
    /// the same SQLite transaction as the current-row mutation.
    pub fn upsert_file_with_origin_and_author(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: &ChangeHash,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(authoring_change_hash))?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Upserts many records for one group inside a single SQLite
    /// transaction (batch processing) — used by
    /// `LocalChangeProcessor::scan_existing_files` so a large initial scan
    /// commits once instead of once per file. Semantically identical to
    /// calling `upsert_file_with_origin` for each record in order (same
    /// `origin_device_id` for the whole batch — a scan is always this
    /// device's own local device id); a no-op (no transaction opened) for
    /// an empty batch.
    ///
    /// `metas` is each record's local metadata (record kind, symlink
    /// target/out-of-root, unix mode, xattrs), aligned 1:1 with `records`,
    /// or empty to leave those columns as `upsert_file_in_tx` left them.
    /// It is written in the SAME transaction as the row it belongs to, for
    /// the same reason `upsert_files_batch_emitting_change` does it: a row
    /// and the metadata the scan observed for it must become durable
    /// together or not at all.
    ///
    /// The scan that calls this used to stamp those columns afterwards,
    /// one `UPDATE` per path. The rows were durable before the first of
    /// those ran, and they already satisfy every "the scan finished"
    /// readiness check a caller has, so a restart in the middle came back
    /// to an index that looked complete and was not: most rows carried no
    /// mode. The next boot's scan then compared the real on-disk mode
    /// against that missing value, concluded the path had changed offline,
    /// and authored a metadata-only version for content nobody had
    /// touched — one per affected path, on every such restart.
    ///
    /// `observed` is aligned the same way: index `i`'s `Some` value is
    /// what the scan saw on disk for `records[i]` -- the exact version it
    /// derived for those bytes, the object's kind, and the identity it
    /// observed -- and is what lets this transaction publish the path's
    /// actual-state proof. It carries the version rather than leaving it
    /// to be recomputed here because the scan already has it: it built
    /// the record from the same read.
    pub fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        metas: &[Option<LocalFileMetaColumns>],
        observed: &[Option<ImportedActualState>],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        if records.is_empty() {
            return Ok(());
        }
        if !metas.is_empty() && metas.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} metas for {} records (metas must be empty or aligned 1:1 with records)",
                metas.len(),
                records.len()
            )));
        }
        if !observed.is_empty() && observed.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} observations for {} records \
                 (observations must be empty or aligned 1:1 with records)",
                observed.len(),
                records.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for (idx, record) in records.iter().enumerate() {
                upsert_file_in_tx(tx, group_id, record, origin_device_id, None)?;
                // After the row exists: these columns are an `UPDATE`
                // against the just-written `current` row.
                if let Some(Some(meta)) = metas.get(idx) {
                    apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
                }
                // Hydrated is published only together with the proof that
                // earns it, in this one transaction -- and where there is
                // no proof to publish, the row is left saying so, rather
                // than inheriting the superseded version's claim. Both
                // arms are mandatory: an unproven upsert that wrote
                // nothing here would leave `Hydrated` carried forward over
                // content this scan never verified.
                //
                // Kind comes from the observation, not from `metas`: the
                // desired state this proof has to match is derived from
                // the version's own metadata, so taking the kind from the
                // index column instead would be a second source of truth
                // for one of the two fields the proof is hashed over.
                match (record.deleted, observed.get(idx)) {
                    (false, Some(Some(observation))) => {
                        adopt_local_capture_actual_state(
                            tx,
                            group_id,
                            &record.path,
                            observation.record_kind,
                            &observation.version_hash,
                            &observation.filesystem_identity,
                        )?;
                        stamp_hydrated_after_local_emission_in_tx(tx, group_id, &record.path)?;
                    }
                    _ => retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?,
                }
            }
            permit.verify()?;
            Ok(())
        })
    }

    /// Upserts one record and appends the signed change describing it, in one
    /// transaction. Returns the appended change's hash. `versions` are the
    /// content-addressed file versions the change's ops reference (empty for a
    /// pure delete); each is persisted in the same transaction, so a change and
    /// the version bytes needed to materialize it on any receiver can never
    /// diverge across a crash. `meta`, when `Some`, is the record's local
    /// metadata (record kind, symlink target/out-of-root, exec bit), written
    /// in the SAME transaction so the index row's metadata columns can never
    /// lag the `FileVersion`/DAG change across a crash between the commit and a
    /// separate post-commit setter; pass `None` to leave those columns as
    /// `upsert_file_in_tx` left them.
    /// `permit` is re-verified inside the write transaction, immediately
    /// before commit -- not merely required to be present. See
    /// `root_commit::RootCommitPermit`'s own doc for why this is a
    /// required parameter rather than a caller-side convention.
    ///
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// resolved by `SyncState::upsert_file_emitting_change`'s own one-line
    /// call to `local_emission_auth` before this method is reached, since
    /// `local_change_auth_provider` lives on `SyncState`, not here: this
    /// repository owns file-record persistence, not authorization.
    ///
    /// `filesystem_identity`: `Some` only when the caller has a strong
    /// `FileIdentity` freshly observed from the real path AND `meta` is
    /// also `Some` (needed to know the object's kind) -- see
    /// `materialized_generation::adopt_observed_actual_generation_in_tx`'s
    /// own doc comment for the full precondition list a caller must have
    /// already satisfied before passing `Some` here (disk fingerprint,
    /// index state, and authoring identity all revalidated as unchanged
    /// immediately before this call). When both are `Some`, this commits
    /// an exact actual-state proof for the just-authored content IN THIS
    /// SAME transaction, so the Convergence Engine's zero-work pre-check
    /// can recognize this device's own locally-authored content as already
    /// correct without a redundant `materialize_dag_content_head` round
    /// trip. `None` (either one) commits the Change/index exactly as
    /// before, publishing no proof -- the Convergence Engine's existing
    /// fail-closed ordinary reconcile path handles it exactly as it always
    /// has; this is never required for correctness, only an optimization.
    // ~40 call sites workspace-wide (via this port's implementors);
    // grouping these into a params struct is out of scope for a lint
    // cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        filesystem_identity: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
        emission: ChangeEmissionContext<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::snapshot_install_hold::refuse_local_authoring_if_held(
                tx,
                group_id,
                &record.path,
            )?;
            // Committed without a batch, this is often a file captured
            // directly from disk because a peer's change for the same path
            // is about to be applied -- a change already in the frontier and
            // not yet shown here, which the plain frontier would claim.
            let change = emit_local_write_onto_frontier(
                tx,
                group_id,
                &record.path,
                content.ops.clone(),
                emission.emitter,
            )?;
            for version in content.versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            let change_hash = change.compute_hash();
            // This change was read off this device's own disk, whether or
            // not the read could also be proven below.
            crate::local_capture_provenance::record_local_capture_in_tx(
                tx,
                group_id,
                &record.path,
                &change_hash,
            )?;
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(&change_hash))?;
            if let Some(meta) = meta {
                apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
            }
            // The version comes from THIS path's own `Put`, not from
            // `versions.first()`. The two coincide for a single-op
            // change, which is the only shape this function is called
            // with today -- but "the first version this change happened to
            // carry" is not the same statement as "the version this path
            // was just put at", and the proof has to record the second
            // one. A change whose ops and versions do not line up is a
            // caller that built them inconsistently, and gets no proof and
            // no `Hydrated` rather than a proof naming some other path's
            // content.
            // A write-through's `Put` is at the entry the row is a copy
            // of; its version is still the one this row now holds.
            let put_path = write_through_source_of(&record.path, &content.ops)?
                .unwrap_or_else(|| record.path.clone());
            let provable = match (meta, filesystem_identity) {
                (Some(meta), Some(identity)) if !record.deleted => content
                    .ops
                    .iter()
                    .find_map(|op| match op {
                        Op::Put { path, version, .. } if path.as_str() == put_path => Some(version),
                        _ => None,
                    })
                    .filter(|version| content.versions.iter().any(|v| v.version_hash == **version))
                    .map(|version| (meta, identity, version)),
                _ => None,
            };
            match provable {
                Some((meta, identity, version)) => {
                    adopt_local_capture_actual_state(
                        tx,
                        group_id,
                        &record.path,
                        meta.record_kind,
                        version,
                        identity,
                    )?;
                    // In the same transaction as the proof, never ahead of
                    // it.
                    stamp_hydrated_after_local_emission_in_tx(tx, group_id, &record.path)?;
                    settle_obligation_against_local_presence_in_tx(tx, group_id, &record.path)?;
                }
                // Nothing here could be proven, so nothing here may keep
                // claiming to have been: the row just superseded may have
                // been `Hydrated` under a proof that named its version,
                // and both would otherwise survive this new one.
                None => retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?,
            }
            // Re-verified here, immediately before commit, not merely at
            // this call's entry -- root ownership/lifecycle can change
            // during the work above (chunking/hashing already happened
            // in the caller before this call, but `emit_local_change`'s
            // own DB work takes real time too).
            emission.permit.verify()?;
            Ok(change_hash)
        })
    }

    /// Upserts a batch of records under a single change (one change carrying
    /// every op), in one transaction — the shape used by an initial folder
    /// scan. Returns the appended change's hash, or `None` for an empty batch.
    ///
    /// `metas`, when non-empty, is aligned 1:1 with `records`: index `i`'s
    /// `Some` value is that record's local metadata (record kind, symlink
    /// target/out-of-root, exec bit), written in the SAME transaction so the
    /// index row's metadata columns can never lag the `FileVersion`/DAG change
    /// across a crash between the commit and a separate post-commit setter. A
    /// `None` element (e.g. a tombstone) leaves that row's columns as
    /// `upsert_file_in_tx` left them; passing an empty `metas` leaves every
    /// row's columns untouched.
    ///
    /// Callers with a large detected batch MUST split it into op-count- and
    /// encoded-byte-bounded chunks and call this once per chunk: each call
    /// commits its own change whose parents are the previous chunk's committed
    /// head (see `dag_store::emit_local_change`), so the chunks form a linear
    /// chain no single wire message / decode bound can reject.
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see [`Self::upsert_file_emitting_change`]'s doc comment for why it is
    /// a parameter here rather than resolved internally.
    // The batch counterpart of `upsert_file_emitting_change`, which carries
    // the same allow; a params struct is out of scope for a lint cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_files_batch_emitting_change(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        content: ChangeContent<'_>,
        metas: &[Option<LocalFileMetaColumns>],
        actual_state: &std::collections::HashMap<
            String,
            crate::file_index::LocalCaptureActualStateEvidence,
        >,
        emission: ChangeEmissionContext<'_>,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        if records.is_empty() {
            return Ok(None);
        }
        // A length mismatch here would commit index rows whose emitted change
        // carries a different set of ops, or whose metadata columns land on the
        // wrong row — silent divergence, exactly what this dual-write exists to
        // prevent. It can only arise from a caller bug (the one production
        // caller slices `records`/`ops`/`metas` in lockstep), so fail fast here,
        // before the transaction opens, rather than let it reach the write.
        if content.ops.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} ops for {} records (one op per record is required)",
                content.ops.len(),
                records.len()
            )));
        }
        if !metas.is_empty() && metas.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} metas for {} records (metas must be empty or aligned 1:1 with records)",
                metas.len(),
                records.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for record in records {
                crate::snapshot_install_hold::refuse_local_authoring_if_held(
                    tx,
                    group_id,
                    &record.path,
                )?;
            }
            let change =
                dag_store::emit_local_change(tx, group_id, content.ops.clone(), emission.emitter)?;
            let change_hash = change.compute_hash();
            for version in content.versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            for (idx, record) in records.iter().enumerate() {
                crate::local_capture_provenance::record_local_capture_in_tx(
                    tx,
                    group_id,
                    &record.path,
                    &change_hash,
                )?;
                upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(&change_hash))?;
                if let Some(Some(meta)) = metas.get(idx) {
                    apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
                }
                // `Hydrated` is NOT stamped here. It used to be, for every
                // non-deleted record, before the match below decided
                // whether a proof could be published at all -- so a record
                // whose evidence was missing, or whose version this batch
                // did not carry, was left claiming `Hydrated` with no
                // proof behind it. That is the exact combination this
                // module's invariant excludes, and it was reachable on the
                // ordinary local-emission path, not only in a crash
                // window. The stamp now lives inside the branch that
                // publishes the proof, in this same transaction.
                //
                // The proof takes its version from the very op this change
                // carries, not from a second reconstruction of what the
                // file "should" hash to. That is the whole point: a proof
                // and a live head are two records of one decision, and they
                // can only be guaranteed to agree if there is one decision
                // to record.
                //
                // Both directions of a path's state are proofs, and both
                // are written here. A deletion used to be excluded from
                // this block entirely, so the transaction that emitted a
                // path's `Delete` left the path's actual-state record
                // untouched -- still naming the content that used to be
                // there, still current against the path's own mutation
                // fence, and therefore still readable as "this path holds
                // that file". Absence is a first-class generation (see
                // `materialized_generation`'s module doc), so a caller
                // that revalidated the absence of the object before this
                // commit gets the same treatment as one that revalidated
                // its presence.
                //
                // Every record leaves this block having said something
                // about its own actual state. The third arm is not a
                // fallthrough: a record with no usable evidence inherited
                // the superseded version's `materialization_state`, and
                // its predecessor's proof is still current against the
                // path's fence, so writing nothing would publish exactly
                // the pair this block exists to prevent.
                match (actual_state.get(&record.path), content.ops.get(idx)) {
                    (
                        Some(LocalCaptureActualStateEvidence::Present { filesystem_identity }),
                        Some(Op::Put { version, .. }),
                    ) if !record.deleted
                        && content.versions.iter().any(|v| v.version_hash == *version) =>
                    {
                        // Object kind from the version's own metadata, not
                        // from the index's column: the desired state this
                        // proof has to match is derived from exactly that
                        // field, so reading it from anywhere else
                        // reintroduces the second source of truth this is
                        // removing. A version the change references but
                        // this batch did not carry means the caller built
                        // the two inconsistently, and falls to the arm
                        // below -- no proof, and no inherited claim
                        // either.
                        let carried = content
                            .versions
                            .iter()
                            .find(|v| v.version_hash == *version)
                            .expect("the guard above required this batch to carry the version");
                        adopt_local_capture_actual_state(
                            tx,
                            group_id,
                            &record.path,
                            carried.meta.record_kind,
                            version,
                            filesystem_identity,
                        )?;
                        // Only now, and in this same transaction: the
                        // claim and the proof that earns it commit
                        // together or not at all.
                        stamp_hydrated_after_local_emission_in_tx(tx, group_id, &record.path)?;
                        settle_obligation_against_local_presence_in_tx(tx, group_id, &record.path)?;
                    }
                    // Same consistency requirement as the present case, in
                    // the other direction: the proof says "absent" only
                    // when the op this change carries for the path is the
                    // one that makes it absent. `Absent` evidence against
                    // anything else is a caller that built its evidence and
                    // its ops inconsistently, and writes no proof.
                    (Some(LocalCaptureActualStateEvidence::Absent), Some(Op::Delete { .. }))
                        if record.deleted =>
                    {
                        adopt_local_capture_absent_state(tx, group_id, &record.path)?;
                        settle_obligation_against_local_absence_in_tx(tx, group_id, &record.path)?;
                    }
                    _ => retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?,
                }
            }
            emission.permit.verify()?;
            Ok(Some(change_hash))
        })
    }

    /// Marks a file deleted (tombstone), preserving its version vector
    /// lineage so the deletion itself propagates as a normal index update.
    /// Stamps the tombstone's `mtime_unix_nanos` with "now" — the right
    /// choice for every caller of this method (a full-rescan recovery, a
    /// direct test, `hydration.rs`'s bookkeeping): none of them have an
    /// earlier, more accurate observation of when the deletion actually
    /// happened to prefer instead. `mark_deleted_at` is the one exception
    /// (see its own doc comment).
    pub fn mark_deleted(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.mark_deleted_at(group_id, path, device_id, now_unix_nanos(), permit)
    }

    /// Like `mark_deleted`, but stamps the tombstone with a caller-supplied
    /// observed time instead of "now".
    ///
    /// `local_change.rs`'s
    /// debounced dispatch of a `Removed` event is the one caller that
    /// needs this — a local deletion can sit in the debounce accumulator
    /// for up to `DebounceConfig::quiet_period` (default 300ms) before
    /// `mark_deleted` actually runs, so stamping "now" *at dispatch time*
    /// would record a tombstone time systematically *later* than the
    /// deletion's true, watcher-observed moment — unlike a concurrent
    /// edit's `mtime_unix_nanos`, which is always the file's own real
    /// content-modification time (`std::fs::metadata`), never delayed by
    /// debounce. That asymmetry alone can invert the correct chronological
    /// order between a genuinely-earlier delete and a genuinely-later
    /// edit once `conflict.rs` compares them — confirmed via
    /// `concurrent_edit_delete_edit_wins_when_later_leaves_no_conflict_artifact`
    /// regressing under a naive "now at dispatch time" stamp. Passing the
    /// debounce accumulator's own per-path last-observed timestamp here
    /// (`debounce::DebounceFlush::Paths`'s third tuple element) closes
    /// that gap.
    pub fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        // Stamp the tombstone
        // with the deletion's own observed time, not the mtime carried
        // forward from the file's last live content (the field above is
        // only overwritten here, nowhere else in this function) — a stale
        // content mtime gives `conflict.rs`'s `a_is_loser`/
        // `resolve_conflict_names` no correct chronological signal to
        // order a concurrent edit against this delete once the race that
        // used to mask the conflict path entirely is fixed (see
        // `peer_session::PeerSyncSession::reconcile_one_file`).
        record.mtime_unix_nanos = observed_at_unix_nanos;
        // `device_id` is a known origin (this device, for a local delete)
        // — recorded on the tombstone row itself, and the row it
        // supersedes (the file's last live content, if any) is retained as
        // `state = 'trashed'` rather than discarded — see
        // `upsert_file_in_tx`'s doc comment for the exact rule.
        //
        // Open-coded rather than delegated to `upsert_file_with_origin`
        // because of the second statement, which has to share this
        // transaction. This method has no evidence about the path: its
        // callers reach it from a watcher event, or from a lock-free
        // snapshot of paths orphaned by a vanished directory, and none of
        // them revalidated absence under this path's own lock. So the
        // proof naming the content that used to be here -- still current
        // against the fence, and still paired with the `Hydrated` this
        // tombstone inherits from the row it supersedes -- must not
        // survive the write that says the file is gone.
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, &record, device_id, None)?;
            retire_unproven_actual_state_in_tx(tx, group_id, path)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Tombstones a path and appends the signed `Delete` change describing
    /// it, in one transaction. Mirrors [`mark_deleted_at`](Self::mark_deleted_at)'s
    /// tombstone construction (observed-time stamp, version-vector bump,
    /// origin-recording upsert that retains the superseded live row as
    /// trash) while additionally emitting the change.
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see [`Self::upsert_file_emitting_change`]'s doc comment for why it is
    /// a parameter here rather than resolved internally.
    pub fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        publish_absent_proof: bool,
        emission: ChangeEmissionContext<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        record.mtime_unix_nanos = observed_at_unix_nanos;
        let ops = vec![Op::Delete { path: SyncPath(path.to_string()) }];
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::snapshot_install_hold::refuse_local_authoring_if_held(tx, group_id, path)?;
            let change = dag_store::emit_local_change(tx, group_id, ops.clone(), emission.emitter)?;
            let change_hash = change.compute_hash();
            crate::local_capture_provenance::record_local_capture_in_tx(
                tx,
                group_id,
                path,
                &change_hash,
            )?;
            upsert_file_in_tx(tx, group_id, &record, device_id, Some(&change_hash))?;
            if publish_absent_proof {
                adopt_local_capture_absent_state(tx, group_id, path)?;
            } else {
                // A caller that declines to publish absence is saying it
                // did not revalidate the path under its own lock -- not
                // that the old present proof is still good. Retire that
                // proof and the `Hydrated` this tombstone inherited with
                // it, so the pair cannot outlive the file they describe.
                retire_unproven_actual_state_in_tx(tx, group_id, path)?;
            }
            emission.permit.verify()?;
            Ok(change_hash)
        })
    }

    /// Commits a bounded batch of already-prepared, already-revalidated
    /// local mutations in ONE transaction — one signed DAG `Change` per
    /// mutation, in the exact order given (never collapsed into a single
    /// multi-op `Change`; see `upsert_files_batch_emitting_change`'s own
    /// doc for why that shape is deliberately NOT reused here). Sharing one
    /// `writer_gate` acquisition and one fsync-backed commit across the
    /// whole batch, instead of one per mutation, is the entire point of
    /// this method: under a burst of local mutations, per-mutation commits
    /// convoy on the writer gate.
    ///
    /// `emit_local_change` re-derives `group_heads()` from the SAME
    /// transaction on every call, so looping it here, once per mutation,
    /// naturally chains each mutation's `Change` onto the previous
    /// mutation's own just-committed head — identical causal order to
    /// calling `upsert_file_emitting_change`/`mark_deleted_emitting_change`
    /// once per mutation across N separate transactions would have
    /// produced.
    ///
    /// Callers are responsible for every correctness precondition a single-
    /// mutation call gets for free from holding its own path lock for its
    /// own commit: each mutation here must already be known-current (disk
    /// and index state revalidated) under its own path lock, and every
    /// mutation's path lock must still be held for the whole duration of
    /// this call — this repository has no filesystem/tokio dependency and
    /// cannot enforce either; see `yadorilink-local-capture`'s
    /// `flush_pending_batch` for where that revalidation and locking
    /// happen. `auth` is the already-resolved authorization stamp for
    /// `group_id`, resolved once for the whole batch — see
    /// [`Self::upsert_file_emitting_change`]'s doc comment for why it is a
    /// parameter here rather than resolved internally.
    /// `evidence`, when non-empty, must be aligned 1:1 with `mutations` --
    /// index `i`'s entry describes what actual-state evidence local
    /// capture has for `mutations[i]`, if any (see
    /// [`LocalCaptureActualStateEvidence`]'s own doc comment). An empty
    /// `evidence` slice (not aligned -- deliberately distinct from a
    /// same-length slice of every entry `None`, exactly like `metas` in
    /// [`Self::upsert_files_batch_emitting_change`]) is shorthand for "no
    /// evidence for anything in this batch," so an existing caller that
    /// predates this parameter needs no changes.
    #[allow(
        clippy::excessive_nesting,
        reason = "the whole batch must commit in ONE `write_immediate` transaction (the entire \
                  point of this method), so the per-mutation loop and its Upsert/Delete match \
                  arms are necessarily nested inside that closure; extracting an arm would \
                  move it outside the transaction guard or force the `&Transaction` and every \
                  emission parameter through a helper signature for no behavioural gain"
    )]
    pub fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: ChangeEmissionContext<'_>,
    ) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        if mutations.is_empty() {
            return Ok(Vec::new());
        }
        if !evidence.is_empty() && evidence.len() != mutations.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "commit_local_mutations_batch length mismatch: {} evidence entries for {} \
                 mutations (evidence must be empty or aligned 1:1 with mutations)",
                evidence.len(),
                mutations.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            // Checked for the whole batch before anything is authored, in
            // the transaction that authors it: a mutation prepared before a
            // snapshot install and committed after it is exactly the one
            // this is the last chance to refuse.
            for mutation in mutations {
                crate::snapshot_install_hold::refuse_local_authoring_if_held(
                    tx,
                    group_id,
                    &mutation.record().path,
                )?;
            }
            let mut hashes = Vec::with_capacity(mutations.len());
            for (i, mutation) in mutations.iter().enumerate() {
                let this_evidence = evidence.get(i).and_then(|e| e.as_ref());
                let change = emit_local_edit_onto_its_base(
                    tx,
                    group_id,
                    &mutation.record().path,
                    vec![mutation.op().clone()],
                    emission.emitter,
                )?;
                let change_hash = change.compute_hash();
                apply_local_mutation_in_tx(
                    tx,
                    group_id,
                    mutation,
                    this_evidence,
                    origin_device_id,
                    &change_hash,
                )?;
                hashes.push(change_hash);
            }
            emission.permit.verify()?;
            Ok(hashes)
        })
    }

    /// Commits a local deletion of the copy name `copy_path` as a
    /// write-through: the row at `copy_path` is tombstoned, and the change
    /// deletes `source`, the entry the namespace placed there (see
    /// [`crate::write_through`]), superseding only the head the row holds.
    /// The caller has just seen nothing under `copy_path`'s exact name
    /// while holding its path lock, which is the `Absent` evidence
    /// committed with it. The single-mutation counterpart of
    /// [`Self::commit_local_mutations_batch`] with a write-through delete.
    pub fn commit_write_through_deletion(
        &self,
        group_id: &str,
        copy_path: &str,
        source: &str,
        origin_device_id: &str,
        observed_at_unix_nanos: i64,
        emission: ChangeEmissionContext<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let mut record = self.get_file(group_id, copy_path)?.ok_or_else(|| {
            SyncSqliteError::NotFound(format!("no row at {copy_path:?} to delete through"))
        })?;
        record.deleted = true;
        record.mtime_unix_nanos = observed_at_unix_nanos;
        let op = Op::Delete { path: SyncPath(source.to_string()) };
        if crate::write_through::write_through_op_path(copy_path, source).is_none() {
            return Err(SyncSqliteError::InvalidInput(format!(
                "{copy_path:?} is not a copy name of {source:?}; nothing to delete through"
            )));
        }
        let mutation = PreparedLocalMutation::Delete { record, op: op.clone() };
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::snapshot_install_hold::refuse_local_authoring_if_held(tx, group_id, copy_path)?;
            let change = emit_local_edit_onto_its_base(
                tx,
                group_id,
                copy_path,
                vec![op.clone()],
                emission.emitter,
            )?;
            let change_hash = change.compute_hash();
            apply_local_mutation_in_tx(
                tx,
                group_id,
                &mutation,
                Some(&LocalCaptureActualStateEvidence::Absent),
                origin_device_id,
                &change_hash,
            )?;
            emission.permit.verify()?;
            Ok(change_hash)
        })
    }

    /// Commits one recursive delete (`rm -rf`) or directory rename as a
    /// signed [`RecursiveOperation`], in one transaction.
    ///
    /// `mutations` is the operation's whole observed effect set: a point
    /// delete for each explicit entry the device observed under the
    /// operation's scope, and for a rename a put of each at its new path.
    /// It is cut into parts of at most [`RECURSIVE_PART_OP_LIMIT`] ops (and
    /// [`RECURSIVE_PART_OP_BYTES`] of encoded ops), each one change carrying
    /// the operation's descriptor: one random operation id, the part's
    /// index, the part count, and the digest of the whole effect set, so a
    /// reader can tell which changes were one operation and whether it
    /// holds all of it without guessing from sequence, time or prefix.
    ///
    /// Each part is parented on the union of its paths' materialized bases
    /// (see [`recursive_part_parents_in_tx`]), so every version the device
    /// observed is consumed and none it did not is. `evidence` is aligned
    /// with `mutations` (or empty) exactly as for
    /// [`Self::commit_local_mutations_batch`], whose preconditions (every
    /// path revalidated and locked by the caller) apply unchanged.
    ///
    /// Returns the parts' change hashes in part order.
    pub fn commit_recursive_operation(
        &self,
        group_id: &str,
        kind: RecursiveOperationKind,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: ChangeEmissionContext<'_>,
    ) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        if mutations.is_empty() {
            return Ok(Vec::new());
        }
        if !evidence.is_empty() && evidence.len() != mutations.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "commit_recursive_operation length mismatch: {} evidence entries for {} mutations",
                evidence.len(),
                mutations.len()
            )));
        }
        let operation_id = loop {
            let id: [u8; 16] = rand::random();
            if id != [0u8; 16] {
                break RecursiveOperationId(id);
            }
        };
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for mutation in mutations {
                crate::snapshot_install_hold::refuse_local_authoring_if_held(
                    tx,
                    group_id,
                    &mutation.record().path,
                )?;
            }
            // A copy name the namespace placed another entry's leaf under
            // is that entry: its delete or move is authored there, read in
            // this transaction so the decision and the commit agree.
            let written = crate::write_through::write_recursive_operation_through(
                tx, group_id, &kind, mutations,
            )?;
            let mutations = written.as_slice();
            for mutation in mutations {
                if let Op::Put { path, .. } | Op::Delete { path } = mutation.op() {
                    if path.as_str() != mutation.record().path {
                        crate::snapshot_install_hold::refuse_local_authoring_if_held(
                            tx,
                            group_id,
                            path.as_str(),
                        )?;
                    }
                }
            }
            let parts = recursive_operation_parts(mutations);
            let part_count = u32::try_from(parts.len())
                .ok()
                .filter(|count| *count <= MAX_RECURSIVE_OPERATION_PARTS)
                .ok_or_else(|| {
                    SyncSqliteError::InvalidInput(format!(
                        "a recursive operation over {} entries needs {} parts, more than the \
                         {MAX_RECURSIVE_OPERATION_PARTS} one operation may have",
                        mutations.len(),
                        parts.len()
                    ))
                })?;
            let effect_set_hash = EffectSetHash::of_effects(mutations.iter().map(|m| m.op()));
            let mut hashes = Vec::with_capacity(parts.len());
            for (part_index, range) in parts.iter().enumerate() {
                let members = &mutations[range.clone()];
                let paths: Vec<&str> = members.iter().map(|m| m.record().path.as_str()).collect();
                let parents = recursive_part_parents_in_tx(tx, group_id, &paths)?;
                let part = RecursiveOperation {
                    operation_id,
                    kind: kind.clone(),
                    part_index: part_index as u32,
                    part_count,
                    effect_set_hash,
                };
                let seen = versions_shown_to_mutations(tx, group_id, members)?;
                let change = dag_store::emit_recursive_part_onto_seeing(
                    tx,
                    group_id,
                    parents,
                    members.iter().map(|m| m.op().clone()).collect(),
                    part,
                    &seen,
                    emission.emitter,
                )?;
                let change_hash = change.compute_hash();
                for (offset, mutation) in members.iter().enumerate() {
                    let this_evidence = evidence.get(range.start + offset).and_then(|e| e.as_ref());
                    apply_local_mutation_in_tx(
                        tx,
                        group_id,
                        mutation,
                        this_evidence,
                        origin_device_id,
                        &change_hash,
                    )?;
                }
                hashes.push(change_hash);
            }
            emission.permit.verify()?;
            Ok(hashes)
        })
    }

    /// Deletes every version row for one path -- not a tombstone, an
    /// erasure of this device's local index entry. Its one production
    /// caller is the ignore sweep, for a path that has just become
    /// `.yadorilinkignore`d: sync must stop considering it, but nothing
    /// about it is deleted for anyone else.
    ///
    /// Known limitation, recorded rather than silently left: un-ignoring
    /// such a path later re-indexes it from `version_seq = 1`, so the rewind
    /// planning layer reads it as a path this device first saw at the
    /// re-index and answers `Delete` for targets before the ignore, when in
    /// fact the path was indexed and answerable back then. This is the same
    /// class of wrong reading `group_local_history_floor` closes for a link
    /// or a re-bootstrap, but it is per-PATH rather than per-group, so that
    /// group-scoped floor is the wrong instrument for it -- setting one here
    /// would make every OTHER path in the group unanswerable before this
    /// instant. Closing it needs a per-path boundary, or an ignored-but-
    /// retained index row instead of a delete; neither is attempted here.
    pub fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<bool, SyncSqliteError> {
        permit.verify()?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )? > 0)
        })
    }

    pub fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, SyncSqliteError> {
        // Retried like every writer below: a shared-cache in-memory database
        // (every test's `open_in_memory`) can hand a plain read `DatabaseLocked`
        // (or, under sustained contention past `busy_timeout`'s window,
        // `DatabaseBusy` — see `retry_on_database_locked`'s own doc comment)
        // while a concurrent writer holds the table, so a caller polling state
        // from a background task (e.g. a wire-convergence test reading while a
        // real `PeerSyncSession::run()` loop writes) must retry a read here too.
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(u64, i64, String, i64)> = conn
                .query_row(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            row.map(|(size, mtime, blocks_json, deleted)| {
                row_to_record(path.to_string(), size, mtime, &blocks_json, deleted)
            })
            .transpose()
        })
    }

    /// [`Self::get_file`], restricted to the published subgraph -- see
    /// `dag_store::published_view::published_file_at_path`'s own doc
    /// comment for why this is NOT "the current row, filtered." Any
    /// peer-facing caller that decides whether to serve content on this
    /// device's behalf (block-serving authorization in particular) must
    /// use this instead of [`Self::get_file`], which stays as-is for
    /// purely local purposes (materialization, directory listing) where a
    /// user's own not-yet-checkpointed edits must remain visible.
    pub fn published_file_at_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::dag_store::published_view::published_file_at_path(conn, group_id, path)
        })
    }

    /// The `state = 'current'` row for `(group, path)` read as ONE atomic
    /// statement, carrying every column a `FileVersion` identity needs
    /// (blocks, size, mtime, record kind, symlink target, exec bit). Unlike
    /// stitching `get_file` together with the separate `get_record_kind`/
    /// `get_symlink_target`/`get_unix_mode` accessors — each its own
    /// `SELECT ... state = 'current'` — this cannot tear across a concurrent
    /// metadata/content transition: every field comes from the same row, so
    /// the `change::VersionHash` derived via [`CurrentVersionRecord::
    /// to_file_version`] always describes a version some single row actually
    /// held, never a hybrid snapshot of two. This is the read the durability
    /// custody path (eviction querier + responder) must use to reconstruct
    /// the current version's identity. `None` if there is no current row.
    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError> {
        // See `get_file`'s comment: retried for the same read-vs-writer
        // `DatabaseLocked` reason.
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, size, mtime_unix_nanos, blocks_json, deleted FROM \
                 files WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get(4)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime, blocks_json, deleted) = row?;
                // Fail the whole listing closed on a corrupt row rather than
                // silently dropping content or emitting a defaulted record: a
                // directory listing built from partially-corrupt index rows is a
                // worse failure than a hard, diagnosable error (the corrupt path is
                // named by `row_to_record`'s `warn!`).
                out.push(row_to_record(path, size, mtime, &blocks_json, deleted)?);
            }
            Ok(out)
        })
    }

    /// [`Self::list_files`] with each row's own `record_kind`, read from the
    /// same statement so a listing can never pair one row's content with
    /// another row's kind. For surfaces that list entries by kind (the
    /// shell's folder listing); sync paths keep using `list_files`.
    pub fn list_files_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(FileRecord, RecordKind)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, size, mtime_unix_nanos, blocks_json, deleted, record_kind FROM \
                 files WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get(4)?,
                    r.get::<_, String>(5)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime, blocks_json, deleted, record_kind) = row?;
                // Fails closed on a corrupt row, same as `list_files`.
                out.push((
                    row_to_record(path, size, mtime, &blocks_json, deleted)?,
                    RecordKind::from_db_str(&record_kind),
                ));
            }
            Ok(out)
        })
    }

    /// Paths of `state = 'current'`, `version_seq > 0` rows for `group_id`
    /// that do NOT yet carry a verified authoring identity -- exactly the
    /// schema's own `files_require_authoring_identity_on_*` triggers'
    /// predicate (`yadorilink_sqlite_runtime::schema`), queried directly
    /// rather than re-derived by inference so the two can never drift apart.
    /// A group with any nonempty result here is NOT safe to treat as fully
    /// DAG-backed: see `yadorilink_daemon::dag_import::ensure_initial_import`,
    /// which is what actually drives this to empty.
    pub fn list_unauthored_current_paths(
        &self,
        group_id: &str,
    ) -> Result<HashSet<String>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| unauthored_current_paths_in_tx(conn, group_id))
    }

    /// Count of live (non-deleted) `state = 'current'` rows for `group_id`
    /// -- a plain `COUNT(*)`, for callers that only need a progress number
    /// and would otherwise pay to deserialize every `FileRecord` via
    /// `list_files(...).len()`. Excludes tombstones, matching what a
    /// directory listing of real files on disk would count (see
    /// `list_files`'s own doc comment for why that one deliberately does
    /// NOT filter tombstones -- this one exists specifically because a
    /// caller that only wants "how many real files are indexed right now"
    /// doesn't want to pay to load and then discard them either).
    pub fn count_live_files(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND state = 'current' AND \
                 deleted = 0",
                rusqlite::params![group_id],
                |r| r.get(0),
            )?)
        })
    }

    /// Bulk-loads every local
    /// `FileRecord` (including tombstones — deleted rows are not filtered
    /// here, matching `get_file`'s own behavior) whose `path` is in
    /// `paths`, for `group_id`, keyed by path — the batched counterpart to
    /// calling `get_file` once per path. Mirrors the existing bulk-load
    /// pattern `LocalChangeProcessor::scan_existing_files` already uses via
    /// `list_files` — collecting the batch of incoming paths/hashes and
    /// issuing set-based queries, then diffing in memory — but scoped to
    /// exactly the requested paths via `WHERE path IN (...)`
    /// rather than loading the whole group — the right shape for
    /// materialization audits, where the requested paths are often a handful
    /// of records out of a much larger indexed group, not the whole file list.
    ///
    /// Chunks the `IN (...)` query at `GET_FILES_BY_PATHS_CHUNK_SIZE`
    /// paths per round trip (SQLite's compiled bound-parameter limit is a
    /// real, if generous, ceiling — chunking avoids ever depending on it
    /// being large enough for an arbitrarily big `paths`). A no-op query
    /// for an empty `paths`. A path with no matching row is simply absent
    /// from the returned map, exactly as `get_file` returning `None` for a
    /// path with no row.
    pub fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, SyncSqliteError> {
        const GET_FILES_BY_PATHS_CHUNK_SIZE: usize = 500;
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut out = HashMap::with_capacity(paths.len());
            for chunk in paths.chunks(GET_FILES_BY_PATHS_CHUNK_SIZE) {
                let placeholders =
                    std::iter::repeat_n("?", chunk.len()).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT path, size, mtime_unix_nanos, blocks_json, deleted \
                     FROM files WHERE group_id = ? AND state = 'current' AND path IN \
                     ({placeholders})"
                );
                let mut stmt = conn.prepare(&sql)?;
                let params = std::iter::once(&group_id as &dyn rusqlite::ToSql)
                    .chain(chunk.iter().map(|p| p as &dyn rusqlite::ToSql));
                let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get::<_, String>(3)?,
                        r.get(4)?,
                    ))
                })?;
                for row in rows {
                    let (path, size, mtime, blocks_json, deleted) = row?;
                    // Fail closed on a corrupt row (same rationale as `list_files`).
                    let record = row_to_record(path.clone(), size, mtime, &blocks_json, deleted)?;
                    out.insert(path, record);
                }
            }
            Ok(out)
        })
    }

    /// Every column of `path`'s `state = 'current'` row that a
    /// materialization decision or a proof can depend on, read as ONE
    /// statement -- see [`crate::read_canonical_current_row`], which this
    /// is a repository-level handle for.
    ///
    /// Exists so a caller that needs more than one of those columns never
    /// assembles them from several point queries. `get_file` plus
    /// `get_record_kind` plus `get_symlink_target` plus `get_unix_mode`
    /// plus `get_xattrs` plus `get_origin_device_id` plus
    /// `get_authoring_change_hash` is seven independent read
    /// transactions, and nothing holds the row still across them: the
    /// result can pair the blocks of one incarnation with the mode of
    /// another. Each of those accessors stays, for the callers that
    /// genuinely want one column as a guard.
    pub fn canonical_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<crate::CanonicalCurrentRow>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::read_canonical_current_row(conn, group_id, path)
        })
    }

    /// A single retained version by its exact `version_seq` — the restore
    /// engine's lookup for `yadorilink restore <path> --version
    /// <id>`. `None` if no row exists at all for this exact
    /// `(group_id, path, version_seq)`.
    pub fn get_version(
        &self,
        group_id: &str,
        path: &str,
        version_seq: i64,
    ) -> Result<Option<VersionRecord>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            #[allow(clippy::type_complexity)]
            let row: Option<(
                u64,
                i64,
                String,
                i64,
                String,
                Option<String>,
                String,
                Option<Vec<u8>>,
                i64,
                String,
            )> = conn
                .query_row(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted, state, \
                            origin_device_id, record_kind, symlink_target, unix_mode, xattrs_json \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                    rusqlite::params![group_id, path, version_seq],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                            r.get(9)?,
                        ))
                    },
                )
                .optional()?;
            row.map(
                |(
                    size,
                    mtime,
                    blocks_json,
                    deleted,
                    state,
                    origin_device_id,
                    record_kind,
                    symlink_target,
                    unix_mode,
                    xattrs_json,
                )| {
                    version_record(
                        path.to_string(),
                        version_seq,
                        size,
                        mtime,
                        &blocks_json,
                        deleted,
                        &state,
                        origin_device_id,
                        &record_kind,
                        symlink_target,
                        unix_mode,
                        &xattrs_json,
                    )
                },
            )
            .transpose()
        })
    }

    /// spec "Deletion Enters Recoverable Trash" / CLI "trash list": every
    /// path currently in the trashed state for `group_id` — i.e. a path
    /// whose `current` row is itself a tombstone (`deleted = 1`) and that
    /// has at least one retained `state = 'trashed'` row (the last live
    /// content before that deletion). Returns the *most recent* trashed
    /// row per path (its highest `version_seq`) alongside the tombstone's
    /// own `mtime_unix_nanos` as the deletion time — the pair `trash
    /// restore` needs (last-known size/content, and when it was deleted).
    /// A path deleted, restored, and deleted again correctly surfaces only
    /// its latest trashed version, not every historical one (`list_versions`
    /// is the place for full history).
    pub fn list_trashed(&self, group_id: &str) -> Result<Vec<TrashedFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT t.path, t.version_seq, t.size, t.mtime_unix_nanos, t.origin_device_id, \
                        c.mtime_unix_nanos, t.trashed_by_operation_author, \
                        t.trashed_by_operation_id, t.record_kind
                 FROM files t
                 JOIN (
                     SELECT path, MAX(version_seq) AS max_seq FROM files
                     WHERE group_id = ?1 AND state = 'trashed' GROUP BY path
                 ) latest ON latest.path = t.path AND latest.max_seq = t.version_seq
                 JOIN files c ON c.group_id = ?1 AND c.path = t.path AND c.state = 'current'
                 WHERE t.group_id = ?1 AND t.state = 'trashed' AND c.deleted = 1
                 ORDER BY c.mtime_unix_nanos DESC",
            )?;
            let rows = stmt.query_map([group_id], trashed_file_from_row)?;
            let rows: Vec<TrashedFile> = rows.collect::<Result<_, _>>()?;
            without_live_history(conn, group_id, rows)
        })
    }

    /// Every file currently in the trash because of one recursive delete
    /// or directory rename, in path order -- the set a folder restore
    /// puts back. Read from the trashed rows themselves, so it does not
    /// depend on the deleting changes still being retained. Like
    /// [`Self::list_trashed`], only a path's latest trashed version counts:
    /// a path the operation deleted that was since restored and deleted
    /// again by something else is not the operation's to put back, and its
    /// older version would overwrite what came after. Pair it with
    /// [`crate::dag_store::recursive_operation`]'s completeness to tell
    /// the user when the operation's parts are not all here and the
    /// restore would be partial.
    pub fn list_trashed_by_recursive_operation(
        &self,
        group_id: &str,
        operation: &RecursiveOperationRef,
    ) -> Result<Vec<TrashedFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT t.path, t.version_seq, t.size, t.mtime_unix_nanos, t.origin_device_id, \
                        c.mtime_unix_nanos, t.trashed_by_operation_author, \
                        t.trashed_by_operation_id, t.record_kind
                 FROM files t
                 JOIN (
                     SELECT path, MAX(version_seq) AS max_seq FROM files
                     WHERE group_id = ?1 AND state = 'trashed' GROUP BY path
                 ) latest ON latest.path = t.path AND latest.max_seq = t.version_seq
                 JOIN files c ON c.group_id = ?1 AND c.path = t.path AND c.state = 'current'
                 WHERE t.group_id = ?1 AND t.state = 'trashed' AND c.deleted = 1
                   AND t.trashed_by_operation_author = ?2 AND t.trashed_by_operation_id = ?3
                 ORDER BY t.path",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![
                    group_id,
                    operation.author.as_str(),
                    &operation.operation_id.0[..]
                ],
                trashed_file_from_row,
            )?;
            let rows: Vec<TrashedFile> = rows.collect::<Result<_, _>>()?;
            without_live_history(conn, group_id, rows)
        })
    }

    /// Every currently-live (non-deleted) conflicted-copy file for
    /// `group_id` -- the single source of truth both
    /// `FileHistoryQueryService::list_conflicts` and
    /// `LinkStatusReadPort::list_links`'s `conflict_count` must read from,
    /// so the two can never disagree about which paths count (a
    /// conflict-copy row is routinely deleted by the retirement sweep, so
    /// a caller that forgets the `deleted` filter silently counts a
    /// different, larger set than one that remembers it).
    ///
    /// Like `list_trashed`, a targeted query rather than `list_files`
    /// filtered in memory: selects only `path`/`size`/`mtime_unix_nanos`,
    /// never `blocks_json`, so this doesn't pay to deserialize every live
    /// file's full block map just to substring-test its path. The `LIKE`
    /// clause is a cheap SQL pre-filter, not the authoritative check --
    /// it can only ever produce a superset (it doesn't distinguish a
    /// filename's stem from a directory component, or account for the
    /// suffix landing before the extension) -- so every candidate row is
    /// re-validated in Rust against the canonical
    /// [`yadorilink_replica_domain::conflict::is_conflict_copy_path`],
    /// the same predicate `peer_session.rs`'s own conflict-copy dedup
    /// guard uses.
    pub fn list_live_conflict_copies(
        &self,
        group_id: &str,
    ) -> Result<Vec<ConflictCopyFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, size, mtime_unix_nanos, record_kind FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
                 AND path LIKE '%(conflicted copy, %'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime_unix_nanos, record_kind) = row?;
                if yadorilink_replica_domain::conflict::is_conflict_copy_path(&path) {
                    out.push(ConflictCopyFile {
                        path,
                        size,
                        mtime_unix_nanos,
                        record_kind: RecordKind::from_db_str(&record_kind),
                    });
                }
            }
            Ok(out)
        })
    }

    /// Whether any live current row lies strictly below `path` -- the
    /// index's answer to whether `path` is a directory holding synced
    /// content. See [`crate::snapshot_install_hold::has_live_descendant_row`].
    pub fn has_live_descendant_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::snapshot_install_hold::has_live_descendant_row(conn, group_id, path)
        })
    }

    /// The entry a local delete or edit of `path` is authored at, when
    /// `path` is the copy name the namespace projection placed another
    /// entry's File or Symlink under. See
    /// [`crate::write_through::write_through_source`].
    pub fn write_through_source(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::write_through::write_through_source(conn, group_id, path)
        })
    }

    /// Whether a live current row strictly below `path` (anywhere in the
    /// group when `path` is empty, the link root) is a conflict copy --
    /// the one per-file status worse than synced that an indexed row
    /// carries, which a directory's aggregate status raises. `LIKE` only
    /// narrows the candidates; each is confirmed by the same
    /// [`yadorilink_replica_domain::conflict::is_conflict_copy_path`] the
    /// per-file status uses.
    pub fn has_live_conflict_copy_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        let (lower, upper) = if path.is_empty() {
            (String::new(), "\u{10FFFF}".to_string())
        } else {
            (format!("{path}/"), format!("{path}0"))
        };
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT path FROM files WHERE group_id = ?1 AND path > ?2 AND path < ?3 \
                   AND state = 'current' AND deleted = 0 \
                   AND path LIKE '% (conflicted copy, %'",
            )?;
            let mut rows = stmt.query(rusqlite::params![group_id, lower, upper])?;
            while let Some(row) = rows.next()? {
                let candidate: String = row.get(0)?;
                if yadorilink_replica_domain::conflict::is_conflict_copy_path(&candidate) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Whether `(group_id, path)` has a genuine current row -- one this
    /// device actually indexed at some point -- as opposed to no row at
    /// all, or only the `version_seq = 0` scaffold
    /// [`ensure_bootstrap_row_for_metadata`] creates for a path it has
    /// never seen. `get_file(...).is_some()` alone cannot make this
    /// distinction: `apply_incoming_wire_metadata` (`peer_session.rs`)
    /// always bootstraps that scaffold before `materialize` runs, for
    /// EVERY never-before-seen incoming record including a tombstone, so
    /// a caller that only checks `is_some()` to decide "is there real
    /// content here to protect" sees the scaffold and wrongly answers yes.
    pub fn has_real_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            conn.query_row(
                "SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                 AND version_seq > 0 LIMIT 1",
                rusqlite::params![group_id, path],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(SyncSqliteError::from)
        })
    }

    /// The device that originated `path`'s current version, if recorded.
    /// `None` when there is no current row, or when the row predates origin
    /// tracking / was created locally without an origin stamp. Used to
    /// distinguish content this device received from a peer (a full replica of
    /// the group necessarily holds it) from a brand-new local edit no peer has
    /// yet — the fail-closed input to on-demand cache-reclamation custody.
    pub fn current_version_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let origin: Option<Option<String>> = conn
                .query_row(
                    "SELECT origin_device_id FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?;
            Ok(origin.flatten())
        })
    }

    /// Creates a `version_seq = 0` scaffold row
    /// for `path` if (and only if) no `current` row exists for it yet — the
    /// `apply_incoming_wire_metadata` bootstrap need (`peer_session.rs`):
    /// its four metadata setters (`set_record_kind`/`set_symlink_target`/
    /// `set_symlink_out_of_root`/`set_unix_mode`) are `UPDATE`-only and error
    /// if no row exists yet for a path this device has genuinely never seen
    /// before. `version_seq = 0` is a sentinel `upsert_file_in_tx`'s own
    /// `files_supersede_prior_current` trigger recognizes specially: the
    /// *next* real `upsert_file`/`upsert_file_with_origin` call for this
    /// path deletes this scaffold outright and starts real history at
    /// `version_seq = 1`, rather than leaving a spurious empty first
    /// version behind. A no-op if a current row already exists (an update
    /// to a previously-seen path) — the bootstrap is only ever needed for a
    /// path this device has never indexed at all.
    pub fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        // This write, like every sibling
        // per-path metadata setter below it (`set_record_kind`,
        // `set_symlink_target`, `set_symlink_out_of_root`, `set_unix_mode`,
        // `set_held`/`clear_held`) sits directly on `reconcile_one_file`'s
        // "adopt a brand-new path from a peer" hot path, called
        // concurrently (up to `MAX_CONCURRENT_RECONCILES` at a time, times
        // however many `handle_message` tasks are in flight) against the
        // exact same shared-cache-mode connection pool
        // `upsert_file_with_origin`'s doc comment on `retry_on_database_
        // locked`/`new_immediate_write_transaction` describes -- but,
        // unlike that function, this one was never wrapped, so a burst
        // large enough to produce real concurrent writers hit an
        // unretried `SQLITE_LOCKED` here and the whole reconcile attempt
        // was dropped, indistinguishable in effect from the semaphore/
        // head-of-line-blocking stall this change's periodic resync
        // exists to recover from. Found via this change's own burst
        // reproduction (real `database table is locked: files` errors
        // observed under load, not a hypothetical) -- fixed the same way
        // `upsert_file_with_origin` already is, so a resync round's own
        // retried reconciles aren't undermined by this same gap.
        //
        // Stamped with `admitted_at_unix_nanos` like every other `files`
        // insert -- see `upsert_file_in_tx`'s "stamping invariant" section.
        // A scaffold row is short-lived (the next real upsert promotes it in
        // place) but it is a genuine row this device held, and leaving it
        // unstamped would make the path's whole history unreadable for
        // rewind purposes rather than merely imprecise.
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, admitted_at_unix_nanos)
                 SELECT ?1, ?2, 0, 0, '[]', 0, 0, 'current', NULL, ?3
                  WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
                rusqlite::params![group_id, path, now_unix_nanos_checked()],
            )?;
            Ok(())
        })
    }

    /// The kind of on-disk entry this record represents. `None`
    /// if no row exists for `group_id`/`path` at all — distinct from `Some
    /// (RecordKind::File)`, which is a real row that just hasn't been
    /// classified as anything else.
    pub fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let kind: Option<String> = conn
                .query_row(
                    "SELECT record_kind FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(kind.as_deref().map(RecordKind::from_db_str))
        })
    }

    // `retry_on_database_locked`-wrapped
    // for the same reason as `ensure_bootstrap_row_for_metadata` just
    // above -- see its doc comment for the full diagnostic story.
    pub fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let affected = conn.execute(
                "UPDATE files SET record_kind = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![kind.as_db_str(), group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The raw, unresolved symlink target bytes, exactly as captured — only
    /// meaningful when `get_record_kind` returns `Symlink`; `None`
    /// otherwise (either no row, or a row that isn't a symlink).
    pub fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let target: Option<Option<Vec<u8>>> = conn
                .query_row(
                    "SELECT symlink_target FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(target.flatten())
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET symlink_target = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![target, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// `true` when this symlink's raw target is an absolute
    /// path, or resolves (syntactically — see
    /// `local_change::symlink_target_is_out_of_root`, never by
    /// dereferencing) outside the linked folder's root. Only meaningful
    /// when `get_record_kind` returns `Symlink`; defaults to `false`
    /// otherwise, matching `get_unix_mode`'s default-to-`false` shape for
    /// an unknown/never-set row. Deliberately a distinct column from
    /// `held_reason`/`held_since_unix_nanos` — see the migration comment
    /// in `init` for why this flag doesn't gate materialization the way
    /// held state does.
    pub fn get_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let flag: Option<i64> = conn
                .query_row(
                    "SELECT symlink_out_of_root FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(flag.unwrap_or(0) != 0)
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET symlink_out_of_root = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![out_of_root as i64, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The replicated extended attributes currently recorded for `path`
    /// sorted by name -- empty for any row with none recorded,
    /// including every pre-existing row from before this column existed.
    pub fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let xattrs_json: Option<String> = conn
                .query_row(
                    "SELECT xattrs_json FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            match xattrs_json {
                Some(json) => decode_xattrs_column(&json),
                None => Ok(Vec::new()),
            }
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_xattrs(
        &self,
        group_id: &str,
        path: &str,
        xattrs: &[(String, Vec<u8>)],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let stored = encode_xattrs_column(xattrs);
            let affected = conn.execute(
                "UPDATE files SET xattrs_json = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![stored, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The replicated Unix permission bits, or `None` for any row with no
    /// info recorded — including every pre-existing one from before this
    /// column existed (stored as `-1`, see `SCHEMA_VERSION` v23's own doc
    /// comment) and any row genuinely authored with no Unix mode (a
    /// Windows peer). Never a stand-in for "unknown collapses to zero
    /// permissions" — `Some(0)` is a real, distinct value (mode `0o000`).
    pub fn get_unix_mode(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<u32>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let unix_mode: Option<i64> = conn
                .query_row(
                    "SELECT unix_mode FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(decode_unix_mode_column(unix_mode.unwrap_or(-1)))
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_unix_mode(
        &self,
        group_id: &str,
        path: &str,
        unix_mode: Option<u32>,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let stored: i64 = encode_unix_mode_column(unix_mode);
            let affected = conn.execute(
                "UPDATE files SET unix_mode = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![stored, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// Applies every incoming-wire-metadata field for `(group_id,
    /// path)` in ONE `write_immediate` transaction -- bootstrap row if
    /// needed, then every column [`apply_local_meta_columns_in_tx`]
    /// already writes atomically for the local-capture path -- instead of
    /// up to 6 separate `SyncDatabase::write` calls
    /// (`ensure_bootstrap_row_for_metadata` + the 5 setters above), each
    /// its own `writer_gate` acquisition. Under a sync storm this exact
    /// call sequence (`peer_session.rs`'s `apply_incoming_
    /// wire_metadata`, called on every peer-driven path resolution
    /// regardless of whether anything actually changed) would otherwise
    /// be the dominant writer_gate contributor once receiver-side
    /// batching removed the bigger per-path content-write sources. `LocalFileMetaColumns`
    /// already has exactly the fields peer-side `IncomingWireMeta` needs
    /// (record_kind/symlink_target/symlink_out_of_root/unix_mode/xattrs),
    /// so this reuses that type and `apply_local_meta_columns_in_tx`'s
    /// SQL directly rather than duplicating it -- only the bootstrap-row
    /// step is new here (the local-capture caller never needs it: its own
    /// `upsert_file_in_tx` call always creates the row first).
    pub fn apply_incoming_metadata_atomic(
        &self,
        group_id: &str,
        path: &str,
        meta: &LocalFileMetaColumns,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            ensure_bootstrap_row_for_metadata_in_tx(tx, group_id, path)?;
            apply_local_meta_columns_in_tx(tx, group_id, path, meta)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// `upsert_file_in_tx` (the full row -- blocks/size/
    /// mtime/deleted/origin/authoring identity) plus `apply_local_meta_
    /// columns_in_tx` (record_kind/symlink_target/symlink_out_of_root/
    /// unix_mode/xattrs) in ONE transaction, for the peer-projection
    /// "content already matches, but something in the row/metadata/
    /// authoring/origin differs" case -- rather than two separate calls (`upsert_file_with_
    /// origin[_and_author]` + `apply_incoming_wire_metadata`), each its
    /// own `writer_gate` acquisition, even though nothing about this case
    /// needs two commits.
    pub fn apply_projected_row_atomic(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        meta: &LocalFileMetaColumns,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, authoring_change_hash)?;
            apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// The device id that
    /// actually produced this path's *current* content, as already
    /// recorded by every `upsert_file_with_origin` call (the
    /// `origin_device_id` column has existed since file-version-history
    /// support was added, previously write-only from this query's point of
    /// view — used for version-history attribution, never read back
    /// during conflict resolution). `None` for a row with no recorded
    /// origin (an empty string is stored as SQL `NULL`, per
    /// `upsert_file_in_tx`'s existing convention) — callers fall back to
    /// their own best guess (typically `self.local_device_id`/
    /// `self.peer_device_id`) in that case, matching the pre-this-fix
    /// behavior for a record that predates this column being consulted.
    pub fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let origin: Option<String> = conn
                .query_row(
                    "SELECT origin_device_id FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            Ok(origin)
        })
    }

    /// Returns the retained DAG change that authored the current projected
    /// row. `None` is deliberately preserved for pre-v7 rows and any legacy
    /// writer; callers must treat it as unverifiable, never as equality.
    pub fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let blob: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT authoring_change_hash FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            blob.map(|bytes| {
                let hash: [u8; 32] = bytes.try_into().map_err(|_| {
                    SyncSqliteError::CorruptState(format!(
                        "invalid authoring_change_hash length for {group_id}/{path}"
                    ))
                })?;
                Ok(ChangeHash(hash))
            })
            .transpose()
        })
    }

    /// Attaches verified DAG authorship to the current row. This is called
    /// while the path lock is held immediately after projection.
    pub fn set_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
        hash: &ChangeHash,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET authoring_change_hash = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![&hash.0[..], group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// Whether `path` is kept on this device: its own pin flag, or a
    /// pinned directory at or above it ([`Self::set_directory_pinned`]).
    pub fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let pinned: Option<i64> = conn
                .query_row(
                    "SELECT pinned FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            if pinned.unwrap_or(0) != 0 {
                return Ok(true);
            }
            directory_pin_covers(conn, group_id, path)
        })
    }

    /// Whether a pinned directory at or above `path` covers it -- the
    /// directory half of [`Self::is_pinned`], and the whole answer for a
    /// directory, which has no pin flag of its own.
    pub fn is_directory_pinned(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| directory_pin_covers(conn, group_id, path))
    }

    /// Records (`pinned`) or removes the policy that keeps everything at or
    /// below the directory `prefix` on this device, including entries that
    /// arrive after it is set. `""` is the link root. Removing it leaves
    /// each file's own pin flag, and any pinned directory above, as they
    /// are. Returns whether this call changed anything: a policy added, or
    /// one removed.
    pub fn set_directory_pinned(
        &self,
        group_id: &str,
        prefix: &str,
        pinned: bool,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let changed = if pinned {
                conn.execute(
                    "INSERT OR IGNORE INTO pinned_directories (group_id, prefix) VALUES (?1, ?2)",
                    rusqlite::params![group_id, prefix],
                )?
            } else {
                conn.execute(
                    "DELETE FROM pinned_directories WHERE group_id = ?1 AND prefix = ?2",
                    rusqlite::params![group_id, prefix],
                )?
            };
            Ok(changed > 0)
        })
    }

    /// The pinned directory strictly above `path` nearest to it, if any --
    /// what keeps `path` pinned whatever its own flag or policy says.
    pub fn pinned_directory_above(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    &format!(
                        "SELECT p.prefix FROM pinned_directories p WHERE p.group_id = ?1 AND \
                         p.prefix <> ?2 AND {} ORDER BY length(p.prefix) DESC LIMIT 1",
                        pinned_directory_covers_sql("?2", "0")
                    ),
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// Every live current file at or below the directory `prefix` (`""`
    /// is the link root), in path order: what a directory's pin, eviction
    /// or hydration acts on.
    pub fn list_live_files_under(
        &self,
        group_id: &str,
        prefix: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path FROM files WHERE group_id = ?1 AND state = 'current' AND \
                 deleted = 0 AND record_kind = 'file' AND \
                 (?2 = '' OR substr(path, 1, length(?2) + 1) = ?2 || '/') ORDER BY path",
            )?;
            let rows = stmt.query_map(rusqlite::params![group_id, prefix], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    pub fn set_pinned(
        &self,
        group_id: &str,
        path: &str,
        pinned: bool,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE files SET pinned = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![pinned as i64, group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Records `unix_ts` as this file's last-accessed time:
    /// called on hydration completion, and best-effort from the eviction
    /// sweep's `fs::metadata.accessed` fallback for already-hydrated
    /// files.
    pub fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE files SET last_accessed_unix = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![unix_ts, group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Whether any current or retained materialized index version in `group_id`
    /// references `block_hash`. A DAG conflict may move a losing version to a
    /// derived path after its original current row has become superseded.
    pub fn group_retained_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare("SELECT blocks_json FROM files WHERE group_id = ?1")?;
            let mut rows = stmt.query([group_id])?;
            while let Some(row) = rows.next()? {
                let blocks_json: String = row.get(0)?;
                let blocks: Vec<BlockInfo> =
                    serde_json::from_str(&blocks_json).map_err(|error| {
                        // A malformed stored block list is locally-corrupt state, not an
                        // absent referent — classify it as `CorruptState`, not
                        // `NotFound`, so the whole "stored block list is malformed"
                        // fault is reported one consistent way.
                        SyncSqliteError::CorruptState(format!(
                            "stored block list is corrupt: {error}"
                        ))
                    })?;
                if blocks.iter().any(|block| block.hash.as_slice() == block_hash) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Every user-recoverable durability root for `group_id`: the single set
    /// a full-replica handoff must cover so that demoting/unlinking/revoking
    /// the group's last eager replica can never silently lose recoverable
    /// history, not just the current head. A root is `(path, change::
    /// VersionHash)`, one entry per still-restorable `(path, version_seq)`
    /// row, so the same `path` legitimately appears more than once when
    /// several of its versions are each still retained.
    ///
    /// The three categories that actually exist in this schema today all
    /// live in the same `files` table, distinguished only by `state`
    /// ([`VersionState`]) — there is no separate version-history, trash, or
    /// conflict-copy table:
    ///
    /// - **current** (`state = 'current'`): the live head of every file —
    ///   the same set `list_files` returns.
    /// - **retained superseded** (`state = 'superseded'`): prior versions not
    ///   yet swept by [`Self::expire_superseded_and_trashed_versions`],
    ///   restorable via `versions`/`restore --version`.
    /// - **trash-restorable** (`state = 'trashed'`): deleted-but-in-retention
    ///   content, restorable via `trash restore`, not yet swept by the same
    ///   expiry.
    ///
    /// Conflict copies are NOT a fourth category — there is no
    /// `RecordKind::ConflictCopy` or marker column (see
    /// `conflict::is_conflict_copy_of`): a conflict copy is written as an
    /// ordinary `state = 'current'` row under a synthetic
    /// `"name (conflicted copy, ...)"` path, so it is already covered by the
    /// `current` scan above with no extra query.
    ///
    /// A non-deleted row of any of the three states carries real, restorable
    /// block content — `live_block_hashes_with_extra_roots`'s own doc
    /// comment establishes the identical fact for the block-store GC live
    /// set. Directories and symlinks carry no blocks and are excluded
    /// (`record_kind != 'file'`, itself a per-row column so this can filter
    /// in SQL directly rather than needing a second per-path lookup); a
    /// `deleted = 1` row is also excluded — its `blocks_json` is always `[]`
    /// by construction.
    ///
    /// Also returns a stable digest over the root set (roots sorted by path,
    /// each root's block sequence kept ordered — see
    /// [`durability_roots_digest`]) so a caller can capture it when
    /// readiness is first confirmed and re-check it immediately before
    /// committing a role loss, detecting the set changing out from under
    /// that confirmation. For the daemon-driven commit paths that must be
    /// atomic against a concurrent index write, use
    /// [`Self::recheck_digest_then_set_materialization_policy`] /
    /// [`Self::recheck_digest_then_remove_link`] instead of comparing a
    /// separately-read digest, which re-enumerate and commit in one
    /// transaction so no write can interleave.
    ///
    /// Deliberately NOT used by per-file eviction custody
    /// ([`Self::list_versions`]/the daemon's `confirm_version_present_via_
    /// peer`), which stays a `VersionPresent` check for the ONE evicted
    /// exact version — routing eviction through the whole-group root set
    /// would ask an on-demand device to prove custody of history it was
    /// never asked to hold in the first place. GC unification (a future
    /// block-store sweep computing its live set from roots ∪
    /// hydration-in-progress (`MaterializationState::Hydrating`) ∪
    /// dirty/in-flight (`Self::list_dirty_paths`) ∪ a grace window) is out
    /// of scope here; this function only answers the handoff/durability
    /// question.
    pub fn enumerate_group_durability_roots(
        &self,
        group_id: &str,
    ) -> Result<DurabilityRoots, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            enumerate_group_durability_roots_on_conn(conn, group_id)
        })
    }

    /// `group_id`'s current `file_root_set_generation` counter — `0` if the
    /// group has never had a `files` row written for it.
    ///
    /// Maintained by triggers on `files` (see that table's own comment in
    /// `yadorilink_sqlite_runtime::schema`), so it moves for every insert,
    /// update and delete, in the same transaction as the write. Two reads
    /// returning the same value mean no `files` row for the group changed in
    /// between; they do not mean the *set* is unchanged in any deeper sense,
    /// since a write that nets out still moves it. That asymmetry is the
    /// right one for a cache key: it can only ever cause an unnecessary
    /// recomputation, never a stale hit.
    pub fn root_set_generation(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| root_set_generation_on_conn(conn, group_id))
    }

    /// `group_id`'s durability-root set reduced to [`RootSetSummary`] — two
    /// digests, two counts, and the generation they were taken at — in one
    /// scan, without reading a single block.
    ///
    /// The generation is read FIRST, before the rows. A concurrent write
    /// landing during the scan then produces a summary stamped with a
    /// generation older than the state it describes, so the next read sees a
    /// moved generation and recomputes. Reading it afterwards would stamp a
    /// possibly-torn summary as current, which is the one ordering that can
    /// cache a digest the table does not support.
    pub fn group_root_set_summary(
        &self,
        group_id: &str,
    ) -> Result<RootSetSummary, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let generation = root_set_generation_on_conn(conn, group_id)?;
            group_root_set_summary_on_conn(conn, group_id, generation)
        })
    }

    /// The `(path, version_seq)` identity of every row
    /// [`Self::enumerate_group_durability_roots`] would enumerate for
    /// `group_id`, in the same order over the same `WHERE` clause. `
    /// DurabilityRoot` itself (`path` + `block_hashes`) carries no
    /// `version_seq` — it identifies content, not a specific retained row —
    /// so a caller that needs to pin the *exact rows* a handoff-readiness
    /// check just verified (see [`Self::record_handoff_lease`]) reads this
    /// sibling query instead. Deliberately a separate, read-only query
    /// rather than a change to `DurabilityRoot`'s own shape: this crate's
    /// durability-root type is shared, public-facing wire surface, not
    /// something this lease-pinning feature owns.
    ///
    /// Not run in the same transaction as the digest capture it is normally
    /// paired with (see `daemon_state`'s handoff-lease request path) — a
    /// small, documented gap matching every other "digest captured, then a
    /// separate read/commit" pattern this crate already accepts elsewhere
    /// (e.g. [`Self::full_replica_handoff_ready_digest`]'s own doc comment).
    /// Pinning is defense in depth on top of, not a replacement for, the
    /// existing digest re-check gates.
    pub fn enumerate_group_durability_root_versions(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, i64)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, version_seq FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
                   AND state IN ('current', 'superseded', 'trashed') \
                 ORDER BY path, version_seq",
            )?;
            let rows =
                stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The retention-expiry sweep — deletes the index row (never the
    /// blocks; leaves actual block reclamation to a future
    /// block-store GC) for any `superseded`/`trashed` version of
    /// `group_id` that exceeds *both* the built-in version-count bound
    /// ([`RETENTION_MAX_VERSIONS`], by recency rank among that path's own
    /// superseded/trashed rows) and the built-in age bound
    /// ([`RETENTION_MAX_AGE_DAYS`], by wall-clock age from `now_unix_nanos`).
    /// This is the union-retain / intersection-expire rule: a version is kept
    /// while it is within *either* bound, and expired only once it is beyond
    /// *both*, so recent history and recently-changed history are both kept.
    /// Retention is a fixed built-in policy applied to every link; it is not
    /// configurable. The `current` row for any path is never a candidate —
    /// the `WHERE state IN ('superseded', 'trashed')` below structurally
    /// excludes it, matching the rule that the current live version is never
    /// subject to retention expiry. Returns the number of rows deleted.
    ///
    /// `pinned` is the `(path, version_seq)` set an outstanding handoff lease
    /// still protects (see `HandoffLease`'s doc comment) — resolved by
    /// `SyncState::expire_superseded_and_trashed_versions` via
    /// `HandoffLeaseRepository::leased_version_keys_for_group` and passed in
    /// as a parameter, since `handoff_leases` is not `files`-table state and
    /// therefore not this repository's own concern to read (mirrors
    /// `upsert_file_emitting_change`'s already-resolved-`ChangeAuth`
    /// parameter pattern). A pinned row is retained past both bounds until
    /// the lease is confirmed/released/expires.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        now_unix_nanos: i64,
        pinned: &HashSet<(String, i64)>,
    ) -> Result<usize, SyncSqliteError> {
        // Opens its own DEFERRED transaction (rather than going through
        // `write_immediate`, which is always IMMEDIATE) on purpose: this
        // sweep is read-heavy (the whole candidate SELECT below) before its
        // handful of DELETEs, and taking the write lock only once a
        // candidate is actually found to delete -- SQLite's default
        // deferred-lock-upgrade behavior -- is the original, deliberate
        // choice here, preserved unchanged by this conversion.
        self.database.write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            let expired = expire_superseded_and_trashed_versions_in_tx(
                &tx,
                group_id,
                now_unix_nanos,
                pinned,
            )?;
            tx.commit()?;
            Ok(expired)
        })
    }
}

/// The body of [`FileIndexRepository::expire_superseded_and_trashed_versions`],
/// in the caller's transaction: the same rule, the same rows deleted, the
/// number deleted returned.
pub(crate) fn expire_superseded_and_trashed_versions_in_tx(
    tx: &Connection,
    group_id: &str,
    now_unix_nanos: i64,
    pinned: &HashSet<(String, i64)>,
) -> Result<usize, SyncSqliteError> {
    const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;
    let age_cutoff_unix_nanos =
        now_unix_nanos.saturating_sub(RETENTION_MAX_AGE_DAYS.saturating_mul(NANOS_PER_DAY));
    let candidates: Vec<(String, i64)> = {
        // `rnk = 1` is the most recently superseded/trashed row for a
        // given path; the newest `RETENTION_MAX_VERSIONS` rows survive on
        // the count axis alone. A row is deleted only when it is beyond
        // both the count bound and the age bound.
        let mut stmt = tx.prepare(
            "SELECT path, version_seq FROM (
            SELECT path, version_seq, mtime_unix_nanos,
                   ROW_NUMBER() OVER (PARTITION BY path ORDER BY version_seq DESC) AS rnk
            FROM files WHERE group_id = ?1 AND state IN ('superseded', 'trashed')
         )
         WHERE rnk > ?2 AND mtime_unix_nanos < ?3",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![group_id, RETENTION_MAX_VERSIONS, age_cutoff_unix_nanos],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            // A leased row is retained past both bounds until the lease is
            // confirmed/released/expires -- see the `pinned` note on
            // `FileIndexRepository::expire_superseded_and_trashed_versions`
            // for why the time check (not merely `state`) is what actually
            // matters.
            .filter(|key| !pinned.contains(key))
            .collect()
    };
    for (path, version_seq) in &candidates {
        tx.execute(
            "DELETE FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
            rusqlite::params![group_id, path, version_seq],
        )?;
    }
    Ok(candidates.len())
}

/// The parents a LOCAL filesystem edit at `path` must be signed onto.
///
/// A local edit is a statement about bytes the user actually had on disk,
/// so it must be causally parented on the state those bytes came from --
/// never on whatever the DAG frontier happens to be at emission time. The
/// two differ whenever a peer's change is admitted between the edit being
/// captured and the debounced emission committing it, and taking the
/// frontier there is a silent lost update: the peer's change becomes the
/// winner at those parents, `resolve_path_heads` never copies a winner, and
/// the local edit supersedes it with no copy of its content anywhere.
///
/// `lookup_materialized_generation` is the authority for "these exact bytes
/// are on disk". It is fence-checked, and by that module's own rule a row
/// appears only after an observed, durable filesystem placement -- an
/// admission alone never writes one, and placeholder/held outcomes cannot
/// write one even in principle (`ExactActualState` has no constructor for
/// them). That is precisely the distinction this decision needs, and the
/// one the index's `authoring_change_hash` cannot make: that column reads
/// the peer's change as soon as it is projected, while the user was still
/// editing the previous bytes.
///
/// `None` means "unknown", not "absent" -- a path this device has never
/// placed, or whose recorded generation has since been invalidated: by a
/// physical mutation, by a local emission that wrote the path without
/// proving what is on disk, or by a prune or base install that removed
/// history the basis could name. The caller then signs onto the current
/// frontier, less any version of the path this device has not shown -- see
/// [`emit_local_write_onto_frontier`].
fn local_edit_parents_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<Option<Vec<ChangeHash>>, SyncSqliteError> {
    let Some(basis) =
        crate::materialized_generation::lookup_materialized_generation(tx, group_id, path)?
    else {
        return Ok(None);
    };
    dag_store::lookup_causal_basis_members(tx, &basis.causal_basis_id.0)
}

/// The most ops one part of a recursive operation carries. Each part is
/// one change, delivered whole, so this keeps a part small; the byte bound
/// below applies too.
pub const RECURSIVE_PART_OP_LIMIT: usize = 256;

/// The most encoded op bytes one part of a recursive operation carries:
/// half of [`MAX_CHANGE_OP_BYTES`], leaving the other half for conflict
/// copies the emission may derive into the same change.
pub const RECURSIVE_PART_OP_BYTES: usize = MAX_CHANGE_OP_BYTES / 2;

/// Cuts `mutations` into the index ranges of a recursive operation's
/// parts, in order: each at most [`RECURSIVE_PART_OP_LIMIT`] ops and
/// [`RECURSIVE_PART_OP_BYTES`] encoded bytes (a single op larger than that
/// still gets a part of its own).
fn recursive_operation_parts(mutations: &[PreparedLocalMutation]) -> Vec<std::ops::Range<usize>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (index, mutation) in mutations.iter().enumerate() {
        let len = encoded_op_len(mutation.op());
        if index > start
            && (index - start >= RECURSIVE_PART_OP_LIMIT || bytes + len > RECURSIVE_PART_OP_BYTES)
        {
            parts.push(start..index);
            start = index;
            bytes = 0;
        }
        bytes += len;
    }
    parts.push(start..mutations.len());
    parts
}

/// The index half of one prepared local mutation, in the transaction that
/// just emitted `change_hash` for it: the row, its metadata, the local
/// capture provenance, and what `evidence` proves about the disk (or the
/// retirement of any earlier proof when it proves nothing).
fn apply_local_mutation_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutation: &PreparedLocalMutation,
    evidence: Option<&LocalCaptureActualStateEvidence>,
    origin_device_id: &str,
    change_hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    crate::local_capture_provenance::record_local_capture_in_tx(
        tx,
        group_id,
        &mutation.record().path,
        change_hash,
    )?;
    match mutation {
        PreparedLocalMutation::Upsert { record, version, meta, .. } => {
            dag_store::put_file_version(tx, group_id, version)?;
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(change_hash))?;
            if let Some(meta) = meta {
                apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
            }
            // THE production hot path for an ordinary live local edit --
            // `process_event` defers every non-symlink create/modify into a
            // pending batch flushed through here, so
            // `upsert_file_emitting_change` alone (also stamped) is not the
            // whole story. Same local-emission precondition as that
            // sibling: `record`'s bytes were this device's own disk content
            // when the batch was prepared.
            match (meta, evidence) {
                (
                    Some(meta),
                    Some(LocalCaptureActualStateEvidence::Present { filesystem_identity }),
                ) if !record.deleted => {
                    adopt_local_capture_actual_state(
                        tx,
                        group_id,
                        &record.path,
                        meta.record_kind,
                        &version.version_hash,
                        filesystem_identity,
                    )?;
                    stamp_hydrated_after_local_emission_in_tx(tx, group_id, &record.path)?;
                }
                // The batch prepared this mutation but could not vouch for
                // the bytes it leaves on disk. The row it just superseded
                // may have been `Hydrated` with a proof naming its version;
                // neither may carry over onto this one.
                _ => retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?,
            }
        }
        PreparedLocalMutation::Delete { record, .. } => {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(change_hash))?;
            if matches!(evidence, Some(LocalCaptureActualStateEvidence::Absent)) {
                adopt_local_capture_absent_state(tx, group_id, &record.path)?;
            } else {
                // Same reasoning as the `Upsert` arm's, and the one that
                // matters most here: a tombstone whose absence nobody
                // revalidated must not leave the path's last present proof
                // readable as current.
                retire_unproven_actual_state_in_tx(tx, group_id, &record.path)?;
            }
        }
    }
    Ok(())
}

/// What the writer of `mutations` was shown at each path their ops write:
/// the version the row each mutation acts on holds, at every path its op
/// names. The row and the op are at one path except for a write through a
/// conflict copy to its source, where the copy's row is what was shown at
/// the source -- and only that: the source's own row shows another entry.
/// The installed base's heads a write supersedes are the ones among these
/// (see [`dag_store::SeenVersions`]).
fn versions_shown_to_mutations(
    tx: &rusqlite::Transaction,
    group_id: &str,
    mutations: &[PreparedLocalMutation],
) -> Result<dag_store::SeenVersions, SyncSqliteError> {
    let mut seen = dag_store::SeenVersions::new();
    for mutation in mutations {
        let Some(shown) = dag_store::content_shown_at(tx, group_id, &mutation.record().path)?
        else {
            continue;
        };
        for path in dag_store::op_touched_paths(mutation.op()) {
            seen.entry(path.to_owned()).or_default().insert(shown);
        }
    }
    Ok(seen)
}

/// The parents of one part of a recursive operation that touches `paths`:
/// the union of every path's materialized basis (BASIS-CONSUMPTION), and,
/// when any path's basis is unknown, the frontier as it stands without the
/// versions of the touched paths this device has not shown -- the same
/// rule [`emit_local_write_onto_frontier`] applies to one path, applied to
/// all of them at once, so no path's unseen head is claimed as causal past
/// through another path's parents.
///
/// A path's seen versions are its basis when it has one, and otherwise the
/// version its index row names.
fn recursive_part_parents_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    paths: &[&str],
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut parents: std::collections::BTreeSet<ChangeHash> = std::collections::BTreeSet::new();
    let mut seen_by_path: Vec<(&str, Vec<ChangeHash>)> = Vec::with_capacity(paths.len());
    let mut any_unknown = false;
    for path in paths {
        match local_edit_parents_in_tx(tx, group_id, path)? {
            Some(basis) if !basis.is_empty() => {
                parents.extend(basis.iter().copied());
                seen_by_path.push((path, basis));
            }
            _ => {
                any_unknown = true;
                let shown: Option<Option<Vec<u8>>> = tx
                    .query_row(
                        "SELECT authoring_change_hash FROM files \
                          WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                            AND version_seq > 0",
                        rusqlite::params![group_id, path],
                        |row| row.get(0),
                    )
                    .optional()?;
                let seen = shown
                    .flatten()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                    .map(ChangeHash);
                seen_by_path.push((path, seen.into_iter().collect()));
            }
        }
    }
    if any_unknown {
        let specs: Vec<(&str, &[ChangeHash])> =
            seen_by_path.iter().map(|(path, seen)| (*path, seen.as_slice())).collect();
        let frontier = match dag_store::path_frontier::frontier_without_unseen_heads_of_paths(
            tx, group_id, &specs,
        )? {
            Some(cut) => cut,
            None => dag_store::group_heads(tx, group_id)?,
        };
        parents.extend(frontier);
    }
    Ok(parents.into_iter().collect())
}

/// [`local_edit_parents_in_tx`] applied: emits `ops` onto the base the
/// edited bytes actually came from, and onto
/// [`emit_local_write_onto_frontier`]'s parents when that base is unknown.
fn emit_local_edit_onto_its_base(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    if let Some(source) = write_through_source_of(path, &ops)? {
        return emit_write_through(tx, group_id, path, &source, ops, emitter);
    }
    if let Some(parents) = local_edit_parents_in_tx(tx, group_id, path)? {
        if !parents.is_empty() {
            return dag_store::emit_local_change_onto(tx, group_id, parents, ops, emitter);
        }
    }
    emit_local_write_onto_frontier(tx, group_id, path, ops, emitter)
}

/// Emits a local write at `path` onto the current frontier, less every
/// version of `path` this device has not shown.
///
/// Admission writes only the DAG, never the index, so the frontier can hold
/// versions of `path` the user never saw: most commonly a peer's create or
/// edit admitted while this write waited out its debounce, or admitted just
/// before the link captured the file from disk to apply it. Signed onto the
/// plain frontier the write would supersede them, and nothing preserves a
/// superseded version. They are cut away instead
/// ([`dag_store::path_frontier::frontier_without_unseen_path_heads`]), so
/// the write lands concurrent with them and the ordinary conflict
/// resolution keeps both contents.
///
/// The version this device has shown is the one its index row names
/// (`authoring_change_hash`), which moves when the device projects a
/// version or writes one itself; every live head that is it or its
/// ancestor is still superseded, as the write means to. A path with no row
/// with content -- never indexed, or holding only the `version_seq = 0`
/// scaffold reconciliation writes before placing a peer's version, which
/// survives a retried placement -- has shown no version, and every live
/// head of it is cut. So is every live head of a row that names no
/// authoring change.
fn emit_local_write_onto_frontier(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    if let Some(source) = write_through_source_of(path, &ops)? {
        return emit_write_through(tx, group_id, path, &source, ops, emitter);
    }
    emit_onto_frontier_without_unseen(tx, group_id, path, path, ops, emitter)
}

/// The source entry a single-op local write of the row at `row_path`
/// writes through to: `Some` exactly when its op is at the entry
/// `row_path` is a copy name of ([`crate::write_through`]).
fn write_through_source_of(row_path: &str, ops: &[Op]) -> Result<Option<String>, SyncSqliteError> {
    let [op] = ops else { return Ok(None) };
    let op_path = match op {
        Op::Put { path, .. } | Op::Delete { path } => path.as_str(),
        Op::Move { .. } => return Ok(None),
    };
    Ok(crate::write_through::write_through_op_path(row_path, op_path).map(str::to_owned))
}

/// Emits a local write of the row at the copy name `row_path` as a write of
/// `source`, the entry the projection placed there.
///
/// Signed onto the frontier less every head of `source` the row does not
/// hold: the change supersedes the head whose content the user deleted or
/// edited and nothing else there. An explicit Directory that keeps
/// `source`'s path, another File's head, or a peer's write admitted since
/// all stay live beside it. Parenting on the copy's materialized basis
/// instead would name the whole frontier the copy was placed under,
/// Directory head included, and a `Delete(source)` would then take the
/// Directory with it.
fn emit_write_through(
    tx: &rusqlite::Transaction,
    group_id: &str,
    row_path: &str,
    source: &str,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    crate::snapshot_install_hold::refuse_local_authoring_if_held(tx, group_id, source)?;
    emit_onto_frontier_without_unseen(tx, group_id, row_path, source, ops, emitter)
}

/// [`emit_local_write_onto_frontier`] with the version shown read from the
/// row at `row_path` and the unseen heads cut at `op_path` (the same path
/// but for a write-through).
///
/// The installed base's heads the write supersedes at `op_path` are the
/// same one version: for a write-through, the head the copy's row holds,
/// and never the entry the source's own row shows beside it.
fn emit_onto_frontier_without_unseen(
    tx: &rusqlite::Transaction,
    group_id: &str,
    row_path: &str,
    op_path: &str,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let seen = dag_store::version_shown_at(tx, group_id, row_path)?;
    let cut = dag_store::path_frontier::frontier_without_unseen_path_heads(
        tx,
        group_id,
        op_path,
        seen.as_ref(),
    )?;
    if row_path == op_path {
        return match cut {
            Some(parents) => dag_store::emit_local_change_onto(tx, group_id, parents, ops, emitter),
            None => dag_store::emit_local_change(tx, group_id, ops, emitter),
        };
    }
    let mut shown = dag_store::SeenVersions::new();
    if let Some(content) = dag_store::content_shown_at(tx, group_id, row_path)? {
        shown.entry(op_path.to_owned()).or_default().insert(content);
    }
    match cut {
        Some(parents) => {
            dag_store::emit_local_change_onto_seeing(tx, group_id, parents, ops, &shown, emitter)
        }
        None => dag_store::emit_local_change_seeing(tx, group_id, ops, &shown, emitter),
    }
}

/// The actual query behind [`FileIndexRepository::list_unauthored_current_paths`]
/// -- a free function taking a plain `&Connection` (via `Transaction`'s
/// `Deref`) so `change_history.rs`'s `append_initial_import` can re-run the
/// identical check FRESH, inside its own write transaction, immediately
/// before deciding whether it is safe to commit -- see that function's own
/// doc comment for why re-deriving this inside the transaction, rather than
/// trusting a value computed outside it, is the actual fix.
///
/// A row is authored when its authoring change is retained, was pruned
/// with a stub left behind, or carries authorization evidence here. The
/// last is what a row an installed base carries has: the change that wrote
/// it was absorbed by the base and is no longer retained, while the
/// evidence that authorized it is kept as long as a file row names that
/// change as its author (`authorization_witness_gc` collects only evidence
/// nothing retained names). Such a row is part of the
/// history the base stands for, not an unauthored one to import again.
pub(crate) fn unauthored_current_paths_in_tx(
    conn: &Connection,
    group_id: &str,
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path FROM files f
          WHERE f.group_id = ?1 AND f.state = 'current' AND f.version_seq > 0
            AND (f.authoring_change_hash IS NULL
                 OR length(f.authoring_change_hash) != 32
                 OR NOT EXISTS(
                     SELECT 1 FROM changes c
                      WHERE c.group_id = f.group_id AND c.change_hash = f.authoring_change_hash
                     UNION ALL
                     SELECT 1 FROM pruned_changes pc
                      WHERE pc.group_id = f.group_id AND pc.change_hash = f.authoring_change_hash
                     UNION ALL
                     SELECT 1 FROM change_authorization ca
                      WHERE ca.change_hash = f.authoring_change_hash
                 ))",
    )?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

/// Drops the trashed paths the history holds live again. The index keeps a
/// path's tombstone until the projection places what replaced it, and a
/// restore the projection places (beside a directory, say) may never write
/// a live row at the path at all; the path is not in the trash either way,
/// and restoring it again would only author another change.
fn without_live_history(
    conn: &Connection,
    group_id: &str,
    rows: Vec<TrashedFile>,
) -> Result<Vec<TrashedFile>, SyncSqliteError> {
    let mut kept = Vec::with_capacity(rows.len());
    for row in rows {
        let live = dag_store::live_path_heads(conn, group_id, &row.path)?
            .iter()
            .any(|head| head.content.is_some());
        if !live {
            kept.push(row);
        }
    }
    Ok(kept)
}

/// One `TrashedFile` from a row shaped like `list_trashed`'s select list.
fn trashed_file_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TrashedFile> {
    let author: Option<String> = r.get(6)?;
    let operation_id: Option<Vec<u8>> = r.get(7)?;
    let deleted_by_operation = match (author, operation_id) {
        (Some(author), Some(id)) => {
            let id: [u8; 16] = id.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Blob,
                    "trashed_by_operation_id is not 16 bytes".into(),
                )
            })?;
            Some(RecursiveOperationRef {
                author: DeviceId(author),
                operation_id: RecursiveOperationId(id),
            })
        }
        _ => None,
    };
    Ok(TrashedFile {
        path: r.get(0)?,
        version_seq: r.get(1)?,
        last_known_size: r.get::<_, u64>(2)?,
        origin_device_id: r.get(4)?,
        deleted_at_unix_nanos: r.get(5)?,
        deleted_by_operation,
        record_kind: RecordKind::from_db_str(&r.get::<_, String>(8)?),
    })
}

/// Marks the row a deletion just trashed with the recursive operation that
/// deletion was a part of, if it was one. The tombstone's authoring change
/// is the deleting change, and its part record is already in this database
/// by the time any row is projected from it: a change is admitted (and its
/// part recorded) before anything is materialized from it, and local
/// emission appends and records in the transaction that writes the row.
fn stamp_trashed_row_operation(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    trashed_seq: i64,
    deleting_change: Option<&ChangeHash>,
) -> Result<(), SyncSqliteError> {
    let Some(deleting_change) = deleting_change else { return Ok(()) };
    let Some(operation) = crate::dag_store::recursive_operation_of_change(tx, deleting_change)?
    else {
        return Ok(());
    };
    tx.execute(
        "UPDATE files SET trashed_by_operation_author = ?1, trashed_by_operation_id = ?2 \
         WHERE group_id = ?3 AND path = ?4 AND version_seq = ?5 AND state = 'trashed'",
        rusqlite::params![
            operation.author.as_str(),
            &operation.operation_id.0[..],
            group_id,
            path,
            trashed_seq
        ],
    )?;
    Ok(())
}

/// The shared version-retaining write
/// path behind `SyncState::upsert_file_with_origin` and
/// `SyncState::upsert_files_batch` — see `upsert_file_with_origin`'s doc
/// comment for the full semantics. Takes an open `Transaction` rather than
/// checking out its own pooled connection so a batch caller can commit
/// once for many records (mirroring the pre-existing `upsert_files_batch`
/// shape) while a single-record caller still gets the same atomicity via
/// its own one-record transaction — see `new_immediate_write_transaction`'s
/// doc comment for why that transaction must be opened `IMMEDIATE`, not
/// rusqlite's default `DEFERRED`.
///
/// sync-performance: `upsert_file_with_origin` is the hot path for every
/// local edit and every peer-adopted change, so this is written for two
/// SQLite round trips, not the more obvious three (a `SELECT` to find the
/// current row, an `INSERT` for the new one, an `UPDATE` to flip the old
/// one). An earlier draft chased this down to a *single* round trip with
/// an `AFTER INSERT` trigger; that turned out not to be the actual
/// bottleneck (see `new_immediate_write_transaction`) and introduced its
/// own correctness risk (a trigger recursing into the same table its own
/// statement is still executing over), so it was reverted in favor of this
/// plainer two-statement version.
///
/// The first round trip below is an `UPDATE... RETURNING`: it flips
/// whatever row is currently `state = 'current'` (if any) to
/// `superseded`/`trashed` per 's rule *and* returns everything
/// needed to build the new current row, so no separate up-front `SELECT`
/// is needed before it.
///
/// Every row this function writes -- all three branches -- is stamped with
/// `admitted_at_unix_nanos`, this device's own local clock read at the
/// moment of the write. Captured inside this function rather than passed
/// in, so no caller can supply it and no caller site needed to change.
/// Never `record.mtime_unix_nanos` -- see that column's own migration
/// comment in `yadorilink-sqlite-runtime`'s schema for why a replicated
/// filesystem timestamp is untrusted input here.
///
/// # The stamping invariant
///
/// This function is the ordinary per-path version write path, but it is
/// deliberately NOT the only writer of `files` rows, and the correctness of
/// everything reading `admitted_at_unix_nanos` rests on the whole set
/// agreeing. The invariant, stated once here because it is easy to break by
/// adding a fourth writer without noticing:
///
/// > **Every statement anywhere that inserts a `files` row stamps
/// > `admitted_at_unix_nanos` from this device's own clock at the moment of
/// > that write. A NULL means only "this row predates the column".**
///
/// The complete set of writers, all of which do:
///
/// * this function (three branches: new path, `version_seq = 0` scaffold
///   promotion, and superseding version bump),
/// * [`FileIndexRepository::ensure_bootstrap_row_for_metadata`] and
///   [`ensure_bootstrap_row_for_metadata_in_tx`], which insert the
///   `version_seq = 0` metadata scaffold, and
/// * `rebootstrap_store::replace_group_files_from_snapshot`, which replaces
///   a whole group's rows from an installed HistoryBase snapshot.
///
/// Two consequences follow, and both are load-bearing rather than
/// incidental:
///
/// * Because every writer stamps, a NULL genuinely does mean "written
///   before the column existed" -- so `crate::rewind_plan` is entitled to
///   treat NULL rows as a prefix of a path's history and to report the
///   affected path as unanswerable rather than guessing.
/// * Several rows for one path can share a stamp, because the snapshot
///   replace above writes a path's whole retained history in one pass. The
///   reader's `version_seq DESC` tie-break is what resolves that to the
///   path's current row, so a rebootstrapped group reports real per-path
///   values rather than a blanket "unavailable".
pub fn upsert_file_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    authoring_change_hash: Option<&ChangeHash>,
) -> Result<(), SyncSqliteError> {
    let blocks_json = serde_json::to_string(&record.blocks)?;
    let origin: Option<&str> =
        if origin_device_id.is_empty() { None } else { Some(origin_device_id) };
    let authoring_change_hash_arg = authoring_change_hash;
    let authoring_blob = authoring_change_hash.map(|hash| &hash.0[..]);
    // Read once, before any branch, so all three branches stamp the exact
    // same instant for one call -- a scaffold promotion in particular
    // writes what is logically the same admission as the insert that
    // preceded it, and two clock reads could otherwise straddle a rewind
    // target and split them.
    let admitted_at_unix_nanos = now_unix_nanos_checked();

    #[allow(clippy::type_complexity)]
    let flipped: Option<(
        i64,
        i64,
        String,
        i64,
        Option<i64>,
        String,
        Option<Vec<u8>>,
        i64,
        Option<String>,
        Option<i64>,
        i64,
        Option<Vec<u8>>,
        String,
    )> = tx
        .query_row(
            "UPDATE files SET state = CASE WHEN deleted = 0 AND ?3 = 1 THEN 'trashed' ELSE 'superseded' END
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'
             RETURNING version_seq, deleted, materialization_state, pinned, last_accessed_unix,
                       record_kind, symlink_target, unix_mode, held_reason, held_since_unix_nanos,
                       symlink_out_of_root, authoring_change_hash, xattrs_json",
            rusqlite::params![group_id, record.path, record.deleted as i64],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                ))
            },
        )
        .optional()?;

    match flipped {
        None => {
            // No current row: a brand new path, or one whose rows are all
            // history. A base install leaves the latter where the path's
            // row moved away -- a leaf relocated to its copy name when the
            // path became a directory, or a row the base keeps only as
            // history -- so the new version is numbered after whatever the
            // path already has, never as its first.
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, authoring_change_hash, admitted_at_unix_nanos)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                         (SELECT COALESCE(MAX(version_seq), 0) + 1 FROM files
                           WHERE group_id = ?1 AND path = ?2),
                         'current', ?7, ?8, ?9)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                    authoring_blob,
                    admitted_at_unix_nanos,
                ],
            )?;
        }
        // The `apply_incoming_wire_metadata` bootstrap scaffold
        // (`version_seq = 0`, created by `ensure_bootstrap_row_for_metadata`)
        // was never a genuine observed version — the `UPDATE` above
        // incorrectly flipped it to superseded/trashed as a side effect of
        // matching `state = 'current'`; undo that and promote it to
        // version 1 in place (an `UPDATE`, not a fresh `INSERT`, so
        // whatever `record_kind`/`symlink_target`/`unix_mode`/etc. its own
        // setters already wrote onto it survives untouched) instead of
        // leaving a spurious empty first version in this path's history.
        // The scaffold exists exactly when the path has no current row,
        // which includes a path that holds only history (a merged base
        // that made it structural, a relocation's source): the promoted
        // row is numbered after that history, never as version 1.
        // Rare (a scaffold row exists for at most the moment between its
        // own creation and this call), so the extra round trip here
        // doesn't cost the common case anything.
        Some((0, ..)) => {
            tx.execute(
                "UPDATE files SET size = ?1, mtime_unix_nanos = ?2, blocks_json = ?3, deleted = ?4,
                        version_seq = (SELECT COALESCE(MAX(version_seq), 0) + 1 FROM files
                                        WHERE group_id = ?8 AND path = ?9),
                        state = 'current', origin_device_id = ?5, authoring_change_hash = ?6, admitted_at_unix_nanos = ?7
                 WHERE group_id = ?8 AND path = ?9 AND version_seq = 0",
                rusqlite::params![
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                    authoring_blob,
                    admitted_at_unix_nanos,
                    group_id,
                    record.path,
                ],
            )?;
        }
        Some((
            old_seq,
            old_deleted,
            materialization_state,
            pinned,
            last_accessed_unix,
            record_kind,
            symlink_target,
            unix_mode,
            held_reason,
            held_since_unix_nanos,
            symlink_out_of_root,
            authoring_change_hash,
            xattrs_json_carried,
        )) => {
            // Every per-file column `FileRecord` doesn't carry
            // (materialization state, pinned, record kind, symlink target,
            // exec bit, extended attributes, held state) is copied forward
            // from the row just superseded — already in hand from the
            // `RETURNING` above, no extra read needed — so a version bump
            // alone never silently resets any of them to their column
            // defaults. Which new `state` the old row ended up as
            // (`trashed` vs `superseded`) was already decided by the `CASE`
            // in the `UPDATE` above.
            //
            // `materialization_state` specifically is an explicit CARRY-
            // FORWARD, not a missing-column case -- the schema's own
            // default (`'placeholder'` as of v25, see `SCHEMA_VERSION`'s
            // doc comment) never applies here, so it cannot protect this
            // branch the way it protects a genuinely brand-new path's
            // first-ever row below. Carrying `Hydrated` forward onto a
            // version bump whose NEW content is not yet confirmed on disk
            // reintroduces the identical "claims Hydrated with nothing to
            // back it up" bug this whole file's callers exist to avoid --
            // it is the caller's job, not this function's, to correct this
            // afterward (in the SAME transaction, same as `stamp_hydrated_
            // after_local_emission_in_tx` does for local emission) whenever
            // the new content is not already known-present. Every current
            // production caller either IS local emission (does correct it,
            // via that stamp), or is `materialize`/`materialize_symlink_at`
            // in `yadorilink-peer-session`, each of which already performs
            // its own explicit, targeted correction (a hazard hold or a
            // policy-skipped symlink demotes to `Placeholder`; the
            // content-identical fast path only reaches this branch after
            // verifying the disk bytes already match, so the carried-
            // forward value is factually correct, not a guess) -- verified
            // by enumerating every non-test caller of this function's own
            // wrappers, not assumed. A FUTURE caller that upserts an
            // existing row for content it has not itself verified is
            // already on disk MUST perform the same explicit correction;
            // this carry-forward alone is not a safe default for it.
            if record.deleted && old_deleted == 0 {
                stamp_trashed_row_operation(
                    tx,
                    group_id,
                    &record.path,
                    old_seq,
                    authoring_change_hash_arg,
                )?;
            }
            tx.execute(
                "INSERT INTO files (
                    group_id, path, size, mtime_unix_nanos, blocks_json, deleted,
                    version_seq, state, origin_device_id,
                    materialization_state, pinned, last_accessed_unix, record_kind,
                    symlink_target, unix_mode, held_reason, held_since_unix_nanos,
                    symlink_out_of_root, authoring_change_hash, xattrs_json,
                    admitted_at_unix_nanos
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'current', ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    old_seq + 1,
                    origin,
                    materialization_state,
                    pinned,
                    last_accessed_unix,
                    record_kind,
                    symlink_target,
                    unix_mode,
                    held_reason,
                    held_since_unix_nanos,
                    symlink_out_of_root,
                    authoring_blob.or(authoring_change_hash.as_deref()),
                    xattrs_json_carried,
                    // NOT carried forward from the row just superseded --
                    // this is a NEW admission of a NEW version, and its
                    // admission time is now, not the previous version's.
                    admitted_at_unix_nanos,
                ],
            )?;
        }
    }
    Ok(())
}

/// Writes a path's local metadata columns (record kind, symlink target /
/// out-of-root flag, exec bit) inside `tx`, the SAME transaction that just
/// wrote its `current` row via [`upsert_file_in_tx`]. This is the atomic,
/// in-transaction counterpart to the standalone `set_record_kind`/
/// `set_symlink_target`/`set_symlink_out_of_root`/`set_unix_mode` setters — it
/// must run strictly after `upsert_file_in_tx` (these are `UPDATE`s and need
/// the row to already exist), so the index columns and the emitted change's
/// `FileVersion` commit as one unit.
pub fn apply_local_meta_columns_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    meta: &LocalFileMetaColumns,
) -> Result<(), SyncSqliteError> {
    let unix_mode_stored: i64 = encode_unix_mode_column(meta.unix_mode);
    let xattrs_json = encode_xattrs_column(&meta.xattrs);
    tx.execute(
        "UPDATE files SET record_kind = ?1, symlink_target = ?2, symlink_out_of_root = ?3, unix_mode = ?4, xattrs_json = ?5
         WHERE group_id = ?6 AND path = ?7 AND state = 'current'",
        rusqlite::params![
            meta.record_kind.as_db_str(),
            meta.symlink_target,
            meta.symlink_out_of_root as i64,
            unix_mode_stored,
            xattrs_json,
            group_id,
            path,
        ],
    )?;
    Ok(())
}

/// Stamps `Hydrated` on a just-locally-authored, non-deleted row, in the
/// SAME transaction as its index/change commit -- the explicit counterpart
/// to `files.materialization_state`'s schema-level default
/// (`'placeholder'` as of schema v25; see that column's own migration
/// comment for the full reasoning). A schema default fires for ANY insert
/// that omits the column, including ones this device has no evidence about
/// (a peer's incoming record, a hazard hold, a policy skip) -- those must
/// default to `Placeholder` and earn `Hydrated` only once real content is
/// confirmed. Called only for `!record.deleted` -- a tombstone has no
/// materialized content to claim, and its own row's
/// `materialization_state` is moot.
pub fn stamp_hydrated_after_local_emission_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "UPDATE files SET materialization_state = ?1 \
         WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
        rusqlite::params![MaterializationState::Hydrated.as_db_str(), group_id, path],
    )?;
    Ok(())
}

/// What the initial import observed on disk for one path, so the
/// transaction that puts that path into history can also record the proof
/// that the path is already materialized.
///
/// The same idea as [`LocalCaptureActualStateEvidence`], for the one
/// capture path that is not a live edit: an import of files that were
/// already sitting in the folder when it was linked. Those files are
/// already correct on disk -- nothing has to be fetched or written to
/// make them so -- and without a proof saying that, this device has no
/// way to conclude it, so it waits for a peer to tell it something it
/// already knows.
#[derive(Clone, Debug)]
pub struct ImportedActualState {
    pub filesystem_identity: yadorilink_root_authority::fs_identity::FileIdentity,
    pub record_kind: RecordKind,
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
}

/// What actual-state evidence local capture has for one already-prepared
/// batch mutation, if any -- see `adopt_local_capture_actual_state`/
/// `adopt_observed_actual_generation_in_tx`'s own doc comments for the
/// full design. No evidence for a path means: commit the Change/index
/// exactly as before, publish no proof -- never a correctness
/// requirement, only a forgone optimization.
#[derive(Clone, Debug)]
pub enum LocalCaptureActualStateEvidence {
    /// A present object this capture just authored: `filesystem_identity`
    /// must be freshly observed from the real path, immediately before
    /// the batch commit, under the path's lock -- not reused from an
    /// earlier prepare-time observation without a fresh disk-fingerprint
    /// match confirming nothing changed since.
    Present { filesystem_identity: yadorilink_root_authority::fs_identity::FileIdentity },
    /// A deletion local capture just observed and revalidated as still
    /// absent immediately before this commit.
    Absent,
}

/// Adopts a just-locally-authored path's actual state, in the SAME
/// transaction as the local Change/index commit that produced it -- see
/// `materialized_generation::adopt_observed_actual_generation_in_tx`'s own
/// doc comment for the full design (why this differs from an internal
/// mutator's bump-then-mutate-then-CAS ordering, and the external-writer
/// consistency boundary this proof is exact relative to).
///
/// `causal_basis` is read fresh from `tx` (the group's actual current
/// heads, AFTER this call's own just-emitted change has been admitted),
/// never assumed -- today's local-emission path always chains onto the
/// group's prior head, producing a basis of exactly `[change_hash]`, but
/// this reads the real thing rather than hard-coding that shape, so it
/// stays correct if that ever changes.
///
/// `object_kind`/`version` describe a PRESENT object; there is no
/// `Absent` case here -- a locally observed deletion is a structurally
/// different call (no version, no filesystem identity, kind `Absent`),
/// handled at its own call site, not through this present-only helper.
///
/// # Race/crash arguments (mandatory regression list, items B/C/F/G)
///
/// Items A/D/E of that list are exercised as real tests (disk-changes-
/// mid-prepare, second-edit supersession, delete). B/C/F/G are argued here
/// instead, per the same list's own allowance to prove a structural
/// call-graph/lock property rather than write a test for an interleaving
/// the design makes impossible:
///
/// - **B (a concurrent internal mutator advances E while local capture is
///   mid-flight)**: cannot interleave with this call. Both an internal
///   mutator's [`materialized_generation::bump_mutation_fence`] and this
///   path's own call into [`materialized_generation::
///   adopt_observed_actual_generation_in_tx`] happen only under the same
///   path lock local capture already holds for the whole prepare-through-
///   commit window (see the call site's own lock-scope comments), and the
///   fence bump plus generation write both happen inside one SQLite
///   `IMMEDIATE` transaction (`write_immediate`), so a second writer for
///   the same `(group_id, path)` blocks at the SQLite layer until this
///   transaction commits or aborts -- there is no window in which a
///   concurrent bump can land between this call's own bump and its own
///   write. A stale local proof from a *prior* completed transaction is
///   simply never written in the first place, because the row this call
///   writes always carries the epoch it just minted, not an older one.
/// - **C (a new admission lands after this proof publishes)**: not
///   prevented by locking -- allowed to happen, and handled by the
///   pre-existing, unchanged mechanism: [`materialized_generation::
///   lookup_materialized_generation`] is a fail-closed CAS read that
///   requires `published_under_mutation_generation` to still equal the
///   live fence value. A subsequent admission that mutates the same path
///   goes through the ordinary internal-mutator path, which bumps the
///   fence again before its own mutation -- at that instant this call's
///   row's captured epoch stops matching the live fence, so the lookup
///   used by zero-work settlement stops returning it (reads as absent, not
///   as a stale hit). Nothing added by this function weakens that
///   existing guarantee; it only ever produces rows that participate in
///   it.
/// - **F (crash before this transaction's commit)**: `write_immediate`'s
///   underlying `BEGIN IMMEDIATE ... COMMIT` is SQLite's own atomic unit --
///   a crash before `COMMIT` leaves neither the fence bump, the generation
///   row, nor the admitted local Change durable, because none of the
///   transaction's writes are visible outside it until commit succeeds.
///   The dirty-journal entry that triggered this capture in the first
///   place was written before the transaction started and survives
///   untouched, so the ordinary local-capture re-drive path picks the path
///   back up exactly as if this attempt never happened. No new failure
///   mode: this is the same atomicity every other `write_immediate` caller
///   in this file already relies on.
/// - **G (commit succeeds, but clearing the dirty-journal entry fails or
///   is delayed)**: the generation row and the admitted Change are now
///   durable; a redundant re-drive later observes the same disk state,
///   revalidates it (fingerprint/index/identity all still match), and
///   this function runs again -- `bump_mutation_fence` mints a new epoch,
///   `write_generation_row` writes a new row under it, replacing the
///   prior one (see `materialized_generation`'s "Immutability" doc: a row
///   is always replaced whole, never edited in place). The redundant
///   proof is content-identical to the one it replaces (same
///   `resolved_path_state_hash`, since content and kind are unchanged),
///   so this is idempotent from zero-work settlement's point of view --
///   a second, unnecessary proof publication, never an incorrect one.
///
/// `version_hash` is by value, not `Option`, and that is the whole point
/// of the parameter rather than a convention: a present object with no
/// version is a proof that matches no desired resolution at all --
/// `resolved_path_state_hash` encodes version presence -- so it cannot
/// close anything, while looking healthy enough to stop a repair pass
/// from noticing. Every caller here has the exact version in hand,
/// because the same transaction is committing it.
pub fn adopt_local_capture_actual_state(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    record_kind: RecordKind,
    version_hash: &yadorilink_replica_domain::ids::VersionHash,
    filesystem_identity: &yadorilink_root_authority::fs_identity::FileIdentity,
) -> Result<(), SyncSqliteError> {
    let object_kind = match record_kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    };
    let causal_basis = dag_store::group_heads(tx, group_id)?;
    crate::materialized_generation::adopt_observed_actual_generation_in_tx(
        tx,
        group_id,
        path,
        &causal_basis,
        object_kind,
        Some(version_hash),
        Some(filesystem_identity),
        now_unix_nanos(),
    )?;
    Ok(())
}

/// Absent-object counterpart to [`adopt_local_capture_actual_state`]: a
/// locally observed deletion, revalidated as still absent by the caller
/// immediately before this same transaction. Absence is a first-class
/// materialized generation exactly like a present object -- see
/// `materialized_generation`'s own module doc, "Absence is a generation
/// too" -- so this commits `MaterializedObjectKind::Absent`, no version,
/// no filesystem identity, causal basis read fresh post-emission exactly
/// like the present case.
/// Closes the projection obligation a locally-observed deletion opens, in
/// the SAME transaction as the `Delete` change and the `Absent` proof that
/// justify closing it.
///
/// A deletion this device observed on its own disk is the one case where
/// nothing downstream will close the obligation for it. The Convergence
/// Engine's zero-work pre-check declines an `Absent` resolution outright
/// (a delete is meant to be handled by projecting it), and the projection
/// itself does nothing for a path whose index row this same commit already
/// tombstoned -- correctly, since there is nothing to remove -- so it
/// produces no evidence to close against either. The obligation then
/// retries forever, and on a device with no peer nothing else ever
/// touches it.
///
/// Closing it here is not a shortcut around that machinery: it is the
/// same close, made at the only moment the work it describes is provably
/// already done. The caller revalidated absence under this path's lock and
/// holds that lock through this commit, [`adopt_local_capture_absent_
/// state`] has just published the matching `Absent` generation under a
/// fresh fence epoch, and the CAS below re-reads both the obligation and
/// that generation from this same transaction -- it can only close an
/// obligation whose desired state is exactly the absence just proven.
///
/// A parked `ignore_blocked` row is left alone: it is not an outstanding
/// unit of work but a durable marker that a later un-ignore has to re-arm
/// (see [`crate::projection_obligations::NonExactProofKind::
/// IgnoreExcluded`]), and deleting it here would erase that.
fn settle_obligation_against_local_absence_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let Some(obligation) =
        crate::projection_obligations::lookup_projection_obligation(tx, group_id, path)?
    else {
        return Ok(());
    };
    if obligation.state != "pending" {
        return Ok(());
    }
    let desired = crate::materialized_generation::compute_resolved_path_state_hash(
        group_id,
        path,
        MaterializedObjectKind::Absent,
        None,
    );
    crate::projection_obligations::complete_obligation_if_exact_proof_current(
        tx,
        group_id,
        path,
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &desired,
    )?;
    Ok(())
}

/// Present-object counterpart to
/// [`settle_obligation_against_local_absence_in_tx`], and the answer to a
/// measured question: a bulk local emission of N paths published N exact
/// actual-state proofs and still left N obligations runnable, because only
/// the absent direction was ever closed here. Every one of those is a wake,
/// a claim and a full desired-state re-derivation for the Convergence
/// Engine, to reach a conclusion this transaction had already proven and
/// written down.
///
/// The justification is the absent case's, unchanged: the caller
/// revalidated the object on disk immediately before this commit (that
/// observation is what produced the change being emitted), holds that
/// observation's fingerprint through it, and
/// [`adopt_local_capture_actual_state`] has just published the matching
/// generation under a fresh fence epoch. `emit_local_change` says the same
/// thing in its own words where it tags this obligation `Local`: the bytes
/// "were already observed on this device's own disk", so the obligation
/// "can never represent content not yet placed locally". That knowledge was
/// already being used to stop a bogus tombstone veto; this uses it to close
/// the obligation it describes.
///
/// Desired state is RESOLVED, never assumed. It would be easy, and wrong,
/// to close against the version this change happens to carry: that assumes
/// our own op wins the path, which a divergent branch or conflict
/// resolution can deny. `desired_path_state` computes what the engine
/// itself would place at the path -- the per-path winner, with the tree
/// constraint of live descendants applied -- inside this transaction and
/// after this change was appended, and the CAS then closes only if the
/// proof just published IS that state. Anything else -- a losing branch, a
/// file a live descendant displaces, a winner whose version this replica
/// cannot resolve -- leaves the
/// obligation exactly where it was, for the engine to handle as it always
/// has. Fail-safe in the direction that matters: the failure mode of this
/// function is "the engine still does the work", never "nobody does".
fn settle_obligation_against_local_presence_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let Some(obligation) =
        crate::projection_obligations::lookup_projection_obligation(tx, group_id, path)?
    else {
        return Ok(());
    };
    if obligation.state != "pending" {
        return Ok(());
    }
    let heads = dag_store::live_path_heads(tx, group_id, path)?;
    // A resolution carrying conflict copies is not satisfied by this path
    // alone: the losing heads still have to be materialized at their own
    // copy paths, and those paths have no obligation of their own (nothing
    // named them in this change's ops). Closing here on the winner's proof
    // would be closing the only row that gets the copies written. A
    // locally-authored emission parents on every current head, so it
    // leaves one live head and cannot produce this -- but "cannot today" is
    // not a reason to let the close depend on it.
    if let yadorilink_replica_engine::conflict::PathResolution::Present {
        conflict_copies, ..
    } = yadorilink_replica_engine::conflict::resolve_path_heads(path, &heads)
    {
        if !conflict_copies.is_empty() {
            return Ok(());
        }
    }
    // The namespace decides what the path must be, not the path's own
    // heads alone: a captured File at a path a live descendant needs is
    // relocated, and the path itself has to be a directory, which the
    // proof this capture just published does not show. Read in this
    // transaction, after this change was appended.
    let desired = match crate::desired_state::desired_path_state(tx, group_id, path) {
        Ok(state) => state,
        // "Not yet resolvable", not "absent" -- see that function's own
        // fail-closed contract. Leave the obligation for the engine.
        Err(SyncSqliteError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    if let crate::desired_state::DesiredPathState::StructuralDirectory = desired {
        // Its relocated entry is owed at a copy name no obligation names.
        return Ok(());
    }
    let desired = desired.resolved_path_state_hash(group_id, path);
    crate::projection_obligations::complete_obligation_if_exact_proof_current(
        tx,
        group_id,
        path,
        obligation.invalidation_generation,
        obligation.obligation_incarnation,
        &desired,
    )?;
    Ok(())
}

fn adopt_local_capture_absent_state(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let causal_basis = dag_store::group_heads(tx, group_id)?;
    crate::materialized_generation::adopt_observed_actual_generation_in_tx(
        tx,
        group_id,
        path,
        &causal_basis,
        MaterializedObjectKind::Absent,
        None,
        None,
        now_unix_nanos(),
    )?;
    // An exactly-absent path holds no content, so it may not also claim to
    // -- the same rule `commit_internal_materialized_state_if_fence_
    // current` applies to its own `Absent` arm. The tombstone row this
    // proof belongs to inherited its predecessor's `materialization_state`
    // (see `upsert_file_in_tx`), and for a path that used to be
    // `Hydrated` that inheritance is now a claim to hold bytes this same
    // transaction has just proven are gone.
    strip_carried_forward_hydrated_in_tx(tx, group_id, path)?;
    Ok(())
}

/// Removes a `Hydrated` claim that [`upsert_file_in_tx`] carried forward
/// onto a row whose content this transaction has NOT proven.
///
/// That carry-forward is deliberate and right for every other per-file
/// column: a version bump must not reset a path's pinning, record kind or
/// exec bit to a schema default. `materialization_state` is the one
/// column where the inherited value is not a property of the path but an
/// assertion about disk -- and on a version bump the new content is
/// exactly what disk does not hold yet. Anything weaker than `Hydrated`
/// is safe to inherit (a `Placeholder` is still a placeholder; a
/// `Hydrating` marker still names an in-flight attempt, whose own
/// `ExpectedAuthoring` guard now fails on the authoring hash this bump
/// just changed), so only the state that asserts exactness is stripped.
fn strip_carried_forward_hydrated_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "UPDATE files SET materialization_state = ?1 \
         WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
           AND materialization_state = ?4",
        rusqlite::params![
            MaterializationState::Placeholder.as_db_str(),
            group_id,
            path,
            MaterializationState::Hydrated.as_db_str(),
        ],
    )?;
    Ok(())
}

/// The other outcome of a transaction that moves a path to a new version
/// (or tombstones it), and the reason [`adopt_local_capture_actual_state`]
/// alone was not enough: what to do when the transaction cannot say what
/// that leaves on disk.
///
/// Doing nothing is not neutral. The row's `Hydrated` is inherited from
/// the version just superseded, and the proof backing it still names that
/// old version and is still current against the path's fence -- so the
/// pair reads as "this path exactly holds its current content" while
/// naming, between them, two different versions. Local capture reaches
/// this whenever its evidence is missing or does not line up with the op
/// it emitted: an editor's write the watcher saw only after the fact, a
/// delete whose absence nobody revalidated under this path's lock, a
/// caller whose ops and versions disagree. A restore reaches it when its
/// own physical write was declined by policy and it observed nothing.
///
/// So the transaction that writes the row also retires the claim and the
/// proof, together with it:
///
/// ```text
/// fence -> a fresh epoch    (every published proof stops being usable)
/// Hydrated -> Placeholder   (the inherited claim goes with it)
/// ```
///
/// Both are conservative in the same direction. The path becomes one that
/// needs hydrating and has no proof, which is the truth: this device
/// knows what the path should be and does not know what it is. Ordinary
/// reconciliation then does the work and publishes real evidence for the
/// result.
pub fn retire_unproven_actual_state_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    crate::materialized_generation::invalidate_published_generations(
        tx,
        group_id,
        path,
        "unproven-new-version",
        now_unix_nanos(),
    )?;
    strip_carried_forward_hydrated_in_tx(tx, group_id, path)?;
    Ok(())
}

/// In-transaction counterpart to [`FileIndexRepository::ensure_bootstrap_
/// row_for_metadata`], for a caller that already has a `tx` open
/// (`apply_incoming_metadata_atomic` and the batched commit path) --
/// same idempotent `INSERT ... WHERE NOT EXISTS`, no separate `writer_
/// gate` acquisition of its own, and the same `admitted_at_unix_nanos`
/// stamp (see [`upsert_file_in_tx`]'s "stamping invariant" section).
pub fn ensure_bootstrap_row_for_metadata_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, admitted_at_unix_nanos)
         SELECT ?1, ?2, 0, 0, '[]', 0, 0, 'current', NULL, ?3
          WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
        rusqlite::params![group_id, path, now_unix_nanos_checked()],
    )?;
    Ok(())
}

/// Shared enumeration of `group_id`'s durability roots over an arbitrary
/// connection (a pooled read connection, or a write transaction for the
/// atomic re-check-and-commit paths). See
/// [`SyncState::enumerate_group_durability_roots`] for the category
/// semantics; keeping the query in one place guarantees the digest the
/// atomic commit re-checks is computed exactly like the one the readiness
/// check first captured.
pub fn enumerate_group_durability_roots_on_conn(
    conn: &Connection,
    group_id: &str,
) -> Result<DurabilityRoots, SyncSqliteError> {
    // `record_kind = 'file'` in the WHERE clause fixes the record kind for
    // every row this returns, so `RecordKind::File` below is not an
    // assumption. `symlink_target` is NOT inferred the same way, even though
    // a regular file has no business carrying one: nothing in the schema
    // forbids the column being set on a `'file'` row, the version hash binds
    // it either way, and the peer that answers a handoff query for one of
    // these roots reconstructs its own version from the column it actually
    // has. Reading it here rather than assuming `None` is what keeps the two
    // reconstructions of one row from disagreeing about its identity.
    let mut stmt = conn.prepare(
        "SELECT path, size, mtime_unix_nanos, blocks_json, unix_mode, xattrs_json, \
                symlink_target FROM files \
         WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
           AND state IN ('current', 'superseded', 'trashed') \
         ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<Vec<u8>>>(6)?,
        ))
    })?;
    let mut roots = Vec::new();
    for row in rows {
        let (path, size, mtime_unix_nanos, blocks_json, unix_mode, xattrs_json, symlink_target) =
            row?;
        // A malformed stored block list is locally-corrupt state — report it as
        // `CorruptState` (like every other malformed-block-list path) rather
        // than letting the bare `?` classify it as a generic `Json`/protocol
        // error.
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "stored block list for {path} is corrupt: {error}"
            ))
        })?;
        // Reconstruct the exact `FileVersion` this row describes and derive
        // its `version_hash` via the SAME `compute_hash()` the change-DAG
        // itself hashes versions with — see `FileVersion::from_index_row`.
        let version = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::File,
            decode_unix_mode_column(unix_mode),
            symlink_target,
            decode_xattrs_column(&xattrs_json)?,
        );
        roots.push(DurabilityRoot {
            path,
            blocks: version.blocks,
            version_hash: version.version_hash,
        });
    }
    let digest = durability_roots_digest(&roots);
    Ok(DurabilityRoots { roots, digest })
}

/// See [`FileIndexRepository::root_set_generation`].
pub fn root_set_generation_on_conn(
    conn: &Connection,
    group_id: &str,
) -> Result<u64, SyncSqliteError> {
    let generation: Option<i64> = conn
        .query_row(
            "SELECT generation FROM file_root_set_generation WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )
        .optional()?;
    // The counter only ever increments from 1, so a negative value cannot
    // be produced by the triggers that maintain it. Clamping rather than
    // erroring keeps this a pure cache key: the worst a nonsense value can
    // do is force a recomputation.
    Ok(generation.unwrap_or(0).max(0) as u64)
}

/// See [`FileIndexRepository::group_root_set_summary`].
///
/// Shares its `WHERE` clause with
/// [`enumerate_group_durability_roots_on_conn`] on purpose: the digest a
/// peer compares must be computed over exactly the rows the handoff proof
/// would enumerate, or the comparison answers a different question than the
/// one it is trusted for. The two queries differ only in which columns they
/// read back.
pub fn group_root_set_summary_on_conn(
    conn: &Connection,
    group_id: &str,
    generation: u64,
) -> Result<RootSetSummary, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, size, mtime_unix_nanos, blocks_json, unix_mode, xattrs_json, \
                symlink_target, state, materialization_state FROM files \
         WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
           AND state IN ('current', 'superseded', 'trashed') \
         ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<Vec<u8>>>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
        ))
    })?;
    let mut roots = Vec::new();
    let mut current = Vec::new();
    let mut unmaterialized_current_count = 0u64;
    for row in rows {
        let (
            path,
            size,
            mtime_unix_nanos,
            blocks_json,
            unix_mode,
            xattrs_json,
            symlink_target,
            state,
            materialization_state,
        ) = row?;
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "stored block list for {path} is corrupt: {error}"
            ))
        })?;
        let version = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::File,
            decode_unix_mode_column(unix_mode),
            symlink_target,
            decode_xattrs_column(&xattrs_json)?,
        );
        let root =
            DurabilityRoot { path, blocks: version.blocks, version_hash: version.version_hash };
        if state == "current" {
            // Anything but `Hydrated` means the content behind this row has
            // not been fetched, or is still being fetched. The row itself
            // exists from the moment its change is projected, which is why
            // counting rows alone would let a device that has downloaded
            // nothing describe itself exactly like one that holds
            // everything.
            if materialization_state != MaterializationState::Hydrated.as_db_str() {
                unmaterialized_current_count += 1;
            }
            current.push(root.clone());
        }
        roots.push(root);
    }
    Ok(RootSetSummary {
        current_digest: durability_roots_digest(&current),
        current_count: current.len() as u64,
        unmaterialized_current_count,
        roots_digest: durability_roots_digest(&roots),
        roots_count: roots.len() as u64,
        generation,
    })
}

/// The fixed, built-in version-retention bounds applied to every link: a
/// superseded or trashed version is retained while it is within *either*
/// bound and expired only once it exceeds *both* (union-retain, intersection-
/// expire). The current/live version is never subject to retention. Retention
/// is not per-link configurable.
pub(crate) const RETENTION_MAX_VERSIONS: i64 = 10;

pub(crate) const RETENTION_MAX_AGE_DAYS: i64 = 30;

#[allow(clippy::too_many_arguments)]
/// Decodes the raw `unix_mode` column value: `-1` (or anything negative) is
/// "no Unix permission info" (see `SCHEMA_VERSION` v23's own doc comment),
/// everything else is masked into the replicated permission bits. Shared
/// between every site that reads this column so a stray sign-handling typo
/// can't diverge between them.
pub(crate) fn decode_unix_mode_column(raw: i64) -> Option<u32> {
    if raw < 0 {
        None
    } else {
        Some(raw as u32 & yadorilink_replica_domain::file::REPLICATED_MODE_MASK)
    }
}

/// The inverse of [`decode_unix_mode_column`].
pub(crate) fn encode_unix_mode_column(unix_mode: Option<u32>) -> i64 {
    match unix_mode {
        None => -1,
        Some(mode) => (mode & yadorilink_replica_domain::file::REPLICATED_MODE_MASK) as i64,
    }
}

/// `files.xattrs_json`'s decoding -- fails closed on a corrupt
/// column (same reasoning as `blocks_json`, see `version_record`'s own
/// comment) rather than silently reading it back as "no attributes,"
/// which would be indistinguishable from a genuinely-empty set.
pub(crate) fn decode_xattrs_column(raw: &str) -> Result<Vec<(String, Vec<u8>)>, SyncSqliteError> {
    serde_json::from_str(raw).map_err(|error| {
        SyncSqliteError::CorruptState(format!("stored xattrs are corrupt: {error}"))
    })
}

/// The inverse of [`decode_xattrs_column`]. Callers are responsible for
/// `xattrs` already being sorted by name (see `FileMeta::xattrs`'s own
/// doc comment) -- this is a plain encode, not a place that re-sorts.
pub(crate) fn encode_xattrs_column(xattrs: &[(String, Vec<u8>)]) -> String {
    serde_json::to_string(xattrs).expect("xattr list is always representable as JSON")
}

// One parameter per SQLite row column this constructs from; grouping into
// a params struct is out of scope for a lint cleanup.
#[allow(clippy::too_many_arguments)]
pub(crate) fn version_record(
    path: String,
    version_seq: i64,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
    state: &str,
    origin_device_id: Option<String>,
    record_kind: &str,
    symlink_target: Option<Vec<u8>>,
    unix_mode: i64,
    xattrs_json: &str,
) -> Result<VersionRecord, SyncSqliteError> {
    // Fail closed on a corrupt `blocks_json` column rather than coercing it to
    // an empty block list. A silent default would mask genuine index/DB
    // corruption as a legitimately empty version; a valid `"[]"` still parses
    // to an empty list and stays a valid empty record — only an unparseable
    // column errors. Log the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list for a retained version is corrupt; failing closed");
        SyncSqliteError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    let record_kind = RecordKind::from_db_str(record_kind);
    let unix_mode = decode_unix_mode_column(unix_mode);
    let xattrs = decode_xattrs_column(xattrs_json)?;
    // Derive this exact row's `version_hash` the same way the durability-root
    // enumeration does — reconstruct the `FileVersion` this row describes and
    // hash it via `compute_hash()` — so a caller comparing a peer's queried
    // hash against this field is comparing against the canonical identity,
    // never a value re-derived from a different subset of columns.
    let version_hash = FileVersion::from_index_row(
        blocks.clone(),
        size,
        mtime_unix_nanos,
        record_kind,
        unix_mode,
        symlink_target.clone(),
        xattrs.clone(),
    )
    .version_hash;
    let state = VersionState::try_from_db_str(state)
        .map_err(|e| SyncSqliteError::InvalidInput(format!("{path}: {e}")))?;
    Ok(VersionRecord {
        path,
        version_seq,
        size,
        mtime_unix_nanos,
        blocks,
        deleted: deleted != 0,
        state,
        origin_device_id,
        record_kind,
        symlink_target,
        unix_mode,
        xattrs,
        version_hash,
    })
}

pub(crate) fn row_to_record(
    path: String,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
) -> Result<FileRecord, SyncSqliteError> {
    // Fail closed on a corrupt stored block list rather than coercing it to a
    // default: a defaulted (empty) block list would read as "file has no
    // content" and mask genuine index/DB corruption. A valid `"[]"` still
    // parses to a valid empty record; only an unparseable column errors. Log
    // the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list is corrupt; failing closed");
        SyncSqliteError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    Ok(FileRecord { path, size, mtime_unix_nanos, blocks, deleted: deleted != 0 })
}

/// Regression coverage for the retirement/authoring-identity interaction
/// (exercised end to end by `multiway_conflict_matrix.rs`'s multi-device
/// staggered rows): `retire_unjustified_ephemeral_conflict_copies`
/// (`yadorilink-peer-session`'s `local_convergence.rs`) retires a purely
/// local, non-DAG-backed conflict copy -- one no admitted change has ever
/// touched. A `materialize_tombstone` with `authoring_change_hash: None`
/// would go through `upsert_file_with_origin` (a fresh 'current' row
/// asserting no authoring identity), which `yadorilink-sqlite-runtime`'s
/// `files_require_authoring_identity_on_*` triggers reject outright once
/// the group has ANY admitted DAG history. Because `std::fs::remove_file`
/// runs before this index write and is never rolled back, the on-disk file
/// would be gone while the index update that records the deletion kept
/// aborting -- a path stuck between "physically gone" and "still current"
/// in the index. So that one call goes through `remove_file` instead (an erasure, not a tombstone
/// -- see its own doc
/// comment, and `erase_local_only_file`'s in `yadorilink-peer-session`'s
/// `ports/peer_replica_state.rs`), which needs no authoring identity at all
/// because it asserts no DAG fact.
#[cfg(test)]
mod ephemeral_conflict_copy_retirement_tests;

/// The invariant every local-capture writer in this module now upholds:
///
/// > if a current row is observable as `Hydrated`, a usable actual-state
/// > proof exists naming that row's own version.
///
/// The half these tests cover is the one that was missing.
/// `upsert_file_in_tx` carries `materialization_state` forward from the row
/// it supersedes -- deliberately, so a version bump never resets a path's
/// local columns to their schema defaults -- which means stamping
/// `Hydrated` only where a proof is published is enough for a brand-new
/// row and not enough for an existing one. A path that was `Hydrated` at
/// V1 stayed `Hydrated` at V2 by inheritance, with V1's proof still
/// current against the fence: two records of one path naming two different
/// versions, and the pair reading as "exactly materialized". A tombstone
/// inherited the same way, so an observed deletion could leave the
/// path's last present proof readable as the truth about a file that is
/// gone.
#[cfg(test)]
mod local_capture_proof_invariant_tests;

/// Which versions of an indexed path a local write with no known basis may
/// claim as its causal past.
#[cfg(test)]
mod local_write_parent_tests;

/// A trashed row remembers the recursive operation that deleted it, so a
/// folder restore can find every file one `rm -rf` removed without the
/// deleting changes.
#[cfg(test)]
mod recursive_operation_trash_tests;

/// The trash and conflict listings report each row's own kind.
#[cfg(test)]
mod entry_kind_listing_tests;

/// A pinned directory keeps what is below it, now and later, pinned.
#[cfg(test)]
mod pinned_directory_tests;

/// SQL that is true when the `pinned_directories` row aliased `p` covers
/// the path `path_expr`: the link root, anything below the directory, and
/// the entry at the directory's own path only while `is_directory_expr`
/// says it is a directory -- a file that later takes a pinned folder's
/// name is not kept by the folder's policy. Compared by prefix length
/// rather than `LIKE`, which would read `%` and `_` in a directory name as
/// wildcards.
pub(crate) fn pinned_directory_covers_sql(path_expr: &str, is_directory_expr: &str) -> String {
    format!(
        "(p.prefix = '' OR ({path_expr} = p.prefix AND {is_directory_expr}) OR \
         substr({path_expr}, 1, length(p.prefix) + 1) = p.prefix || '/')"
    )
}

/// Whether a pinned directory covers `path`, reading the entry at `path`
/// as a directory unless a live non-directory row is there.
fn directory_pin_covers(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    Ok(conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM pinned_directories p WHERE p.group_id = ?1 AND {})",
            pinned_directory_covers_sql(
                "?2",
                "NOT EXISTS (SELECT 1 FROM files f WHERE f.group_id = ?1 AND f.path = ?2 AND \
                 f.state = 'current' AND f.deleted = 0 AND f.record_kind <> 'directory')"
            )
        ),
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )?)
}
