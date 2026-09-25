//! Owner operations for the daemon's convergence lanes.
//!
//! Each method is the "open" half of a lane's protocol: the durable steps
//! that run before the lane's physical write. The write itself, and every
//! lane check between these steps and the write (target verification,
//! preflight, the fence bump that follows it), stay in the lane.

use std::collections::BTreeMap;
use std::sync::Arc;

use yadorilink_filesystem_sync::materialization_execution::MaterializationIntentKind;
use yadorilink_peer_session::ports::OpenMaterializationIntent;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};

use super::super::ReplicaCoordinator;

/// Resolves the root lease a row persist starts its own, fresh root
/// operation under. Called at the moment of the persist, never earlier:
/// a link that stops after the intent opened must still refuse the row.
pub(crate) type RowAuthority<'a> = &'a dyn Fn() -> Result<Arc<RootLease>, PeerSessionError>;

/// A materialization intent a lane holds across its physical write.
pub(crate) type LaneIntent<'a> = Box<dyn OpenMaterializationIntent + Send + 'a>;

/// The target a tombstone delete's intent names. A delete has no content to
/// name, so the target is a marker, and one no content can have: every
/// content target is a 32-byte SHA-256, this is not 32 bytes. The hash of
/// an empty block list would not do, since that is also the ordinary target
/// of an empty file. Only this module reads or writes it; everything else
/// sees [`MaterializationIntentKind`].
const TOMBSTONE_DELETE_INTENT_TARGET: &[u8] = b"yadorilink:tombstone-delete";

impl ReplicaCoordinator {
    /// Writes `record` into the index with its origin, and its authoring
    /// identity when one is known, under a root operation begun from
    /// `row_authority` right now, in its own transaction.
    pub(crate) fn persist_row_under_fresh_operation(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        row_authority: RowAuthority<'_>,
    ) -> Result<(), PeerSessionError> {
        let authority = row_authority()?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        match authoring_change_hash {
            Some(hash) => self.upsert_file_with_origin_and_author(
                group_id,
                record,
                origin_device_id,
                hash,
                &permit,
            ),
            None => self.upsert_file_with_origin(group_id, record, origin_device_id, &permit),
        }
    }

    /// The journaled row commit every regular-file write opens with:
    /// durably open this record's materialization intent (tx), then commit
    /// its row under a fresh root operation (tx), so a crash between the
    /// row and the file never leaves an indexed path with no file and no
    /// intent.
    fn open_intent_and_persist_row<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        row_authority: RowAuthority<'_>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<LaneIntent<'a>, PeerSessionError> {
        let intent_target_hash = yadorilink_local_storage::intent_target_hash(&record.blocks);
        let intent_guard = self.open_materialization_intent_guard(
            group_id,
            &record.path,
            &intent_target_hash,
            permit,
        )?;
        self.persist_row_under_fresh_operation(
            group_id,
            record,
            origin_device_id,
            authoring_change_hash,
            row_authority,
        )?;
        Ok(intent_guard)
    }

    /// Open half of the eager/pinned content write: open the intent
    /// (tx), persist the row (tx), mark the row in flight (tx), and clear
    /// any hazard hold (tx). Returns the intent the lane holds across the
    /// write; the lane verifies the target, preflights, and bumps the fence
    /// afterwards.
    pub(crate) fn open_content_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        row_authority: RowAuthority<'_>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<LaneIntent<'a>, PeerSessionError> {
        let intent_guard = self.open_intent_and_persist_row(
            group_id,
            record,
            origin_device_id,
            authoring_change_hash,
            row_authority,
            permit,
        )?;
        // Explicitly the in-flight state, NOT `Hydrated`: the intent is what
        // makes the row-before-file ordering safe across a crash, and the
        // bytes are still nowhere at this point.
        self.set_materialization_state(
            group_id,
            &record.path,
            yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
            permit,
        )?;
        // Invariant (the whole point of the seam): a content row is never
        // committed for a not-yet-written file without a preceding durable
        // intent. Any future edit that reorders or drops the open above
        // trips this in debug/test builds.
        debug_assert!(
            self.has_materialization_intent(group_id, &record.path).unwrap_or(false),
            "materialize committed a content row with a pending file write but no open \
             materialization intent — the journaled write seam was bypassed"
        );
        self.clear_held(group_id, &record.path)?;
        Ok(intent_guard)
    }

    /// Open half of a fresh placeholder write, for the on-demand lane and
    /// for the eager lane's incomplete-content arm: open the intent (tx),
    /// persist the row (tx),
    /// clear any hazard hold (tx, no permit), and demote the row to
    /// `Placeholder` (tx). The lane then verifies the target, bumps the
    /// fence and writes the placeholder (`write_placeholder`).
    ///
    /// Not the eager lane's reconstruct-failed demotion: that one enters
    /// from `Hydrating` after a real write attempt, clears no hold, and
    /// stays a single state set in the lane.
    pub(crate) fn open_placeholder_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        row_authority: RowAuthority<'_>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<LaneIntent<'a>, PeerSessionError> {
        let intent_guard = self.open_intent_and_persist_row(
            group_id,
            record,
            origin_device_id,
            authoring_change_hash,
            row_authority,
            permit,
        )?;
        self.clear_held(group_id, &record.path)?;
        self.set_materialization_state(
            group_id,
            &record.path,
            MaterializationState::Placeholder,
            permit,
        )?;
        Ok(intent_guard)
    }

    /// Symlink lane, leaving a hazard hold: a held row is `Placeholder`
    /// with `held_reason` set, and the SET `held_reason` is itself what
    /// protects it from the tombstone loop while held. So when the path was
    /// held (a read), an intent naming `intent_target_hash` is opened (tx)
    /// BEFORE the hold is cleared (tx), and handed back for the lane to
    /// keep, uncleared, until it returns: a `PolicySkipped` or failure exit
    /// then still leaves the row protected. Not opened when the path was
    /// never held, so an unheld retry writes no intent.
    ///
    /// The symlink lane's own step, not a shared release: convergence
    /// rehydration leaves a hold differently.
    pub(crate) fn release_symlink_hold_under_intent<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        intent_target_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Option<LaneIntent<'a>>, PeerSessionError> {
        let was_held = self.get_held_state(group_id, path)?.is_some();
        let pre_clear_hold_intent_guard = if was_held {
            Some(self.open_materialization_intent_guard(
                group_id,
                path,
                intent_target_hash,
                permit,
            )?)
        } else {
            None
        };
        self.clear_held(group_id, path)?;
        Ok(pre_clear_hold_intent_guard)
    }

    /// Open half of a symlink write (`materialize_symlink_at`). When there
    /// is a `write_target` (the caller decided the link will really be
    /// written): bump the fence (tx), then open the intent naming the
    /// target (tx). Then upsert the row (tx) unless this exact authored
    /// version is already current (a read), and, for a real write, mark the
    /// row in flight (tx). Returns the fence value and the intent for a
    /// real write, `None` for a policy skip (which still upserts).
    pub(crate) fn open_symlink_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        write_target: Option<&[u8]>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Option<(i64, LaneIntent<'a>)>, PeerSessionError> {
        self.open_single_object_write(
            group_id,
            record,
            origin_device_id,
            authoring_change_hash,
            write_target,
            "symlink_write",
            permit,
        )
    }

    /// Open half of an explicit directory's write (the directory lane):
    /// exactly [`Self::open_symlink_write`]'s steps for an object with no
    /// content -- bump the fence (tx), open the intent (tx), upsert the row
    /// unless this authored version is already current, mark it in flight
    /// (tx). The intent names the empty content, which classifies it as a
    /// write, so repair recreates a directory it finds missing under it.
    pub(crate) fn open_directory_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(i64, LaneIntent<'a>), PeerSessionError> {
        self.open_single_object_write(
            group_id,
            record,
            origin_device_id,
            authoring_change_hash,
            Some(&[]),
            "directory_write",
            permit,
        )?
        .ok_or_else(|| {
            PeerSessionError::CorruptState(format!(
                "{}: a directory write opened no intent",
                record.path
            ))
        })
    }

    /// Settle half of an explicit directory's write: the exact proof for
    /// `version` with the identity observed at `out_path`, the `Hydrated`
    /// stamp and the intent clear, in one transaction guarded on the fence
    /// value the open returned and on the row still being this authored
    /// version in flight. On success the path holds an entry again, so a
    /// retained record for it (a directory kept after an earlier delete)
    /// is released. `false` when the commit was refused: nothing was
    /// written and the intent stays open.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_directory_write(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: VersionHash,
        authoring_change_hash: Option<&ChangeHash>,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, PeerSessionError> {
        let identity =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(out_path).ok();
        let committed = self.commit_internal_materialized_state_if_fence_current(
            group_id,
            path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::Directory,
                version,
                identity: Box::new(identity),
            },
            mutation_generation,
            Some(yadorilink_peer_session::ports::ExpectedAuthoring {
                state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                authoring_change_hash,
                expected_version: Some(&version),
            }),
            permit,
        )?;
        if committed {
            self.release_retained_directory(group_id, path)
                .map_err(crate::sync_error::SyncError::from)?;
        }
        Ok(committed)
    }

    /// The shared open half of a single-object write with no block
    /// content (a symlink, an explicit directory). See
    /// [`Self::open_symlink_write`].
    #[allow(clippy::too_many_arguments)]
    fn open_single_object_write<'a>(
        &'a self,
        group_id: &'a str,
        record: &'a FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        write_target: Option<&[u8]>,
        fence_reason: &'static str,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Option<(i64, LaneIntent<'a>)>, PeerSessionError> {
        let opened = match write_target {
            Some(target) => {
                let mutation_generation =
                    self.dag_bump_mutation_fence(group_id, &record.path, fence_reason)?;
                let target_hash = yadorilink_local_storage::intent_target_hash_for_bytes(target);
                let intent_guard = self.open_materialization_intent_guard(
                    group_id,
                    &record.path,
                    &target_hash,
                    permit,
                )?;
                Some((mutation_generation, intent_guard))
            }
            None => None,
        };

        // A permanently policy-skipped symlink (no target recorded, or a
        // Windows peer that has not opted in) retries this whole write on a
        // capped backoff that is never dead-lettered -- every retry used to
        // unconditionally re-upsert `record` even when nothing had changed
        // since the previous attempt. `upsert_file_in_tx`'s own `INSERT` is
        // unconditional too: it flips the current row to `superseded`/
        // `trashed` and inserts a fresh `version_seq` row every single call,
        // so a long-lived policy skip accumulated an unbounded number of
        // these no-op version rows over the process's lifetime -- purely
        // from retrying, with the actual desired state never once changing.
        // Skip the upsert when this exact authored version is already the
        // current one; whether this is a real write is unaffected either
        // way.
        // `is_some_and` means a `None` `authoring_change_hash` always yields
        // `false` here -- a caller with no authoring hash to compare against
        // gets no dedup at all, and still accumulates a version row on every
        // retry exactly as before this fix. At least one caller does pass
        // `None` (the tombstone-materialize call in the deletion path) --
        // not confirmed reachable for a retry-prone policy-skipped SYMLINK
        // specifically (a tombstone is `record.deleted`, a different
        // dispatch branch), but not proven unreachable either.
        let already_current = authoring_change_hash.is_some_and(|hash| {
            self.get_authoring_change_hash(group_id, &record.path).ok().flatten().as_ref()
                == Some(hash)
        });
        if !already_current {
            match authoring_change_hash {
                Some(hash) => self.upsert_file_with_origin_and_author(
                    group_id,
                    record,
                    origin_device_id,
                    hash,
                    permit,
                )?,
                None => self.upsert_file_with_origin(group_id, record, origin_device_id, permit)?,
            }
        }

        // The row this write targets is established; mark it as a
        // materialization in flight before the syscall, and leave the exact
        // claim to the commit that can prove it. `upsert_file_with_origin`
        // above carries the previous version's `materialization_state`
        // forward, so an existing `Hydrated` symlink would otherwise still
        // read `Hydrated` here -- with its old proof already dead, because
        // the fence was bumped above, and the new one not yet published.
        // Same discipline the projected-upserts batch uses, for the same
        // window.
        if opened.is_some() {
            self.set_materialization_state(
                group_id,
                &record.path,
                yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                permit,
            )?;
        }
        Ok(opened)
    }

    /// The hazard hold (`hold_record`): adopt `record` into the index with
    /// its origin and author (tx), demote the row to `Placeholder` (tx),
    /// and mark it held with `reason` (tx, no permit). Three transactions,
    /// in that order; nothing is written on disk under any name.
    ///
    /// Not the tombstone lane's or rehydration's hold, which set the held
    /// marker without touching the row.
    pub(crate) fn hold_row_for_hazard(
        &self,
        group_id: &str,
        record: &FileRecord,
        reason: &str,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        match authoring_change_hash {
            Some(hash) => self.upsert_file_with_origin_and_author(
                group_id,
                record,
                origin_device_id,
                hash,
                permit,
            )?,
            None => self.upsert_file_with_origin(group_id, record, origin_device_id, permit)?,
        }
        // A held row is, by definition, "not materialized under any name on
        // this device" -- the upsert above leaves `materialization_state` at
        // its schema default of `Hydrated`, which is wrong the instant the
        // row becomes held, not just eventually. Left at `Hydrated`, the
        // periodic repair sweep reads this row (nothing on disk, no
        // materialization intent) as an offline deletion and journals it
        // dirty; the always-running dirty-journal redrive then emits a real,
        // propagating tombstone Change for a path this device never actually
        // deleted. This is reachable on every platform (unlike the
        // Windows-symlink-policy case): a brand-new hazard hold hits it
        // immediately, with no materialize/PolicySkipped round trip needed
        // first. Matches `hydrate_file_with_timeout_locked`'s own
        // hazard-hold outcome, which reverts to `Placeholder` for the
        // identical reason.
        self.set_materialization_state(
            group_id,
            &record.path,
            MaterializationState::Placeholder,
            permit,
        )?;
        self.set_held(
            group_id,
            &record.path,
            reason,
            crate::local_convergence::types::now_unix_nanos(),
        )?;
        Ok(())
    }

    /// Single-path tombstone on a hazardous live row: mark the row held
    /// with `reason` (tx, no permit) only when it is not already held for
    /// that same reason (a read), so a hold re-confirmed on every retry
    /// keeps the time it first applied. The row itself is not touched.
    pub(crate) fn rehold_if_reason_changed(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
    ) -> Result<(), PeerSessionError> {
        let already_held =
            self.get_held_state(group_id, path)?.is_some_and(|held| held.reason == *reason);
        if !already_held {
            self.set_held(
                group_id,
                path,
                reason,
                crate::local_convergence::types::now_unix_nanos(),
            )?;
        }
        Ok(())
    }

    /// Holds `path`, whose existing file at `out_path` denies its owner read
    /// access, instead of applying `version`'s replicated metadata to it
    /// (tx, no permit). Nothing on disk is touched and the fence is only
    /// read. Records what the decision was made against
    /// ([`Self::metadata_unprovable_key`]) so the hazard re-check can skip
    /// the path until that changes, and keeps the time of the first hold
    /// for this reason. Returns the held reason, for the lane's
    /// `HazardHeld` settlement.
    pub(crate) fn hold_metadata_unprovable(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: &VersionHash,
    ) -> Result<String, PeerSessionError> {
        #[cfg(test)]
        self.test_observers.note_metadata_unprovable_hold();
        let reason = yadorilink_peer_session::hazard::metadata_unprovable_reason();
        let key = self.metadata_unprovable_key(group_id, path, out_path, version)?;
        let since = match self.get_held_state(group_id, path)? {
            Some(held) if held.reason == reason => held.since_unix_nanos,
            _ => crate::local_convergence::types::now_unix_nanos(),
        };
        self.materialization_state_repository()
            .set_held_with_key(group_id, path, &reason, since, key.as_deref())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?;
        tracing::warn!(
            group_id,
            path,
            "holding a path whose existing file is not readable by its owner: its replicated \
             metadata cannot be confirmed or applied, and its content is left as it is"
        );
        Ok(reason)
    }

    /// Whether `path` is held as metadata-unprovable and nothing it was
    /// held against has changed since: the same file (identity, and a
    /// metadata fingerprint that covers mode, size, mtime and ctime), the
    /// same mutation fence, and the same desired `version`. A re-check of
    /// such a path would only repeat the decision. Anything unreadable or
    /// unobservable answers `false`, so the path is looked at again.
    pub(crate) fn metadata_unprovable_hold_unchanged(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: &VersionHash,
    ) -> Result<bool, PeerSessionError> {
        let held_for_metadata = self.get_held_state(group_id, path)?.is_some_and(|held| {
            held.reason
                .starts_with(yadorilink_peer_session::hazard::HELD_REASON_METADATA_UNPROVABLE)
        });
        if !held_for_metadata {
            return Ok(false);
        }
        let Some(stored) = self
            .materialization_state_repository()
            .get_held_key(group_id, path)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?
        else {
            return Ok(false);
        };
        Ok(self.metadata_unprovable_key(group_id, path, out_path, version)?.as_deref()
            == Some(stored.as_str()))
    }

    /// Lifts a metadata-unprovable hold once the path has settled; a hold
    /// for any other reason is left for its own lane to lift.
    pub(crate) fn clear_metadata_unprovable_hold(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), PeerSessionError> {
        let held_for_metadata = self.get_held_state(group_id, path)?.is_some_and(|held| {
            held.reason
                .starts_with(yadorilink_peer_session::hazard::HELD_REASON_METADATA_UNPROVABLE)
        });
        if held_for_metadata {
            self.clear_held(group_id, path)?;
        }
        Ok(())
    }

    /// What a metadata-unprovable hold is decided against: the desired
    /// version, the path's current mutation fence, and the observed
    /// identity of the file (an `lstat`, no read access needed). A user's
    /// `chmod` or edit changes the fingerprint (it covers mode and ctime),
    /// any daemon write bumps the fence, and a new version changes the
    /// hash. `None` when the file cannot be observed.
    fn metadata_unprovable_key(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: &VersionHash,
    ) -> Result<Option<String>, PeerSessionError> {
        let Ok(identity) =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(out_path)
        else {
            return Ok(None);
        };
        let fence = self.dag_snapshot_mutation_fence(group_id, path)?;
        Ok(Some(format!(
            "v1 version={} fence={fence} volume={:?} object={:?} generation={:?} metadata={}",
            version.to_hex(),
            identity.volume_identity,
            identity.object_id,
            identity.generation_or_usn,
            hex::encode(identity.metadata_fingerprint),
        )))
    }

    /// Open half of a single-path tombstone delete: open the intent with
    /// the delete marker as its target (tx), then bump the fence (tx).
    /// Returns the intent the lane holds across the removal, and the fence
    /// value the removal's evidence names. The lane verifies the delete
    /// target before this and removes the file after it.
    pub(crate) fn open_tombstone_delete<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(LaneIntent<'a>, i64), PeerSessionError> {
        let delete_intent_guard = self.open_materialization_intent_guard(
            group_id,
            path,
            TOMBSTONE_DELETE_INTENT_TARGET,
            permit,
        )?;
        let mutation_generation =
            self.dag_bump_mutation_fence(group_id, path, "tombstone_delete")?;
        Ok((delete_intent_guard, mutation_generation))
    }

    /// What the intent open on `path` is for, if one is open: a delete when
    /// it names the tombstone delete's marker, a write of content
    /// otherwise. Repair decides a missing file by this, never by the raw
    /// target.
    pub(crate) fn materialization_intent_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationIntentKind>, yadorilink_sync_sqlite::SyncSqliteError> {
        Ok(self
            .materialization_intent_repository()
            .materialization_intent_target(group_id, path)?
            .map(|target| {
                if target == TOMBSTONE_DELETE_INTENT_TARGET {
                    MaterializationIntentKind::Delete
                } else {
                    MaterializationIntentKind::Materialize
                }
            }))
    }

    /// Settle half of a tombstone a DAG change authored, after the lane's
    /// removal: clear any hold (tx, no permit), persist the tombstone row
    /// under a fresh root operation (tx), then clear the intent (tx).
    ///
    /// A held file that is later tombstoned must not leave an orphaned held
    /// entry once its index row no longer represents a live, on-disk file;
    /// `clear_held` is a safe no-op when the path was never held. The
    /// intent is cleared only after the index durably reflects the
    /// deletion. An early error drops it uncleared instead, which is the
    /// fail-safe outcome: the next pass treats the path as still
    /// mid-operation, never as a fresh offline deletion. The fresh root
    /// operation is begun only here, after the hold clear, so a link that
    /// stopped meanwhile refuses the row and leaves the intent open.
    pub(crate) fn settle_tombstone_delete(
        &self,
        delete_intent_guard: LaneIntent<'_>,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: &ChangeHash,
        row_authority: RowAuthority<'_>,
    ) -> Result<(), PeerSessionError> {
        self.clear_held(group_id, &record.path)?;
        self.persist_row_under_fresh_operation(
            group_id,
            record,
            origin_device_id,
            Some(authoring_change_hash),
            row_authority,
        )?;
        delete_intent_guard.clear()
    }

    /// Settle half of a conflict-copy retirement's delete (a tombstone no
    /// DAG change authors), after the lane's removal: clear any hold (tx,
    /// no permit), erase the local-only row under the caller's permit (tx),
    /// then clear the intent (tx). Kept apart from
    /// [`Self::settle_tombstone_delete`]: this is a retirement, not a fresh
    /// mutation, and it asserts no tombstone fact.
    pub(crate) fn settle_retired_copy_erase(
        &self,
        delete_intent_guard: LaneIntent<'_>,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.clear_held(group_id, path)?;
        self.erase_local_only_file(group_id, path, permit)?;
        delete_intent_guard.clear()
    }

    /// Settle of an event-driven conflict-copy retirement pass: publish an
    /// actual-absence proof for every path the pass deleted, each in its
    /// own fence-CAS transaction under the fence value that path's own
    /// pre-delete bump produced, with `frontier_before` as the causal
    /// basis. A lost CAS publishes nothing and is not reported; an error is
    /// logged and never blocks another path's publication. Completes no
    /// obligation, unlike the engine's publication.
    pub(crate) fn publish_retired_copy_absence(
        &self,
        group_id: &str,
        frontier_before: &[ChangeHash],
        retired_generations: &BTreeMap<String, i64>,
        permit: &RootCommitPermit<'_>,
    ) {
        for (path, expected_mutation_generation) in retired_generations {
            if let Err(e) = self.dag_publish_materialized_generation_if_fence_current(
                group_id,
                path,
                frontier_before,
                yadorilink_peer_session::ports::ExactActualState::Absent,
                *expected_mutation_generation,
                permit,
            ) {
                tracing::warn!(
                    group_id,
                    path = %path,
                    error = %e,
                    "failed to publish a retired conflict copy's actual-absence generation; \
                     its obligation stays outstanding for a later pass"
                );
            }
        }
    }

    /// Settle of the equal-authoring File metadata repair: publish
    /// `version` with the identity observed at `out_path` under
    /// `mutation_generation`, the fence value the lane's bump (or, when it
    /// changed nothing, its snapshot) returned before its chmod and xattr
    /// writes, in one commit (tx) that still expects the row `Hydrated`
    /// with `authoring` and `version`. The lane has verified that disk holds
    /// `version`'s bytes, mode and xattrs. Without this the bump left a
    /// `Hydrated` row with no usable proof, which access hydration refuses
    /// as `CorruptState`. `false` when the identity cannot be observed,
    /// the fence moved or the row moved; nothing is written then.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_equal_authoring_metadata_repair(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        version: yadorilink_replica_domain::ids::VersionHash,
        authoring: &ChangeHash,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, PeerSessionError> {
        let Ok(identity) =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(out_path)
        else {
            return Ok(false);
        };
        self.commit_internal_materialized_state_if_fence_current(
            group_id,
            path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::File,
                version,
                identity: Box::new(Some(identity)),
            },
            mutation_generation,
            Some(yadorilink_peer_session::ports::ExpectedAuthoring {
                state: MaterializationState::Hydrated,
                authoring_change_hash: Some(authoring),
                expected_version: Some(&version),
            }),
            permit,
        )
    }

    /// The engine's completion of a claimed obligation against exact
    /// evidence (after its publication, or for a zero-work close): derive
    /// the desired resolved-path-state hash from `exact_state`, then close
    /// the obligation in one transaction only if its claimed generation and
    /// incarnation still hold and a current proof matches that hash.
    /// Never publishes; the engine's publication stays its own transaction.
    pub(crate) fn complete_obligation_exact(
        &self,
        group_id: &str,
        path: &str,
        claimed_generation: i64,
        claimed_incarnation: i64,
        exact_state: &yadorilink_peer_session::ports::ExactActualState,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        let desired_hash = exact_state_desired_hash(group_id, path, exact_state);
        self.sqlite().dag_complete_obligation_if_exact_proof_current(
            group_id,
            path,
            claimed_generation,
            claimed_incarnation,
            &desired_hash,
        )
    }

    /// The engine's zero-work close: the same exact-evidence completion as
    /// [`Self::complete_obligation_exact`], which additionally re-anchors
    /// the proof it closes against on the current frontier, in the same
    /// transaction. Nothing was written to disk, so no real publication
    /// refreshed the proof's causal basis -- and that basis is what the
    /// next local edit of the path is parented on. See
    /// `complete_zero_work_obligation_rebasing_proof`.
    pub(crate) fn complete_zero_work_obligation(
        &self,
        group_id: &str,
        path: &str,
        claimed_generation: i64,
        claimed_incarnation: i64,
        exact_state: &yadorilink_peer_session::ports::ExactActualState,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        let desired_hash = exact_state_desired_hash(group_id, path, exact_state);
        self.sqlite().dag_complete_zero_work_obligation_rebasing_proof(
            group_id,
            path,
            claimed_generation,
            claimed_incarnation,
            &desired_hash,
        )
    }

    /// The engine's completion of a claimed obligation against non-exact
    /// evidence (a policy placeholder, a hazard hold, an ignore exclusion):
    /// one transaction, closing only if the claimed generation and
    /// incarnation still hold. Nothing is published.
    pub(crate) fn complete_obligation_non_exact(
        &self,
        group_id: &str,
        path: &str,
        claimed_generation: i64,
        claimed_incarnation: i64,
        proof: yadorilink_sync_sqlite::projection_obligations::NonExactProofKind,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        self.sqlite().dag_complete_obligation_if_non_exact_proof_current(
            group_id,
            path,
            claimed_generation,
            claimed_incarnation,
            proof,
        )
    }
}

/// The resolved-path-state hash an exact completion closes against,
/// derived from the exact state the caller verified.
fn exact_state_desired_hash(
    group_id: &str,
    path: &str,
    exact_state: &yadorilink_peer_session::ports::ExactActualState,
) -> [u8; 32] {
    use yadorilink_peer_session::ports::ExactActualState;
    use yadorilink_sync_sqlite::materialized_generation::{
        compute_resolved_path_state_hash, MaterializedObjectKind,
    };
    let (object_kind, version) = match exact_state {
        ExactActualState::Object { kind, version, .. } => {
            (completion_object_kind(*kind), Some(*version))
        }
        ExactActualState::Absent => (MaterializedObjectKind::Absent, None),
        ExactActualState::StructuralDirectory { .. } => {
            (MaterializedObjectKind::StructuralDirectory, None)
        }
    };
    compute_resolved_path_state_hash(group_id, path, object_kind, version.as_ref())
}

/// `RecordKind` -> `MaterializedObjectKind`, for computing the desired-side
/// hash a freshly published exact evidence must be closed against. The same
/// correspondence is implemented inline in `peer_replica_state`'s publish
/// impl (which maps the identical `ExactActualState::Object.kind` to build
/// the write it sends to `path_materialized_generations`); kept as a
/// trivial three-arm match rather than a shared export.
fn completion_object_kind(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind {
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind;
    match kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    }
}
