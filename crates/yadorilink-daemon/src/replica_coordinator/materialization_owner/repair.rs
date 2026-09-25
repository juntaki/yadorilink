//! Owner operations for eviction to a placeholder and for recovery: the
//! startup reset of stale transient states, the repair sweep, and
//! restore-journal recovery.
//!
//! Eviction, the repair sweep and restore-journal recovery live in
//! `yadorilink-filesystem-sync` and reach this state only through
//! `MaterializationExecutionPort`, whose implementation delegates each
//! semantic method here. They run under the port's error type: every step
//! maps its storage error exactly as the port adapter it replaced did, so
//! what a lane sees and logs is unchanged. The physical writes, and every
//! disk comparison a decision depends on (the byte, target, mode and xattr
//! checks), stay in the lane. The one disk read here is the reconstruct
//! and symlink-rebuild settles' observation of the identity now at
//! `out_path`, after the lane's write, to name that object in the proof
//! they publish.

use std::path::Path;

use yadorilink_filesystem_sync::materialization_execution::{
    AbandonedEviction, MaterializationExecutionError, MaterializationExecutionPort,
    OpenMaterializationIntent,
};
use yadorilink_local_storage::PlaceholderIdentityToRecord;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::fs_identity::FileIdentity;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::exact_materialized_commit::{
    commit_recovered_materialized_state, ExactMaterializedState, ExpectedAuthoring,
    InternalMaterializedCommit, RecoveredMaterializedCommit,
};

use super::super::ReplicaCoordinator;
use crate::sync_error::SyncError;

impl ReplicaCoordinator {
    /// Open half of an eviction to a placeholder, after the lane's
    /// revalidation: mark the row `Evicting` (tx; its error fails the
    /// eviction outright), then bump the fence for the
    /// `eviction_to_placeholder` write (tx). The bump's own result is
    /// returned inside, for the lane to chain into the placeholder write
    /// and handle exactly like a failure of that write: either way the
    /// lane closes the row with [`Self::abandon_eviction`].
    pub(crate) fn open_eviction(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<Result<i64, MaterializationExecutionError>, MaterializationExecutionError> {
        self.materialization_state_repository()
            .set_materialization_state(group_id, path, MaterializationState::Evicting, permit)
            .map_err(SyncError::from)?;
        Ok(MaterializationExecutionPort::dag_bump_mutation_fence(
            self,
            group_id,
            path,
            "eviction_to_placeholder",
        ))
    }

    /// Settle half of an eviction, after the placeholder write: CAS the
    /// row `Evicting` -> `Placeholder` (tx). `false` when the CAS was lost,
    /// with nothing else written; otherwise record the placeholder's
    /// identity (tx) and answer `true`. An eviction that fails before this,
    /// or in it, closes the row with [`Self::abandon_eviction`].
    pub(crate) fn settle_eviction(
        &self,
        group_id: &str,
        path: &str,
        placeholder: PlaceholderIdentityToRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        if !self
            .materialization_state_repository()
            .transition_materialization_state(
                group_id,
                path,
                MaterializationState::Evicting,
                MaterializationState::Placeholder,
                permit,
            )
            .map_err(SyncError::from)?
        {
            return Ok(false);
        }
        self.record_placeholder_identity(group_id, path, placeholder, permit)?;
        Ok(true)
    }

    /// Close half of an eviction that failed after its open half, so the
    /// row does not wait in `Evicting` for the next daemon start (nothing
    /// else moves a row out of it: it is neither an eviction nor a repair
    /// candidate). One transaction: while the row is still `Evicting`,
    ///
    /// - a row that no longer names `version` goes to `Placeholder`: its
    ///   content was never on disk, and `Placeholder` is what re-fetches it;
    /// - `Intact` goes back to `Hydrated` through the recovery commit,
    ///   which publishes a proof of `version` under the live fence (the
    ///   attempt's bump invalidated the old one) and clears any intent;
    /// - `NotWritten` goes back to `Hydrated` with no proof, the entry
    ///   state, so an edit that landed during the attempt is captured as
    ///   one and the repair sweep re-proves bytes that still match;
    /// - `PlaceholderMayExist` goes to `Placeholder`, as the startup reset
    ///   resolves a stale `Evicting` row.
    ///
    /// The permit is verified inside the transaction. `false`, with
    /// nothing written, when the row is not `Evicting`.
    pub(crate) fn abandon_eviction(
        &self,
        group_id: &str,
        path: &str,
        version: &VersionHash,
        abandoned: AbandonedEviction,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        #[cfg(test)]
        if self.test_observers.abandon_eviction_fails.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MaterializationExecutionError::CorruptState(
                "injected abandon_eviction failure".to_string(),
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        Ok(self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let Some(current) =
                    yadorilink_sync_sqlite::read_canonical_current_row(tx, group_id, path)?
                else {
                    return Ok(false);
                };
                if current.materialization_state != Some(MaterializationState::Evicting) {
                    return Ok(false);
                }
                let next = if current.version_hash() != *version {
                    Some(MaterializationState::Placeholder)
                } else {
                    match abandoned {
                        AbandonedEviction::Intact { identity } => {
                            let recovered = commit_recovered_materialized_state(
                                tx,
                                group_id,
                                path,
                                None,
                                &ExactMaterializedState::Object {
                                    kind: RecordKind::File,
                                    version: *version,
                                    identity: Box::new(Some(identity)),
                                },
                                ExpectedAuthoring {
                                    state: MaterializationState::Evicting,
                                    authoring_change_hash: current.authoring_change_hash.as_ref(),
                                    expected_version: Some(version),
                                },
                                now,
                            )?;
                            match recovered {
                                RecoveredMaterializedCommit::Published(_) => None,
                                // Not reachable under the checks above, which
                                // are the commit's own guard read in this
                                // same transaction; the entry state then.
                                RecoveredMaterializedCommit::Superseded => {
                                    Some(MaterializationState::Hydrated)
                                }
                            }
                        }
                        AbandonedEviction::NotWritten => Some(MaterializationState::Hydrated),
                        AbandonedEviction::PlaceholderMayExist => {
                            Some(MaterializationState::Placeholder)
                        }
                    }
                };
                if let Some(next) = next {
                    yadorilink_sync_sqlite::MaterializationStateRepository::set_materialization_state_in_tx(
                        tx, group_id, path, next,
                    )?;
                }
                permit.verify()?;
                Ok(true)
            })
            .map_err(SyncError::from)?)
    }

    /// Startup recovery of the two transient states a crash can strand a
    /// row in: every `Hydrating` row goes back to `Placeholder` (tx), then
    /// every `Evicting` row does (tx). Both always run; each result is
    /// returned for the caller to log, so one failing does not stop the
    /// other. Must run before any link starts.
    pub(crate) fn reset_stale_transient_states(
        &self,
    ) -> (
        Result<usize, yadorilink_sync_sqlite::SyncSqliteError>,
        Result<usize, yadorilink_sync_sqlite::SyncSqliteError>,
    ) {
        let repository = self.materialization_state_repository();
        let stale_hydrating = repository.reset_stale_hydrating_to_placeholder();
        let stale_evicting = repository.reset_stale_evicting_to_placeholder();
        (stale_hydrating, stale_evicting)
    }

    /// Open half of the repair sweep's quarantine of divergent on-disk
    /// bytes, for a row whose file is present: open the intent naming the
    /// content the path will be rebuilt to (tx), BEFORE bumping the fence
    /// for the quarantine rename (tx). The intent is what keeps the path,
    /// once the rename has moved its bytes aside, from reading as an
    /// offline delete; the lane holds it across the rename and drops it
    /// uncleared.
    pub(crate) fn open_repair_quarantine<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError> {
        let quarantine_intent_guard =
            MaterializationExecutionPort::open_materialization_intent_guard(
                self,
                group_id,
                path,
                target_version_hash,
                permit,
            )?;
        MaterializationExecutionPort::dag_bump_mutation_fence(
            self,
            group_id,
            path,
            "repair_quarantine_dirty_disk_file",
        )?;
        Ok(quarantine_intent_guard)
    }

    /// Open half of the snapshot-install reconciliation's disk write: bump
    /// the fence (tx) before the lane removes, moves aside or places
    /// anything under a path the install holds, so a proof or an in-flight
    /// writer that read the path before cannot outlive the change.
    pub(crate) fn begin_snapshot_install_disk_write(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError> {
        MaterializationExecutionPort::dag_bump_mutation_fence(
            self,
            group_id,
            path,
            "snapshot_install_reconcile",
        )?;
        Ok(())
    }

    /// First step of the repair sweep's placeholder demotion (the
    /// reconstruct-failed arm and the missing-blocks arm), before the
    /// lane's target verification, fence bump and placeholder write: move
    /// the row to `Placeholder` only while it is still the row the lane
    /// read -- in `row_state`, with `authoring` and, when the lane had one,
    /// `version` (tx). `false` when it moved, with nothing written.
    ///
    /// The path lock does not make a plain set safe here: the rebootstrap
    /// install replaces a group's rows without it, so a live pass can find
    /// its row superseded between its snapshot and this step. A blind set
    /// then let the lane go on to write a placeholder sized and stamped for
    /// the version it read over the newer row, record that object's
    /// identity for it, and clear the intent, exactly the authoring- and
    /// version-bound case `settle_repair_reconstruct`'s demotion guards.
    pub(crate) fn open_repair_placeholder_demotion(
        &self,
        group_id: &str,
        path: &str,
        row_state: MaterializationState,
        authoring: Option<&ChangeHash>,
        version: Option<&VersionHash>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        // The guarded transition takes no permit; the blind set it replaces
        // verified one, so this step still does, first.
        permit.verify().map_err(SyncError::from)?;
        Ok(self
            .materialization_state_repository()
            .transition_materialization_state_if_same_authoring(
                group_id,
                path,
                Some(row_state),
                authoring,
                version,
                MaterializationState::Placeholder,
            )
            .map_err(SyncError::from)?)
    }

    /// Settle half of the repair sweep's journaled reconstruct of a regular
    /// file, after the lane rebuilt it from locally present blocks under
    /// `mutation_generation` (the lane's own bump, before the write).
    ///
    /// Publishes the proof for `version` with the identity now observed at
    /// `out_path`, guarded on the row still being in `row_state` with
    /// `authoring` and `version` (tx). No version, an unobservable
    /// identity, a failed or refused commit: nothing is published, the
    /// lane's intent stays open, and the row is demoted to `Hydrating`, a
    /// repair candidate while that intent is open, only while it is still
    /// that same row in that same state (tx). A
    /// published proof clears the intent in the same transaction. Every failure is logged here and none
    /// is returned; the answer is whether the proof was published.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_repair_reconstruct(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
        row_state: MaterializationState,
        authoring: Option<&ChangeHash>,
        version: Option<VersionHash>,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> bool {
        // This pass reconstructs real content and leaves the row
        // `Hydrated`, exactly like the live materialize/hydrate paths -- so
        // it owes the same proof they publish. Without it every repaired
        // row would sit `Hydrated` with nothing vouching for it, which is
        // the state the invariant excludes.
        //
        // If the proof cannot be published, the row must not keep the
        // claim: demote it instead of only logging. A `Hydrated` row with
        // no usable generation is what the hydration reader refuses to
        // reconstruct over, so leaving one here would convert a transient
        // stat or write failure into a permanently stuck path -- and this
        // is the repair pass, the thing that is supposed to get a path
        // unstuck.
        //
        // The demotion target is the in-flight state, not `Placeholder`.
        // The lane's intent stays open (it is the only durable record that
        // this write was never proven), and `Hydrating` with an open
        // intent is exactly what the next repair pass, live or startup,
        // picks up: its disk-matches arm proves the bytes and clears the
        // intent in one commit, and the startup `Hydrating` reset leaves
        // the pair to it. A `Placeholder` is never a repair candidate, so
        // demoting to it stranded the open intent with nothing left to
        // decide it, and every scan kept deferring an offline delete of
        // the path for as long as it lasted.
        let proof_published = match version {
            // No version to name means no publishable proof: a versionless
            // generation reads back as usable while matching no desired
            // resolution, so it would leave the row looking healed and
            // still wedged. Fall through to the demotion below instead.
            None => {
                tracing::warn!(
                    group_id,
                    path = %path,
                    "repair reconstructed this path but its current version row is \
                     absent; refusing to publish a proof that names no version"
                );
                false
            }
            // Test-only: a proof commit that fails after the lane's bytes
            // and metadata already landed, the way a crash between the two
            // would leave it.
            #[cfg(test)]
            Some(_) if repair_reconstruct_proof_commit_fails_for(group_id, path) => {
                tracing::warn!(
                    group_id,
                    path = %path,
                    "test-injected failure of the repair reconstruct proof commit"
                );
                false
            }
            Some(version) => match FileIdentity::observe_path(out_path) {
                Ok(identity) => match self.commit_repair_write(
                    group_id,
                    path,
                    &ExactMaterializedState::Object {
                        kind: RecordKind::File,
                        version,
                        identity: Box::new(Some(identity)),
                    },
                    mutation_generation,
                    // The lane verified and rebuilt against a row read in
                    // an earlier transaction. Whatever state that row was
                    // found in -- a batch interrupted before its finalizer
                    // is still mid-flight, and this commit is what
                    // promotes it.
                    Some(ExpectedAuthoring {
                        state: row_state,
                        authoring_change_hash: authoring,
                        expected_version: Some(&version),
                    }),
                    permit,
                ) {
                    Ok(published) => published,
                    Err(e) => {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            error = %e,
                            "failed to publish an actual-state generation after \
                             repair reconstruct"
                        );
                        false
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        group_id,
                        path = %path,
                        error = %e,
                        "could not observe the reconstructed file's identity after repair"
                    );
                    false
                }
            },
        };
        if !proof_published {
            // Authoring-bound, not a plain state CAS: the commit above can
            // have been refused BECAUSE the row was superseded, and the row
            // that replaced it may legitimately be `Hydrated` already.
            // Demoting on state alone would take that healthy, newer row
            // back to `Hydrating` on the strength of an attempt that was
            // about the version it replaced.
            if let Err(e) = self
                .materialization_state_repository()
                .transition_materialization_state_if_same_authoring(
                    group_id,
                    path,
                    // The state this row was actually found in. Naming
                    // `Hydrated` unconditionally made this a no-op for a row
                    // repaired out of the batch's transient state, leaving
                    // it transient and unproven. The lane's intent is not
                    // cleared by this demotion: it stays open, the durable
                    // record that the write was never proven, until the
                    // next repair pass proves the path (see above) or a
                    // later materialization's own commit clears it.
                    Some(row_state),
                    authoring,
                    // The version this attempt was about, from the same
                    // snapshot as the authoring hash -- a supersession that
                    // keeps the authoring identity still moves the row off
                    // it.
                    version.as_ref(),
                    MaterializationState::Hydrating,
                )
                .map_err(SyncError::from)
                .map_err(MaterializationExecutionError::from)
            {
                tracing::warn!(
                    group_id,
                    path = %path,
                    error = %e,
                    "could not demote an unproven Hydrated row after repair; the \
                     next repair pass must re-derive it"
                );
            }
        }
        proof_published
    }

    /// Open half of the repair sweep's journaled rebuild of a single object
    /// with no block content (a symlink, an explicit directory), after the
    /// lane's eligibility and target checks: bump the fence for the rebuild
    /// (tx), then open the intent naming `target_version_hash` (tx), both
    /// propagating errors. Returns the fence value the rebuild's proof is
    /// published under and the intent, which the lane drops uncleared once
    /// the object is written: the settle commit is what clears it.
    pub(crate) fn open_repair_object_rebuild<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        kind: RecordKind,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(i64, Box<dyn OpenMaterializationIntent + Send + 'a>), MaterializationExecutionError>
    {
        let mutation_generation = MaterializationExecutionPort::dag_bump_mutation_fence(
            self,
            group_id,
            path,
            match kind {
                RecordKind::Directory => "repair_reconstruct_directory",
                _ => "repair_reconstruct_symlink",
            },
        )?;
        let intent_guard = MaterializationExecutionPort::open_materialization_intent_guard(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )?;
        Ok((mutation_generation, intent_guard))
    }

    /// Settle half of the repair sweep's journaled rebuild of a `kind`
    /// object: publish the proof for `version` with whatever identity is
    /// now observable at `out_path` (none when it cannot be observed), under
    /// the fence value
    /// the open returned (tx). Guarded on the row still being in
    /// `row_state` with `authoring` and `version` when the lane found it in
    /// a state; unguarded when it found none. `false`, logged, when the
    /// fence was lost or the row superseded: the intent stays open for the
    /// next pass. Errors propagate.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_repair_object_rebuild(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        out_path: &Path,
        version: VersionHash,
        row_state: Option<MaterializationState>,
        authoring: Option<&ChangeHash>,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        let identity = FileIdentity::observe_path(out_path).ok();
        self.commit_repair_write(
            group_id,
            path,
            &ExactMaterializedState::Object { kind, version, identity: Box::new(identity) },
            mutation_generation,
            row_state.map(|state_now| ExpectedAuthoring {
                state: state_now,
                authoring_change_hash: authoring,
                expected_version: Some(&version),
            }),
            permit,
        )
    }

    /// Restore-journal recovery's preservation of bytes the journal cannot
    /// account for: journal `path` as dirty with `change_kind` and
    /// `observed_at_unix_nanos` (tx), so the ordinary startup repair
    /// quarantines and re-indexes them rather than overwriting them, then
    /// discard the journal entry (tx). Both propagate errors.
    pub(crate) fn preserve_divergent_restore(
        &self,
        operation_id: &str,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        self.dirty_path_repository()
            .record_dirty_path(group_id, path, change_kind, observed_at_unix_nanos, permit)
            .map_err(SyncError::from)?;
        self.restore_operation_repository()
            .discard_restore_operation(operation_id)
            .map_err(SyncError::from)?;
        Ok(())
    }

    /// The repair lanes' exact commit for a write they made under
    /// `mutation_generation`: publish `exact`, stamp the state and clear
    /// the intent in one transaction, only while the fence is still that
    /// value and the row still satisfies `expected`. A lost fence or a
    /// superseded row writes nothing, is logged, and answers `false`.
    fn commit_repair_write(
        &self,
        group_id: &str,
        path: &str,
        exact: &ExactMaterializedState,
        mutation_generation: i64,
        expected: Option<ExpectedAuthoring<'_>>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        let outcome = self
            .materialization_state_repository()
            .commit_internal_materialized_state_if_fence_current(
                group_id,
                path,
                None,
                exact,
                mutation_generation,
                expected,
                permit,
            )
            .map_err(SyncError::from)?;
        match outcome {
            InternalMaterializedCommit::Published(_) => Ok(true),
            InternalMaterializedCommit::FenceLost { live_mutation_generation } => {
                tracing::warn!(
                    group_id,
                    path,
                    expected = mutation_generation,
                    live = ?live_mutation_generation,
                    "a repair write lost its fence before it could publish; nothing was written \
                     and the intent stays open for the next pass"
                );
                Ok(false)
            }
            InternalMaterializedCommit::AuthoringSuperseded => {
                tracing::warn!(
                    group_id,
                    path,
                    "the row a repair write verified its bytes against was superseded before the \
                     proof could be committed; publishing nothing"
                );
                Ok(false)
            }
        }
    }
}

/// Test-only failure injection for `settle_repair_reconstruct`'s proof
/// commit, keyed by `(group_id, path)` so tests running in parallel never
/// see each other's arming.
#[cfg(test)]
static TEST_FAIL_REPAIR_RECONSTRUCT_PROOF_COMMIT: std::sync::Mutex<
    Option<std::collections::HashSet<(String, String)>>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
fn repair_reconstruct_proof_commit_fails_for(group_id: &str, path: &str) -> bool {
    TEST_FAIL_REPAIR_RECONSTRUCT_PROOF_COMMIT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|armed| armed.contains(&(group_id.to_owned(), path.to_owned())))
}

/// Test-only: makes (or stops making) every repair reconstruct proof commit
/// for `(group_id, path)` fail as if the commit itself had been refused.
#[cfg(test)]
pub(crate) fn set_test_fail_repair_reconstruct_proof_commit(
    group_id: &str,
    path: &str,
    armed: bool,
) {
    let mut guard =
        TEST_FAIL_REPAIR_RECONSTRUCT_PROOF_COMMIT.lock().unwrap_or_else(|p| p.into_inner());
    let paths = guard.get_or_insert_with(std::collections::HashSet::new);
    let key = (group_id.to_owned(), path.to_owned());
    if armed {
        paths.insert(key);
    } else {
        paths.remove(&key);
    }
}
