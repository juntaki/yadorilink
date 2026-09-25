//! Owner operations for the two hydration lanes.
//!
//! Convergence rehydration (`local_convergence::hydrate`) and access
//! hydration (`crate::hydration`) are separate protocols with separate
//! guard types: they differ in whether an intent is opened, in hazard and
//! held handling, and in whether the entry CAS runs under a permit. Both
//! downgrade their revert target to `Placeholder` once they bumped the
//! fence. Nothing here is shared between them.
//!
//! Each guard is armed by the entry CAS to `Hydrating` and reverts the row
//! on drop unless its commit published. The lane keeps every fetch, check
//! and physical write between these steps.

use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::fs_identity::FileIdentity;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use yadorilink_sync_sqlite::exact_materialized_commit::{
    ExactMaterializedState, ExpectedAuthoring, InternalMaterializedCommit,
};

use super::super::ReplicaCoordinator;
use super::lanes::LaneIntent;
use crate::sync_error::SyncError;

/// Background convergence rehydration's `Hydrating` window
/// (`hydrate_file_with_timeout_locked`): reverts the row to the state the
/// attempt found on drop unless `commit_exact_file` published first.
///
/// Every fallible step between marking a row `Hydrating` and either
/// committing it (a genuine `Hydrated`) or hitting one of the two
/// already-handled non-error exits (fetch failure, hazard-hold, both of
/// which also just let this guard's drop do the revert) used to leave the
/// row stuck at `Hydrating` on any other error, with no independent
/// recovery: the materialization audit that could otherwise notice and
/// repair it needs a connected peer to even run.
///
/// The revert target is the entry state until `begin_physical_write`
/// bumped the fence, and `Placeholder` after it: the bump makes the
/// proof a `Hydrated` entry stood on stale, and `Hydrated` without a
/// usable proof is the state access hydration refuses as `CorruptState`,
/// which wedged every open and pin of the path. Same rule as the access
/// lane's guard.
pub(crate) struct ConvergenceHydration<'a> {
    coordinator: &'a ReplicaCoordinator,
    group_id: &'a str,
    path: &'a str,
    /// This attempt's own authoring identity, captured before it set
    /// `Hydrating` -- see the `Drop` impl for why a state-only CAS isn't
    /// enough on its own.
    authoring_change_hash: Option<ChangeHash>,
    /// This attempt's own version, from the SAME read as
    /// `authoring_change_hash` -- see the `Drop` impl for why the
    /// authoring hash alone is not enough either.
    version: VersionHash,
    /// What an abandoned attempt puts the row back to -- the state it
    /// found, so an attempt that changes nothing leaves nothing changed;
    /// `Placeholder` once `begin_physical_write` bumped the fence.
    revert_to: MaterializationState,
    committed: bool,
}

impl ReplicaCoordinator {
    /// Entry step of convergence rehydration: CAS the row from
    /// `entry_state` to `Hydrating`, bound to this attempt's authoring
    /// identity and version (tx). `None` when the row moved (the lane
    /// fails the attempt); otherwise the guard that reverts the row to
    /// `entry_state` (or `Placeholder` when it had none) on drop.
    pub(crate) fn begin_convergence_hydration<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        entry_state: Option<MaterializationState>,
        authoring_change_hash: Option<ChangeHash>,
        version: VersionHash,
    ) -> Result<Option<ConvergenceHydration<'a>>, PeerSessionError> {
        if !self.transition_materialization_state_if_same_authoring(
            group_id,
            path,
            entry_state,
            authoring_change_hash.as_ref(),
            Some(&version),
            MaterializationState::Hydrating,
        )? {
            return Ok(None);
        }
        Ok(Some(ConvergenceHydration {
            coordinator: self,
            group_id,
            path,
            authoring_change_hash,
            version,
            revert_to: entry_state.unwrap_or(MaterializationState::Placeholder),
            committed: false,
        }))
    }
}

impl<'a> ConvergenceHydration<'a> {
    /// Hazard exit: mark the path held with `reason` (tx, no permit). The
    /// row is not touched here; this guard's drop then reverts it.
    pub(crate) fn hold_for_hazard(&self, reason: &str) -> Result<(), PeerSessionError> {
        self.coordinator.set_held(
            self.group_id,
            self.path,
            reason,
            crate::local_convergence::types::now_unix_nanos(),
        )
    }

    /// Leaves any hazard hold before the write: when the path is held (a
    /// read), an intent naming `intent_target_hash` is opened (tx) BEFORE
    /// the hold is cleared (tx), and handed back for the lane to keep
    /// until the commit clears it (or until it clears it itself after a
    /// failed metadata step). Not opened when the path was never held.
    ///
    /// Rehydration's own step, not the symlink lane's release.
    pub(crate) fn release_hold_under_intent<'p>(
        &self,
        intent_target_hash: &[u8],
        permit: &'p RootCommitPermit<'p>,
    ) -> Result<Option<LaneIntent<'p>>, PeerSessionError>
    where
        'a: 'p,
    {
        let coordinator: &'a ReplicaCoordinator = self.coordinator;
        let (group_id, path): (&'a str, &'a str) = (self.group_id, self.path);
        let was_held = coordinator.get_held_state(group_id, path)?.is_some();
        let hold_transition_intent_guard = if was_held {
            Some(coordinator.open_materialization_intent_guard(
                group_id,
                path,
                intent_target_hash,
                permit,
            )?)
        } else {
            None
        };
        coordinator.clear_held(group_id, path)?;
        Ok(hold_transition_intent_guard)
    }

    /// Bumps this path's mutation fence for the rehydration write (tx)
    /// and, once it did, forces the revert target to `Placeholder`: the
    /// standing proof is stale from that point, so restoring `Hydrated`
    /// would claim content nothing vouches for. Returns the value
    /// the commit must still find.
    pub(crate) fn begin_physical_write(&mut self) -> Result<i64, PeerSessionError> {
        let mutation_generation = self.coordinator.dag_bump_mutation_fence(
            self.group_id,
            self.path,
            "peer_hydration_write",
        )?;
        self.revert_to = MaterializationState::Placeholder;
        Ok(mutation_generation)
    }

    /// Settle: publish this attempt's version with `identity` under
    /// `mutation_generation`, stamp `Hydrated` and clear any intent, in
    /// one commit (tx) that still expects `Hydrating` with this attempt's
    /// authoring identity and version. Disarms the revert only when it
    /// published; `false` leaves the guard armed.
    pub(crate) fn commit_exact_file(
        &mut self,
        identity: FileIdentity,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, PeerSessionError> {
        let committed = self.coordinator.commit_internal_materialized_state_if_fence_current(
            self.group_id,
            self.path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::File,
                version: self.version,
                identity: Box::new(Some(identity)),
            },
            mutation_generation,
            Some(yadorilink_peer_session::ports::ExpectedAuthoring {
                state: MaterializationState::Hydrating,
                authoring_change_hash: self.authoring_change_hash.as_ref(),
                expected_version: Some(&self.version),
            }),
            permit,
        )?;
        if committed {
            self.committed = true;
        }
        Ok(committed)
    }
}

impl Drop for ConvergenceHydration<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // A conditional transition bound to BOTH the expected state
            // (`Hydrating`) AND this attempt's own authoring identity, not
            // a blind `set_materialization_state`. State alone is not
            // enough: two attempts for the same path can race, and a
            // state-only CAS cannot tell "this row is still the SAME
            // version this attempt started with, just still `Hydrating`"
            // apart from "a NEWER version of this path became current
            // mid-hydration and happened to also land in `Hydrating`
            // before this attempt's cleanup ran" (a peer's concurrent
            // update superseding the row). Binding to the authoring
            // identity narrows that, but does not finish it: authoring
            // identity is not version identity, and a supersession that
            // keeps the hash while moving the content columns leaves a row
            // this guard would still have reverted. The version is bound
            // too, so this only ever reverts the exact version this
            // attempt was hydrating.
            //
            // Best-effort on error: this already runs during unwind from
            // a `?` elsewhere in the lane, so a second failure here has
            // nowhere better to go than a log line.
            match self.coordinator.transition_materialization_state_if_same_authoring(
                self.group_id,
                self.path,
                Some(MaterializationState::Hydrating),
                self.authoring_change_hash.as_ref(),
                Some(&self.version),
                self.revert_to,
            ) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        group_id = self.group_id,
                        path = self.path,
                        error = %e,
                        "failed to revert an aborted hydration's materialization state back to \
                         Placeholder; row may be stuck at Hydrating"
                    );
                }
            }
        }
    }
}

/// Access-triggered hydration's `Hydrating` window (`hydrate_inner`):
/// reverts the row on drop unless `complete` ran first. Silent on error.
///
/// Its revert target starts at the entry state and is forced to
/// `Placeholder` once `begin_physical_write` bumped the fence. Not the
/// convergence lane's guard (`ConvergenceHydration`): this lane opens no
/// intent, has no hazard or held handling, and its entry CAS and revert
/// run without a permit.
pub(crate) struct AccessHydration<'a> {
    coordinator: &'a ReplicaCoordinator,
    group_id: &'a str,
    path: &'a str,
    authoring_change_hash: Option<ChangeHash>,
    /// This attempt's own version, from the same canonical read as
    /// `authoring_change_hash`. Bound as well as the authoring hash
    /// because the two are not the same question: a supersession can
    /// keep the hash while moving the columns the version is derived
    /// from, and reverting on the hash alone would take a row that has
    /// moved on back to `Placeholder`.
    version: VersionHash,
    /// What an abandoned attempt puts the row back to.
    ///
    /// `Placeholder` for an attempt that started from one -- the row
    /// claimed nothing, and it still claims nothing. But this lane is
    /// also reached by the metadata-repair fallthrough, which starts from
    /// a `Hydrated` row whose bytes were just verified against the index.
    /// Demoting THAT to `Placeholder` throws away a real protection: the
    /// `Hydrated` arm refuses to reconstruct over bytes it cannot vouch
    /// for, and a `Placeholder` row skips that check entirely, so the
    /// next attempt would take an unjournalled local edit as its baseline
    /// and overwrite it.
    ///
    /// Restoring `Hydrated` is only honest while nothing has been
    /// mutated: the fence bump invalidates the standing proof, and
    /// `Hydrated` without a usable proof is the wedged state. So
    /// `begin_physical_write` moves this to `Placeholder` once it bumped.
    revert_to: MaterializationState,
    completed: bool,
}

impl ReplicaCoordinator {
    /// Entry step of access hydration: CAS the row from `entry_state` to
    /// `Hydrating`, bound to this attempt's authoring identity and version
    /// (tx, no permit). `None` when the row moved (the lane fails the
    /// attempt); otherwise the guard that reverts the row to `entry_state`
    /// (or `Placeholder` when it had none) on drop.
    pub(crate) fn begin_access_hydration<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        entry_state: Option<MaterializationState>,
        authoring_change_hash: Option<ChangeHash>,
        version: VersionHash,
    ) -> Result<Option<AccessHydration<'a>>, SyncError> {
        if !self
            .materialization_state_repository()
            .transition_materialization_state_if_same_authoring(
                group_id,
                path,
                entry_state,
                authoring_change_hash.as_ref(),
                Some(&version),
                MaterializationState::Hydrating,
            )?
        {
            return Ok(None);
        }
        Ok(Some(AccessHydration {
            coordinator: self,
            group_id,
            path,
            authoring_change_hash,
            version,
            revert_to: entry_state.unwrap_or(MaterializationState::Placeholder),
            completed: false,
        }))
    }
}

impl<'a> AccessHydration<'a> {
    /// Bumps this path's mutation fence for the hydration write (tx) and,
    /// once it did, forces the revert target to `Placeholder`: from that
    /// point the standing proof is stale, so restoring `Hydrated` would
    /// claim content with nothing vouching for it. Returns the fence value
    /// the commit must still find.
    pub(crate) fn begin_physical_write(&mut self) -> Result<i64, PeerSessionError> {
        let mutation_generation = self.coordinator.dag_bump_mutation_fence(
            self.group_id,
            self.path,
            "hydration_write",
        )?;
        self.revert_to = MaterializationState::Placeholder;
        Ok(mutation_generation)
    }

    /// Settle: publish this attempt's version with `identity` under
    /// `mutation_generation`, stamp `Hydrated` and clear any intent, in
    /// one commit (tx) that still expects `Hydrating` with this attempt's
    /// authoring identity and version. The group heads are derived inside
    /// the commit's own transaction. Returns the commit's outcome for the
    /// lane to report; the guard stays armed until `complete`.
    pub(crate) fn commit_exact_file(
        &self,
        identity: FileIdentity,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<InternalMaterializedCommit, SyncError> {
        Ok(self
            .coordinator
            .materialization_state_repository()
            .commit_internal_materialized_state_if_fence_current(
                self.group_id,
                self.path,
                None,
                &ExactMaterializedState::Object {
                    kind: yadorilink_replica_domain::file::RecordKind::File,
                    version: self.version,
                    identity: Box::new(Some(identity)),
                },
                mutation_generation,
                Some(ExpectedAuthoring {
                    state: MaterializationState::Hydrating,
                    authoring_change_hash: self.authoring_change_hash.as_ref(),
                    expected_version: Some(&self.version),
                }),
                permit,
            )?)
    }

    /// Disarms the revert: the attempt published, or found the path
    /// already complete.
    pub(crate) fn complete(&mut self) {
        self.completed = true;
    }

    #[cfg(test)]
    pub(crate) fn armed_for_tests(
        coordinator: &'a ReplicaCoordinator,
        group_id: &'a str,
        path: &'a str,
        authoring_change_hash: Option<ChangeHash>,
        version: VersionHash,
        revert_to: MaterializationState,
    ) -> Self {
        Self {
            coordinator,
            group_id,
            path,
            authoring_change_hash,
            version,
            revert_to,
            completed: false,
        }
    }
}

impl Drop for AccessHydration<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Authoring-bound, not a state-only CAS. `hydrate_inner`
            // holds `path_lock` for its whole attempt, so two attempts for
            // the same path can no longer be mid-flight at once at all --
            // but this binding is kept regardless as defense-in-depth
            // against any future caller that arms this guard without
            // holding that same lock for its whole duration, and because
            // `Drop` itself cannot await the lock even if the surrounding
            // function does: a state-only CAS firing from an unlocked
            // `Drop` could still, in principle, race a differently-authored
            // row it has no way to distinguish from its own.
            let _ = self
                .coordinator
                .materialization_state_repository()
                .transition_materialization_state_if_same_authoring(
                    self.group_id,
                    self.path,
                    Some(MaterializationState::Hydrating),
                    self.authoring_change_hash.as_ref(),
                    Some(&self.version),
                    self.revert_to,
                );
        }
    }
}

impl ReplicaCoordinator {
    /// Access hydration's proof heal for a `Hydrated` row whose bytes,
    /// identity, mode and xattrs the lane verified against `version`:
    /// re-publish the proof for `version` with `identity` under the live
    /// fence (tx), guarded on the row still being `Hydrated` with
    /// `authoring` and `version`. `permit` is verified inside that tx,
    /// before the publish, so a lost root fails the heal with nothing
    /// published; a superseded row writes nothing and answers `false`.
    ///
    /// The errors keep the port's type, exactly as the lane saw them
    /// through `MaterializationExecutionPort` before.
    pub(crate) fn reprove_hydrated_file(
        &self,
        group_id: &str,
        path: &str,
        version: &VersionHash,
        identity: FileIdentity,
        authoring: Option<&ChangeHash>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        let exact = ExactMaterializedState::Object {
            kind: yadorilink_replica_domain::file::RecordKind::File,
            version: *version,
            identity: Box::new(Some(identity)),
        };
        let guard = Some(ExpectedAuthoring {
            state: MaterializationState::Hydrated,
            authoring_change_hash: authoring,
            expected_version: Some(version),
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let published = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::exact_materialized_commit::reprove_verified_hydrated_state(
                    tx, group_id, path, None, &exact, guard, now, permit,
                )
            })
            .map_err(SyncError::from)?;
        Ok(published.is_some())
    }
}

impl ReplicaCoordinator {
    /// Settle half of a live version restore, after the lane's physical
    /// write: mark the journal entry disk-committed (tx), observe what is
    /// now at `out_path` (`None` for the one arm that writes nothing, or
    /// when it cannot be observed), then commit the restore under the
    /// fence value the write went out under (tx). Returns the commit's
    /// outcome for the lane to map.
    ///
    /// `permit` comes from the one `LinkOperation` the lane holds for the
    /// whole restore, and both transactions verify it before they write
    /// so a root lost after the physical write marks nothing and
    /// publishes nothing, leaving the journal entry for recovery.
    pub(crate) fn settle_restore_write(
        &self,
        operation_id: &str,
        out_path: &std::path::Path,
        wrote_under_mutation_generation: i64,
        // False when the write could not confirm every exact-required field
        // it set (its replicated xattrs): the restore is still committed,
        // but with no observed identity, so no exact proof is published
        // and the row does not claim to hold the content.
        exact_claimable: bool,
        permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
    ) -> Result<yadorilink_replica_domain::session_state::RestoreCommitOutcome, SyncError> {
        self.restore_operation_repository().mark_restore_disk_committed(operation_id, permit)?;
        // Observed after the disk write, so the proof describes what a
        // reader would now find.
        let restored_identity =
            if exact_claimable { FileIdentity::observe_path(out_path).ok() } else { None };
        Ok(self.restore_operation_repository().commit_restore_operation(
            operation_id,
            restored_identity.as_ref(),
            Some(wrote_under_mutation_generation),
            permit,
        )?)
    }
}

#[cfg(test)]
mod convergence_guard_tests;
