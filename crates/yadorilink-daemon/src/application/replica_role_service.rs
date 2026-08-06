use std::sync::Arc;

use yadorilink_replica_domain::session_state::MaterializationPolicy;

use super::model::{HandoffCommitResult, RoleLossCommitOutcome};
use super::ports::{
    HandoffReadinessPort, LinkRuntimePort, PlaceholderPipelineCapabilityPort,
    ReplicaRoleRepository, RoleLossCoordination, RoleLossJournal,
};

pub(crate) fn demotion_handoff_lease_failure_message() -> String {
    "refusing to drop full-replica status: confirmed a ready replica but could not obtain the \
     required handoff lease (peer unreachable, not caught up, or coordination unavailable); \
     re-run set-storage-mode to retry"
        .to_string()
}

pub(crate) fn unlink_handoff_lease_failure_message(local_path: &str) -> String {
    format!(
        "refusing to unlink {local_path}: confirmed a ready replica but could not obtain the \
         required handoff lease (peer unreachable, not caught up, or coordination unavailable). \
         Re-run unlink to retry, or use --force to unlink anyway (data-loss risk)."
    )
}

/// Owns storage-mode changes and unlink -- the two operations that can flip
/// or drop this device's full-replica status for a folder group. Every
/// dependency is a port -- no `DaemonState`, no `coordination_client`, no
/// the daemon's own `LinkRuntimeController` -- see the composition root for
/// what backs each one in production.
pub(crate) struct ReplicaRoleService {
    device_id: String,
    repository: Arc<dyn ReplicaRoleRepository>,
    role_loss: Arc<dyn RoleLossJournal>,
    readiness: Arc<dyn HandoffReadinessPort>,
    coordination: Arc<dyn RoleLossCoordination>,
    runtime: Arc<dyn LinkRuntimePort>,
    placeholder_pipeline: Arc<dyn PlaceholderPipelineCapabilityPort>,
}

#[derive(Debug)]
struct AmbiguityRecovery {
    group_id: String,
    survivors: Vec<String>,
}

/// Which link-row removal step the unlink dispatcher still owes after the
/// durability gate (`ensure_unlink_keeps_a_full_replica`) returns.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnlinkCommit {
    /// The eager ready path already removed the link row atomically with its
    /// digest re-check; the caller must not remove it again. Carries the
    /// coordination-plane handoff-commit result, paired with this device's
    /// own locally-computed root digest (never sent to or read back from
    /// coordination-worker), when that path actually ran one (`Some`).
    AlreadyRemoved(Option<(HandoffCommitResult, [u8; 32])>),
    /// No atomic removal happened (on-demand cache, no link row, or a forced
    /// bypass); the caller performs the plain `remove_link`.
    RemoveNormally,
}

/// Protocol-agnostic result of a coordination-plane role-loss handoff commit
/// -- `control_socket` maps this to the IPC `HandoffResult` proto type;
/// nothing in this module depends on the wire format.
pub(crate) struct HandoffOutcome {
    pub(crate) target_device_id: String,
    pub(crate) root_digest: [u8; 32],
    pub(crate) membership_generation: i64,
    pub(crate) lease_id: Option<String>,
}

pub(crate) struct UnlinkOutcome {
    pub(crate) handoff: Option<HandoffOutcome>,
}

impl ReplicaRoleService {
    pub(crate) fn new(
        device_id: String,
        repository: Arc<dyn ReplicaRoleRepository>,
        role_loss: Arc<dyn RoleLossJournal>,
        readiness: Arc<dyn HandoffReadinessPort>,
        coordination: Arc<dyn RoleLossCoordination>,
        runtime: Arc<dyn LinkRuntimePort>,
        placeholder_pipeline: Arc<dyn PlaceholderPipelineCapabilityPort>,
    ) -> Self {
        Self {
            device_id,
            repository,
            role_loss,
            readiness,
            coordination,
            runtime,
            placeholder_pipeline,
        }
    }

    /// The local link's path for `group_id`, if this device has one -- the
    /// reverse of every other lookup in this file (which resolve a
    /// `local_path` forward to a `group_id`), needed here because a
    /// storage-mode request carries only the group id (like the Worker's
    /// own storage-mode route), while the materialization-policy write is
    /// keyed by `local_path`.
    fn local_path_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, crate::sync_error::SyncError> {
        self.repository.live_link_local_path_for_group(group_id)
    }

    fn prepare_ambiguity_recovery(
        &self,
        local_path: &str,
    ) -> Result<Option<AmbiguityRecovery>, crate::sync_error::SyncError> {
        let links = self.repository.list_links()?;
        let Some(target) = links.iter().find(|l| l.local_path == local_path) else {
            return Ok(None);
        };
        let group_id = target.group_id.clone();
        let live_paths: Vec<String> = links
            .iter()
            .filter(|l| l.group_id == group_id && !l.orphaned)
            .map(|l| l.local_path.clone())
            .collect();
        if live_paths.len() < 2 {
            return Ok(None);
        }

        let survivors: Vec<String> =
            live_paths.into_iter().filter(|path| path != local_path).collect();

        self.repository.arm_duplicate_recovery_paths(&group_id)?;
        for survivor in &survivors {
            self.repository.set_suppress_tombstones(survivor, true)?;
        }

        Ok(Some(AmbiguityRecovery { group_id, survivors }))
    }

    /// Orchestrates `yadorilink share set-storage-mode`: the SOLE place that
    /// commits BOTH the coordination-plane record of this device's storage mode
    /// for `group_id` AND the local materialization-policy flip between eager
    /// (full replica) and on-demand (cache) -- the CLI only asks for the
    /// change and prints this function's result; it makes no coordination-plane
    /// call of its own and has nothing to compensate.
    ///
    /// Demoting FROM eager (`on_demand = true`) is refused, fail-closed, unless
    /// the handoff-readiness port confirms some other full replica durably
    /// holds the current version of every file in the group -- without central
    /// storage, a full replica is the only durable copy, so giving one up
    /// before a confirmed handoff risks permanent data loss. This re-checks
    /// readiness itself rather than trusting any earlier check the caller may
    /// have already done, since that is the only check in this whole path
    /// that is actually authoritative at the moment local policy commits.
    ///
    /// Promoting TO eager (`on_demand = false`) has no such hazard -- gaining a
    /// durable copy is always safe -- and is applied unconditionally; this
    /// direction is intentionally minimal (no readiness preflight, no backfill
    /// orchestration) since the corrected custody/hydration paths already bring
    /// an eager link's placeholders down over time.
    ///
    /// Ordering, and why it is crash-safe either way. For a DEMOTION, when a real
    /// confirming peer is named and this device has coordination-plane config
    /// recorded (production, a logged-in registered device), a live lease is now
    /// MANDATORY: this device asks the confirmed peer directly, over the
    /// authenticated peer channel, to verify and pin its own durability-root set
    /// and hand back a lease naming it, refusing outright if no live lease can
    /// be obtained (peer unreachable, refused, or its attested root digest
    /// doesn't match this device's own). Only once a lease is in hand does the
    /// coordination-plane role-loss commit happen, BEFORE the local policy
    /// flip, mirroring `ensure_unlink_keeps_a_full_replica`'s identical wiring.
    /// Unlike unlink, there is no `--force` here, so a refused or unreachable
    /// coordination-plane commit -- or a lease that could not be obtained at
    /// all -- fails the demotion closed with no local-only fallback and this
    /// device stays locally eager -- a crash between the two commits still
    /// leaves both sides agreeing this device is eager, which a re-run of the
    /// command reconciles. Committing local-only first would be the unsafe
    /// order: it would let this device release its only durable copy (and, on
    /// a crash before the coordination-plane commit, start reclaiming blocks)
    /// before the handoff is ever recorded coordination-side. For a PROMOTION,
    /// the coordination-plane storage-mode write also happens BEFORE the local
    /// flip, and its failure aborts before the flip runs -- but a promotion
    /// only ever ADDS a durable copy, so the reverse failure direction (Worker
    /// updated, local flip not yet run) is always safe and self-heals on a
    /// re-run; there is no data-loss hazard symmetric to the demotion case.
    ///
    /// Behavior when no coordination-plane config is recorded differs by
    /// direction. A DEMOTION with no config falls through to a local-only flip
    /// (it can only get there when there was no confirming peer to name, i.e. a
    /// plane-disconnected daemon, which the readiness gate above already handles
    /// fail-closed for a real full replica). A PROMOTION in production instead
    /// FAILS CLOSED: it has no peer gate, so a silently-skipped Worker write
    /// would leave the plane on-demand while local goes eager, and -- because a
    /// re-run no-ops once local already matches the target -- that split would
    /// not self-heal. Under the deterministic simulator, where config is always
    /// absent by design, a promotion still proceeds local-only, just like a
    /// madsim demotion.
    ///
    /// The readiness confirmation above is itself a network round trip, so
    /// there is a real window between it returning and the local policy flip
    /// below actually committing during which this device's own
    /// durability-root set could change (a local edit lands). To close that
    /// TOCTOU, the digest the peer was confirmed against is re-checked and the
    /// policy flip is committed together, in one write transaction, so a
    /// concurrent watcher index write cannot interleave between the re-check
    /// and the commit; a mismatch fails closed exactly like an unconfirmed
    /// peer would -- there is no `--force` for demote, so the caller simply
    /// has to retry.
    ///
    /// Note this atomic re-check guards the coordination-plane ROLE flip
    /// (eager -> on-demand), not block deletion. Actually reclaiming any
    /// specific version's blocks stays separately gated, per file, by the
    /// on-demand eviction custody check, which is the real backstop against
    /// dropping the last copy of a version.
    pub(crate) async fn set_storage_mode(
        &self,
        group_id: &str,
        on_demand: bool,
    ) -> Result<Option<(HandoffCommitResult, [u8; 32])>, String> {
        let Some(local_path) = self.local_path_for_group(group_id).map_err(|e| e.to_string())?
        else {
            return Err(format!("no link registered for folder group {group_id}"));
        };
        if on_demand && !self.placeholder_pipeline.is_connected() {
            return Err(
                "on-demand (placeholder) materialization is not available in this build yet"
                    .to_string(),
            );
        }
        if on_demand && self.readiness.is_local_full_replica(group_id) {
            let Some((digest_at_check, ready_peer_device_id)) =
                self.readiness.full_replica_handoff_ready_digest_and_peer(group_id).await
            else {
                return Err(
                    "refusing to drop full-replica status: no other full replica is confirmed to \
                 hold every file in this group yet"
                        .to_string(),
                );
            };
            // Same role-loss shape as `ensure_unlink_keeps_a_full_replica`'s
            // unlink path (this device giving up its own eager status) --
            // reuse its exact wiring: a real confirmed peer means a
            // non-empty root set, so a live, peer-attested lease is now
            // MANDATORY (asked of the confirmed target directly, not merely
            // looked up best-effort), and its absence refuses the whole
            // commit -- see that function's own doc comment for the full
            // rationale; only duplicated here because the two call sites
            // commit two different local side effects (link removal vs.
            // materialization-policy flip) on top of the same
            // coordination-plane commit.
            // Fix-saga: filled in inside the `Some(lease_id)` arm below,
            // right before the coordination-worker commit, and consulted
            // after the local recheck below to close out (success) or
            // compensate (failure) the journal row it names.
            let mut role_loss_operation_id: Option<String> = None;
            let mut lease_acquisition_failed = false;
            let coordination_result = match (
                &ready_peer_device_id,
                self.coordination.is_configured(),
            ) {
                (Some(target_device_id), true) => {
                    match self
                        .readiness
                        .obtain_handoff_lease_from_peer(group_id, target_device_id, digest_at_check)
                        .await
                    {
                        Some(lease_id) => {
                            // Fix-saga: persist the durable Prepared journal row
                            // FIRST, and fail closed if that write itself fails --
                            // committing the role loss on the Worker without a
                            // durable recovery record would reopen the exact
                            // split-state hole the journal exists to close.
                            // Nothing has been committed on either side yet, so
                            // aborting here leaves no split (routed through the
                            // same `Err(())` fail-closed tail as an unconfirmed
                            // peer -- for demote there is no `--force`, so it just
                            // refuses).
                            match self.role_loss.open_operation(
                                group_id,
                                target_device_id,
                                &lease_id,
                                yadorilink_replica_domain::session_state::RoleLossAction::Demote,
                                &local_path,
                            ) {
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        group_id,
                                        target_device_id = %target_device_id,
                                        "refusing the demotion: could not persist the durable \
                                         role-loss rollback journal, so the role loss must not be \
                                         committed on the coordination plane"
                                    );
                                    Err(())
                                }
                                Ok(operation_id) => {
                                    match self
                                        .coordination
                                        .commit_handoff_role_loss(
                                            group_id,
                                            &self.device_id,
                                            target_device_id,
                                            Some(lease_id.as_str()),
                                            "demote",
                                            &operation_id,
                                        )
                                        .await
                                    {
                                        RoleLossCommitOutcome::Committed(result) => {
                                            self.role_loss.mark_worker_committed(
                                                &operation_id,
                                                result.membership_generation,
                                            );
                                            role_loss_operation_id = Some(operation_id);
                                            Ok(Some((result, digest_at_check)))
                                        }
                                        RoleLossCommitOutcome::DefinitelyRejected(e) => {
                                            self.role_loss.discard_operation(&operation_id);
                                            tracing::warn!(
                                                error = %e,
                                                group_id,
                                                target_device_id = %target_device_id,
                                                "coordination-plane handoff role-loss commit failed; \
                                                 set-storage-mode readiness gate treats this the same \
                                                 as an unconfirmed peer"
                                            );
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Ambiguous(e) => {
                                            tracing::error!(
                                                error = %e,
                                                group_id,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "handoff role-loss commit outcome is ambiguous; retaining the \
                                                 Prepared journal and compensating Worker state back to eager"
                                            );
                                            if let Err(compensation_error) =
                                                self.role_loss.compensate(&operation_id).await
                                            {
                                                tracing::error!(
                                                    error = %compensation_error,
                                                    operation_id,
                                                    "immediate ambiguous role-loss compensation failed; the \
                                                     periodic reconciler will retry"
                                                );
                                            }
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Conflict(e) => {
                                            // Should never happen for a freshly generated operation_id;
                                            // leave the Prepared row untouched for operator attention
                                            // rather than discarding or retrying blindly.
                                            tracing::error!(
                                                error = %e,
                                                group_id,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "handoff role-loss commit's operation_id conflicts with a \
                                                 differently-shaped request already recorded -- operator \
                                                 attention required"
                                            );
                                            Err(())
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            lease_acquisition_failed = true;
                            tracing::warn!(
                                group_id,
                                target_device_id = %target_device_id,
                                "could not obtain a live handoff lease from the confirmed target \
                                 peer (unreachable, refused, or its attested durability-root digest \
                                 did not match this device's own); a lease is mandatory for a \
                                 non-empty root set, so refusing to relinquish full-replica status"
                            );
                            Err(())
                        }
                    }
                }
                // A confirmed handoff target with no coordination-plane config
                // recorded. A named target means a NON-EMPTY root set, which now
                // mandates a live lease -- and with no config there is no way to
                // obtain or commit one. Fail closed rather than relinquish the
                // role lease-less: the mandatory-lease guarantee is encoded here,
                // not left resting on the (implicit, unencoded) assumption that a
                // confirmed peer cannot exist without config. Under the
                // deterministic simulator config is always absent by design and
                // there is no real coordination plane, so a demotion there keeps
                // its pre-existing local-only fallthrough (see the `_` arm).
                #[cfg(not(madsim))]
                (Some(target_device_id), false) => {
                    lease_acquisition_failed = true;
                    tracing::warn!(
                        group_id,
                        target_device_id = %target_device_id,
                        "confirmed a ready replica but cannot obtain the mandatory handoff lease: \
                         coordination-plane configuration is unavailable"
                    );
                    Err(())
                }
                // Empty root set (vacuously ready -- no confirmed peer to name, no
                // lease required), and, under the simulator, the (Some, false) case
                // above (which is not compiled there) as its local-only path.
                _ => Ok(None),
            };
            let Ok(handoff_result) = coordination_result else {
                if lease_acquisition_failed {
                    return Err(demotion_handoff_lease_failure_message());
                }
                return Err(
                    "refusing to drop full-replica status: the coordination plane could not \
                 confirm the target device is still an active eager full replica for this \
                 group; re-run set-storage-mode to re-confirm"
                        .to_string(),
                );
            };
            // Atomic: re-enumerate the root set and, only if its digest still
            // equals the one the peer confirmed against, flip the policy --
            // both in one transaction, so no watcher write can slip in
            // between.
            //
            // Fix-saga: when `role_loss_operation_id` is `Some`, the
            // coordination-worker role-loss commit above already succeeded, so a
            // failure here (digest mismatch OR a storage error -- both handled
            // identically) must not just return an error and leave the Worker
            // and this device disagreeing about full-replica status. Compensate
            // by reverting the Worker back to `eager` instead of erroring bare.
            // When `role_loss_operation_id` is `None`, no Worker commit
            // happened (an empty root set, or no coordination-plane config), so
            // this is exactly the pre-existing local-only failure path,
            // unchanged.
            let recheck_result = self.repository.recheck_digest_then_set_materialization_policy(
                group_id,
                &local_path,
                MaterializationPolicy::OnDemand,
                digest_at_check,
            );
            let local_failure_reason = match &recheck_result {
                Ok(true) => None,
                Ok(false) => Some(
                    "this group's durable file/version set changed between the readiness check and \
                     the commit, so the earlier confirmation no longer covers it"
                        .to_string(),
                ),
                Err(e) => Some(e.to_string()),
            };
            let Some(local_failure_reason) = local_failure_reason else {
                if let Some(operation_id) = &role_loss_operation_id {
                    self.role_loss.settle_success(operation_id);
                }
                return Ok(handoff_result);
            };
            let Some(operation_id) = role_loss_operation_id else {
                return Err(format!(
                    "refusing to drop full-replica status: {local_failure_reason}; re-run \
                 set-storage-mode to re-confirm"
                ));
            };
            return Err(match self.role_loss.compensate(&operation_id).await {
                Ok(()) => format!(
                "demotion was committed on the coordination plane but the matching local change \
                 failed ({local_failure_reason}); the operation was SAFELY ROLLED BACK -- this \
                 device's full-replica status was restored on the coordination plane. Re-run \
                 set-storage-mode to try again."
            ),
                Err(compensation_err) => format!(
                "demotion was committed on the coordination plane but the matching local change \
                 failed ({local_failure_reason}); the automatic rollback could not complete \
                 ({compensation_err}) and will be retried automatically until it succeeds -- \
                 this device may briefly appear demoted on the coordination plane even though \
                 it is still storing this group eagerly locally."
            ),
            });
        }
        // Reached for a PROMOTION (`on_demand = false`), and for a redundant
        // on-demand request from a device that is not currently an eager full
        // replica (nothing to hand off, so the demotion branch above never
        // applies). Only the promotion direction needs a coordination-plane
        // write here: a demotion's write is the role-loss commit above,
        // already done by the time execution reaches this point. Written
        // BEFORE the local flip below, and its failure aborts before the flip
        // runs (via `?`), mirroring the demotion branch's own ordering.
        //
        // Unlike a demotion, a promotion has no ready-peer gate that would
        // independently fail closed when this daemon is disconnected from the
        // coordination plane. So if the mode write is silently skipped when no
        // config is recorded, a promotion would flip local policy to eager while
        // the coordination plane stays on-demand -- and it would NOT self-heal,
        // since re-running the command sees the local mode already at the target
        // and no-ops. Fail closed instead: in production a missing config means
        // the daemon is not connected to the coordination plane (started before
        // login, or a token was lost and it was not restarted), so refuse rather
        // than diverge. The local flip below is never reached in that case.
        #[cfg(not(madsim))]
        if !on_demand {
            if !self.coordination.is_configured() {
                return Err(
                "not connected to the coordination plane; cannot change storage mode (ensure the \
                 daemon is logged in; restart it if you logged in after it started)"
                    .to_string(),
            );
            };
            self.coordination.set_storage_mode(group_id, &self.device_id, "eager").await?;
        }
        // Under the deterministic simulator no coordination-plane config is
        // ever recorded, so config is ALWAYS absent by design and there is no
        // real coordination plane to write to -- a promotion proceeds
        // local-only here, exactly as a madsim demotion's local-only
        // fallthrough above does.
        let policy =
            if on_demand { MaterializationPolicy::OnDemand } else { MaterializationPolicy::Eager };
        self.repository
            .set_materialization_policy(&local_path, policy)
            .map_err(|e| e.to_string())?;
        Ok(None)
    }

    /// Refuses to unlink an eager (full-replica) folder on this device unless
    /// the handoff-readiness port confirms some OTHER full replica is, right
    /// now, durably holding the current version of every file in the group.
    /// Because there is no central storage, a full replica is a group's only
    /// durable copy, so unlinking the last one before a confirmed handoff
    /// risks permanent data loss -- merely having another device's row
    /// recorded as "also a full replica" is not enough, since that device
    /// could be offline, behind, or missing blocks (this is the same gap
    /// `set_storage_mode`'s demotion gate closes; unlink is the same hazard
    /// by a different name). Unlinking an on-demand link (this device is a
    /// cache, not a durable holder) is always allowed regardless. A missing
    /// or unreadable link list defers to `remove_link` for the real outcome
    /// rather than blocking.
    ///
    /// `force` bypasses the gate for a genuinely dead sole replica that would
    /// otherwise have no way to ever unlink -- every forced override is
    /// logged here as an audit trail (`tracing::warn!`), since bypassing this
    /// gate can permanently lose the only copy of the group's data.
    ///
    /// The readiness confirmation is itself a peer round trip, so there is a
    /// real window between it succeeding and the unlink actually committing
    /// during which this device's own durability-root set could change (a
    /// local edit lands). To close that TOCTOU, the digest the peer was
    /// confirmed against is re-checked and the link row removed together, in
    /// one write transaction, so a concurrent watcher index write cannot
    /// interleave between the re-check and the removal; a digest that no
    /// longer matches is treated exactly like an unconfirmed peer -- refused
    /// unless `--force`. See `set_storage_mode`'s matching comment for the
    /// demote side of the same pattern.
    ///
    /// Note this atomic re-check guards only the coordination-plane ROLE flip
    /// (removing this device's eager link), not block deletion. Actually
    /// reclaiming any version's blocks stays separately gated, per file, by
    /// the on-demand eviction custody check, which is the real backstop
    /// against dropping the last copy of a version.
    ///
    /// Returns which removal step the caller still owes: the eager ready path
    /// removes the link atomically here (`AlreadyRemoved`); every other path
    /// leaves the plain removal to the caller (`RemoveNormally`).
    pub(crate) async fn ensure_unlink_keeps_a_full_replica(
        &self,
        local_path: &str,
        force: bool,
    ) -> Result<UnlinkCommit, String> {
        let Some(link) = self
            .repository
            .list_links()
            .map_err(|e| {
                format!("refusing to unlink because the local link table could not be read: {e}")
            })?
            .into_iter()
            .find(|l| l.local_path == local_path)
        else {
            return Ok(UnlinkCommit::RemoveNormally);
        };
        if link.materialization_policy != MaterializationPolicy::Eager {
            return Ok(UnlinkCommit::RemoveNormally);
        }
        // A confirmed whole-group handoff yields the exact root-set digest it
        // was made against (and, when a real peer confirmed it, that peer's
        // device id); the atomic method below re-enumerates and removes the
        // link in one transaction only if that digest still holds.
        let mut lease_acquisition_failed = false;
        if let Some((digest_at_check, ready_peer_device_id)) =
            self.readiness.full_replica_handoff_ready_digest_and_peer(&link.group_id).await
        {
            // This device giving up its own eager status is exactly the
            // role-loss shape coordination-worker's handoff-commit endpoint
            // guards: confirm the named target is currently Active+eager and
            // commit the role loss (`storage_mode` narrows to on-demand)
            // atomically, coordination-side, before this device also removes
            // its own local link. Only attempted when both a real confirming
            // peer was named (not the vacuously-ready empty-group case,
            // which has no peer to target) and this device actually has
            // coordination-plane config recorded -- otherwise this falls
            // back to exactly the pre-existing purely-local gate, unchanged.
            // `Ok(None)`: no coordination-plane commit was attempted (falls
            // back to the pre-existing purely-local gate) or attempted and
            // refused (fail closed, same as an unconfirmed peer). `Ok(Some(result))`:
            // a commit was attempted and succeeded, to be threaded into the
            // eventual `UnlinkResponse`.
            //
            // Fix-saga: filled in inside the `Some(lease_id)` arm below,
            // right before the coordination-worker commit, and consulted
            // after the local recheck further down to close out (success)
            // or compensate (failure) the journal row it names.
            let mut role_loss_operation_id: Option<String> = None;
            let coordination_result = match (
                &ready_peer_device_id,
                self.coordination.is_configured(),
            ) {
                (Some(target_device_id), true) => {
                    // A real confirming peer was named, i.e. a non-empty
                    // root set -- a live, peer-attested lease is now
                    // MANDATORY, not merely looked up best-effort: ask
                    // the confirmed target directly, over the
                    // authenticated peer channel, to verify and pin its
                    // own durability-root set and hand back a lease
                    // naming it, and refuse the whole commit if none can
                    // be obtained (unreachable, refused, or a digest
                    // mismatch -- the target isn't actually caught up to
                    // this device's exact set). The `--force` override
                    // below still lets a forced unlink proceed with no
                    // lease at all; this gate only governs the
                    // non-forced path.
                    match self
                        .readiness
                        .obtain_handoff_lease_from_peer(
                            &link.group_id,
                            target_device_id,
                            digest_at_check,
                        )
                        .await
                    {
                        None => {
                            lease_acquisition_failed = true;
                            tracing::warn!(
                                group_id = %link.group_id,
                                local_path,
                                target_device_id = %target_device_id,
                                "could not obtain a live handoff lease from the confirmed target \
                                 peer; a lease is mandatory for a non-empty root set -- unlink \
                                 readiness gate treats this the same as an unconfirmed peer (use \
                                 --force to override)"
                            );
                            Err(())
                        }
                        Some(lease_id) => {
                            // Fix-saga: persist the durable Prepared journal row
                            // FIRST and fail closed if it can't be written -- see
                            // `set_storage_mode`'s matching Fix-saga comment. A
                            // failed Prepared write routes to the same `Err(())`
                            // the no-lease case uses, so the force-or-refuse tail
                            // below still governs (a `--force` unlink can still
                            // proceed, latching `DurabilityUnknown`; a non-forced
                            // one is refused) -- but the Worker role-loss commit is
                            // never reached without a durable rollback record.
                            match self.role_loss.open_operation(
                                &link.group_id,
                                target_device_id,
                                &lease_id,
                                yadorilink_replica_domain::session_state::RoleLossAction::Unlink,
                                local_path,
                            ) {
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        group_id = %link.group_id,
                                        local_path,
                                        target_device_id = %target_device_id,
                                        "refusing the online unlink handoff: could not persist the \
                                         durable role-loss rollback journal, so the role loss must \
                                         not be committed on the coordination plane"
                                    );
                                    Err(())
                                }
                                Ok(operation_id) => {
                                    match self
                                        .coordination
                                        .commit_handoff_role_loss(
                                            &link.group_id,
                                            &self.device_id,
                                            target_device_id,
                                            Some(lease_id.as_str()),
                                            "demote",
                                            &operation_id,
                                        )
                                        .await
                                    {
                                        // `digest_at_check` is this
                                        // device's own local
                                        // durability-root digest, paired
                                        // here purely for the caller's
                                        // `HandoffResult.root_digest`
                                        // output -- never itself sent to
                                        // coordination-worker.
                                        RoleLossCommitOutcome::Committed(result) => {
                                            self.role_loss.mark_worker_committed(
                                                &operation_id,
                                                result.membership_generation,
                                            );
                                            role_loss_operation_id = Some(operation_id);
                                            Ok(Some((result, digest_at_check)))
                                        }
                                        RoleLossCommitOutcome::DefinitelyRejected(e) => {
                                            self.role_loss.discard_operation(&operation_id);
                                            tracing::warn!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                target_device_id = %target_device_id,
                                                "coordination-plane handoff role-loss commit failed; \
                                                 unlink readiness gate treats this the same as an \
                                                 unconfirmed peer"
                                            );
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Ambiguous(e) => {
                                            tracing::error!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "unlink role-loss commit outcome is ambiguous; retaining the \
                                                 Prepared journal and compensating Worker state back to eager"
                                            );
                                            if let Err(compensation_error) =
                                                self.role_loss.compensate(&operation_id).await
                                            {
                                                tracing::error!(
                                                    error = %compensation_error,
                                                    operation_id,
                                                    "immediate ambiguous unlink compensation failed; the periodic \
                                                     reconciler will retry"
                                                );
                                            }
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Conflict(e) => {
                                            tracing::error!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "unlink role-loss commit's operation_id conflicts with a \
                                                 differently-shaped request already recorded -- operator \
                                                 attention required"
                                            );
                                            Err(())
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // A confirmed handoff target with no coordination-plane
                // config recorded -- a NON-EMPTY root set that now
                // mandates a live lease, with no way to obtain one. Fail
                // closed exactly like the no-lease-obtainable case above
                // (`Err(())`), which the tail below routes to the
                // existing force-or-refuse handling -- so `--force`
                // still proceeds (latching `DurabilityUnknown`), a
                // non-forced unlink is refused, and the mandatory-lease
                // guarantee is encoded rather than resting on the
                // implicit assumption that a confirmed peer cannot exist
                // without config. Under the deterministic simulator
                // config is always absent by design, so this case is not
                // compiled there and the `_` arm's pre-existing
                // local-only fallthrough stands.
                #[cfg(not(madsim))]
                (Some(target_device_id), false) => {
                    lease_acquisition_failed = true;
                    tracing::warn!(
                        group_id = %link.group_id,
                        local_path,
                        target_device_id = %target_device_id,
                        "confirmed a ready replica but cannot obtain the mandatory handoff lease: \
                         coordination-plane configuration is unavailable"
                    );
                    Err(())
                }
                // Empty root set (vacuously ready -- no confirmed peer to
                // name, no lease required), and, under the simulator,
                // the (Some, false) case above (not compiled there) as
                // its local-only path.
                _ => Ok(None),
            };
            if let Ok(handoff_result) = coordination_result {
                let recheck_result = self.repository.recheck_digest_then_remove_link(
                    &link.group_id,
                    local_path,
                    digest_at_check,
                );
                match recheck_result {
                    Ok(true) => {
                        if let Some(operation_id) = &role_loss_operation_id {
                            self.role_loss.settle_success(operation_id);
                        }
                        return Ok(UnlinkCommit::AlreadyRemoved(handoff_result));
                    }
                    Ok(false) | Err(_) if role_loss_operation_id.is_some() => {
                        // Fix-saga: the Worker commit above already succeeded, so a
                        // local failure here (digest mismatch OR a storage error --
                        // both handled identically) must not silently fall through to
                        // `--force` completing an unlink whose digest was never
                        // re-verified against the peer confirmation, nor leave a bare
                        // split state on the non-forced path. Compensate by reverting
                        // the Worker back to `eager` instead -- see
                        // `set_storage_mode`'s matching Fix-saga comment for the full
                        // rationale (revert, never force-complete, once the Worker
                        // has already committed).
                        let operation_id = role_loss_operation_id
                            .clone()
                            .expect("guarded by role_loss_operation_id.is_some() above");
                        let local_failure_reason = match &recheck_result {
                            Ok(false) => {
                                "this group's durable file/version set changed between the \
                                          readiness check and the commit, so the earlier \
                                          confirmation no longer covers it"
                                    .to_string()
                            }
                            Err(e) => e.to_string(),
                            Ok(true) => unreachable!("Ok(true) handled by the arm above"),
                        };
                        return Err(match self.role_loss.compensate(&operation_id).await {
                            Ok(()) => format!(
                                "unlink was committed on the coordination plane but the matching \
                                 local removal failed ({local_failure_reason}); the operation was \
                                 SAFELY ROLLED BACK -- this device's full-replica status was \
                                 restored on the coordination plane. Re-run unlink to try again."
                            ),
                            Err(compensation_err) => format!(
                                "unlink was committed on the coordination plane but the matching \
                                 local removal failed ({local_failure_reason}); the automatic \
                                 rollback could not complete ({compensation_err}) and will be \
                                 retried automatically until it succeeds -- this device may briefly \
                                 appear demoted on the coordination plane even though it is still \
                                 storing this group eagerly locally."
                            ),
                        });
                    }
                    // No coordination-worker commit happened (empty root set,
                    // or no coordination-plane config) -- exactly the
                    // pre-existing behavior: the root set moved between the
                    // peer confirmation and the atomic re-check, so fall
                    // through to the same force-or-refuse handling as an
                    // unconfirmed peer.
                    Ok(false) => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        if force {
            tracing::warn!(
                group_id = %link.group_id,
                local_path,
                "forced unlink of an eager full replica with no other full replica confirmed \
                 ready -- proceeding anyway; this may have permanently lost the only complete \
                 copy of this folder's data"
            );
            // This override is exactly the case the local durability-status
            // latch exists for: the group's remaining local replica (if any)
            // must not be able to report `Healthy`/"synced" again until a real
            // whole-group handoff re-check says so, even though nothing else
            // about its own files just changed.
            self.repository
                .latch_group_durability_unknown(&link.group_id)
                .map_err(|e| e.to_string())?;
            return Ok(UnlinkCommit::RemoveNormally);
        }
        if lease_acquisition_failed {
            return Err(unlink_handoff_lease_failure_message(local_path));
        }
        Err(format!(
            "refusing to unlink {local_path}: no other full replica is confirmed ready to durably \
             hold every file in this group yet, so unlinking it may permanently lose the only \
             complete copy of this folder's data. Wait for another full replica to finish syncing, \
             or re-run with --force to unlink anyway (data-loss risk)."
        ))
    }

    /// Durability gate, atomic link removal (or normal removal), and the
    /// legacy duplicate-root recovery restart of a surviving link -- the
    /// exact sequence `control_socket`'s `Unlink` handler used to run
    /// inline.
    pub(crate) async fn unlink(
        &self,
        local_path: &str,
        force: bool,
    ) -> Result<UnlinkOutcome, String> {
        // If this is recovery from a legacy two-live-roots state, persist the
        // survivor's additive-scan protection BEFORE anything can remove the
        // departing link. A crash after the unlink commit must therefore
        // never leave a seemingly healthy one-link group whose first scan
        // tombstones files that only existed under the departed root.
        let ambiguity_recovery =
            self.prepare_ambiguity_recovery(local_path).map_err(|e| e.to_string())?;
        match self.ensure_unlink_keeps_a_full_replica(local_path, force).await {
            Ok(commit) => {
                self.runtime.stop_link_watch(local_path).await;
                let (removed, handoff_result) = match commit {
                    UnlinkCommit::AlreadyRemoved(handoff_result) => (Ok(()), handoff_result),
                    UnlinkCommit::RemoveNormally => (self.repository.remove_link(local_path), None),
                };
                if removed.is_ok() {
                    if let Some(recovery) = ambiguity_recovery {
                        if recovery.survivors.len() == 1 {
                            let survivor = recovery.survivors[0].clone();
                            self.runtime.stop_link_watch(&survivor).await;
                            if let Err(e) = self
                                .runtime
                                .start_link_watch(survivor.clone(), recovery.group_id.clone())
                            {
                                tracing::error!(
                                    group_id = %recovery.group_id,
                                    local_path = %survivor,
                                    error = %e,
                                    "duplicate-root recovery removed the extra link but could not restart the survivor; the group remains fail-closed until a relink or daemon restart"
                                );
                            }
                        }
                    }
                }
                removed.map_err(|e| e.to_string()).map(|()| UnlinkOutcome {
                    handoff: handoff_result.map(|(hr, root_digest)| HandoffOutcome {
                        target_device_id: hr.target_device_id,
                        root_digest,
                        membership_generation: hr.membership_generation,
                        lease_id: hr.lease_id,
                    }),
                })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use yadorilink_replica_domain::session_state::FolderLink;
    use yadorilink_replica_domain::session_state::MaterializationPolicy;

    use super::*;
    use crate::application::ports::BoxFuture;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Latch(String),
        RemoveLink(String),
        SetPolicy(String),
        OpenOperation(String),
        MarkWorkerCommitted(String),
        DiscardOperation(String),
        SettleSuccess(String),
        Compensate(String),
        StartWatch(String),
        StopWatch(String),
    }

    #[derive(Default)]
    struct FakeRepository {
        calls: Mutex<Vec<Call>>,
        links: Mutex<Vec<FolderLink>>,
        recheck_policy_result: Mutex<VecDeque<Result<bool, crate::sync_error::SyncError>>>,
        recheck_remove_result: Mutex<VecDeque<Result<bool, crate::sync_error::SyncError>>>,
    }

    impl FakeRepository {
        fn with_link(self, link: FolderLink) -> Self {
            self.links.lock().unwrap().push(link);
            self
        }
    }

    impl ReplicaRoleRepository for FakeRepository {
        fn list_links(&self) -> Result<Vec<FolderLink>, crate::sync_error::SyncError> {
            Ok(self.links.lock().unwrap().clone())
        }

        fn live_link_local_path_for_group(
            &self,
            group_id: &str,
        ) -> Result<Option<String>, crate::sync_error::SyncError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .iter()
                .find(|l| l.group_id == group_id)
                .map(|l| l.local_path.clone()))
        }

        fn recheck_digest_then_set_materialization_policy(
            &self,
            _group_id: &str,
            local_path: &str,
            _policy: MaterializationPolicy,
            _expected_digest: [u8; 32],
        ) -> Result<bool, crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(Call::SetPolicy(local_path.to_string()));
            self.recheck_policy_result.lock().unwrap().pop_front().unwrap_or(Ok(true))
        }

        fn recheck_digest_then_remove_link(
            &self,
            _group_id: &str,
            local_path: &str,
            _expected_digest: [u8; 32],
        ) -> Result<bool, crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(Call::RemoveLink(local_path.to_string()));
            self.recheck_remove_result.lock().unwrap().pop_front().unwrap_or(Ok(true))
        }

        fn remove_link(&self, local_path: &str) -> Result<(), crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(Call::RemoveLink(local_path.to_string()));
            Ok(())
        }

        fn set_materialization_policy(
            &self,
            local_path: &str,
            _policy: MaterializationPolicy,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(Call::SetPolicy(local_path.to_string()));
            Ok(())
        }

        fn latch_group_durability_unknown(
            &self,
            group_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(Call::Latch(group_id.to_string()));
            Ok(())
        }

        fn arm_duplicate_recovery_paths(
            &self,
            _group_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            Ok(())
        }

        fn set_suppress_tombstones(
            &self,
            _local_path: &str,
            _suppress: bool,
        ) -> Result<(), crate::sync_error::SyncError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRoleLoss {
        calls: Mutex<Vec<Call>>,
        open_result: Mutex<VecDeque<Result<String, String>>>,
        compensate_result: Mutex<VecDeque<Result<(), String>>>,
    }

    impl RoleLossJournal for FakeRoleLoss {
        fn open_operation(
            &self,
            _group_id: &str,
            _target_device_id: &str,
            _lease_id: &str,
            _action: yadorilink_replica_domain::session_state::RoleLossAction,
            _local_path: &str,
        ) -> Result<String, String> {
            let result =
                self.open_result.lock().unwrap().pop_front().unwrap_or(Ok("op-1".to_string()));
            if let Ok(id) = &result {
                self.calls.lock().unwrap().push(Call::OpenOperation(id.clone()));
            }
            result
        }

        fn mark_worker_committed(&self, operation_id: &str, _membership_generation: i64) {
            self.calls.lock().unwrap().push(Call::MarkWorkerCommitted(operation_id.to_string()));
        }

        fn discard_operation(&self, operation_id: &str) {
            self.calls.lock().unwrap().push(Call::DiscardOperation(operation_id.to_string()));
        }

        fn settle_success(&self, operation_id: &str) {
            self.calls.lock().unwrap().push(Call::SettleSuccess(operation_id.to_string()));
        }

        fn compensate<'a>(&'a self, operation_id: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(Call::Compensate(operation_id.to_string()));
                self.compensate_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
            })
        }
    }

    #[derive(Default)]
    struct FakeReadiness {
        full_replica: AtomicBool,
        digest_and_peer: Mutex<VecDeque<Option<([u8; 32], Option<String>)>>>,
        lease: Mutex<VecDeque<Option<String>>>,
    }

    impl HandoffReadinessPort for FakeReadiness {
        fn is_local_full_replica(&self, _group_id: &str) -> bool {
            self.full_replica.load(Ordering::SeqCst)
        }

        fn full_replica_handoff_ready_digest_and_peer<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> BoxFuture<'a, Option<([u8; 32], Option<String>)>> {
            Box::pin(async move { self.digest_and_peer.lock().unwrap().pop_front().flatten() })
        }

        fn obtain_handoff_lease_from_peer<'a>(
            &'a self,
            _group_id: &'a str,
            _target_peer_device_id: &'a str,
            _my_digest: [u8; 32],
        ) -> BoxFuture<'a, Option<String>> {
            Box::pin(async move { self.lease.lock().unwrap().pop_front().flatten() })
        }
    }

    #[derive(Default)]
    struct FakeCoordination {
        configured: AtomicBool,
        commit_result: Mutex<VecDeque<RoleLossCommitOutcome>>,
        set_storage_mode_calls: Mutex<u32>,
        set_storage_mode_result: Mutex<VecDeque<Result<(), String>>>,
    }

    impl FakeCoordination {
        fn configured() -> Self {
            let this = Self::default();
            this.configured.store(true, Ordering::SeqCst);
            this
        }
    }

    impl RoleLossCoordination for FakeCoordination {
        fn is_configured(&self) -> bool {
            self.configured.load(Ordering::SeqCst)
        }

        fn commit_handoff_role_loss<'a>(
            &'a self,
            _group_id: &'a str,
            _source_device_id: &'a str,
            _target_device_id: &'a str,
            _lease_id: Option<&'a str>,
            _action: &'a str,
            _operation_id: &'a str,
        ) -> BoxFuture<'a, RoleLossCommitOutcome> {
            Box::pin(async move {
                self.commit_result.lock().unwrap().pop_front().expect("missing fake commit result")
            })
        }

        fn set_storage_mode<'a>(
            &'a self,
            _group_id: &'a str,
            _device_id: &'a str,
            _mode: &'a str,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                *self.set_storage_mode_calls.lock().unwrap() += 1;
                self.set_storage_mode_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
            })
        }
    }

    #[derive(Default)]
    struct FakeRuntime {
        calls: Mutex<Vec<Call>>,
        start_result: Mutex<VecDeque<Result<(), String>>>,
    }

    impl LinkRuntimePort for FakeRuntime {
        fn start_link_watch(&self, local_path: String, _group_id: String) -> Result<(), String> {
            self.calls.lock().unwrap().push(Call::StartWatch(local_path));
            self.start_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }

        fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(Call::StopWatch(local_path.to_string()));
            })
        }
    }

    fn link(group_id: &str, policy: MaterializationPolicy) -> FolderLink {
        FolderLink {
            local_path: "/home/alice/Photos".to_string(),
            group_id: group_id.to_string(),
            paused: false,
            materialization_policy: policy,
            max_local_size_bytes: None,
            orphaned: false,
        }
    }

    /// Fixed-answer [`PlaceholderPipelineCapabilityPort`] fake -- defaults to
    /// connected since none of this module's own unit tests exercise the
    /// disconnected-gate rejection itself (that's covered by the daemon
    /// integration tests in `tests/role_loss_saga.rs`/
    /// `tests/storage_mode_orchestration.rs`).
    struct FakePlaceholderPipeline {
        connected: bool,
    }

    impl Default for FakePlaceholderPipeline {
        fn default() -> Self {
            Self { connected: true }
        }
    }

    impl PlaceholderPipelineCapabilityPort for FakePlaceholderPipeline {
        fn is_connected(&self) -> bool {
            self.connected
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn service(
        repository: Arc<FakeRepository>,
        role_loss: Arc<FakeRoleLoss>,
        readiness: Arc<FakeReadiness>,
        coordination: Arc<FakeCoordination>,
        runtime: Arc<FakeRuntime>,
    ) -> ReplicaRoleService {
        ReplicaRoleService::new(
            "device-a".to_string(),
            repository,
            role_loss,
            readiness,
            coordination,
            runtime,
            Arc::new(FakePlaceholderPipeline::default()),
        )
    }

    // ===== set_storage_mode =====

    #[tokio::test]
    async fn promotion_writes_coordination_before_the_local_flip() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let result =
            service(repository.clone(), role_loss, readiness, coordination.clone(), runtime)
                .set_storage_mode("group-1", false)
                .await;

        assert!(result.is_ok());
        assert_eq!(*coordination.set_storage_mode_calls.lock().unwrap(), 1);
        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&Call::SetPolicy("/home/alice/Photos".to_string())));
    }

    #[tokio::test]
    async fn promotion_without_coordination_config_fails_closed() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        let coordination = Arc::new(FakeCoordination::default());
        let runtime = Arc::new(FakeRuntime::default());

        let result = service(repository.clone(), role_loss, readiness, coordination, runtime)
            .set_storage_mode("group-1", false)
            .await;

        assert!(result.is_err());
        assert!(repository.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn demotion_of_a_vacuously_ready_empty_group_flips_locally_with_no_journal() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.full_replica.store(true, Ordering::SeqCst);
        readiness.digest_and_peer.lock().unwrap().push_back(Some(([1u8; 32], None)));
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
            .set_storage_mode("group-1", true)
            .await;

        assert!(result.is_ok());
        assert!(role_loss.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn demotion_with_confirmed_peer_opens_journal_commits_then_settles() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.full_replica.store(true, Ordering::SeqCst);
        readiness
            .digest_and_peer
            .lock()
            .unwrap()
            .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
        readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
            HandoffCommitResult {
                target_device_id: "device-b".to_string(),
                membership_generation: 3,
                lease_id: Some("lease-1".to_string()),
            },
        ));
        let runtime = Arc::new(FakeRuntime::default());

        let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
            .set_storage_mode("group-1", true)
            .await;

        assert!(result.is_ok());
        let calls = role_loss.calls.lock().unwrap();
        assert!(calls.contains(&Call::OpenOperation("op-1".to_string())));
        assert!(calls.contains(&Call::MarkWorkerCommitted("op-1".to_string())));
        assert!(calls.contains(&Call::SettleSuccess("op-1".to_string())));
    }

    #[tokio::test]
    async fn demotion_lease_unavailable_refuses_with_the_lease_failure_message() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.full_replica.store(true, Ordering::SeqCst);
        readiness
            .digest_and_peer
            .lock()
            .unwrap()
            .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
        readiness.lease.lock().unwrap().push_back(None);
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let result = service(repository, role_loss, readiness, coordination, runtime)
            .set_storage_mode("group-1", true)
            .await;

        assert_eq!(result.unwrap_err(), demotion_handoff_lease_failure_message());
    }

    #[tokio::test]
    async fn demotion_ambiguous_commit_compensates_and_refuses() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.full_replica.store(true, Ordering::SeqCst);
        readiness
            .digest_and_peer
            .lock()
            .unwrap()
            .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
        readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .commit_result
            .lock()
            .unwrap()
            .push_back(RoleLossCommitOutcome::Ambiguous("timeout".to_string()));
        let runtime = Arc::new(FakeRuntime::default());

        let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
            .set_storage_mode("group-1", true)
            .await;

        assert!(result.is_err());
        assert!(role_loss.calls.lock().unwrap().contains(&Call::Compensate("op-1".to_string())));
    }

    // ===== ensure_unlink_keeps_a_full_replica =====

    #[tokio::test]
    async fn last_full_replica_cannot_unlink() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.digest_and_peer.lock().unwrap().push_back(None);
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let result = service(repository, role_loss, readiness, coordination, runtime)
            .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn forced_unlink_bypasses_the_gate_and_latches_durability_unknown() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.digest_and_peer.lock().unwrap().push_back(None);
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let commit = service(repository.clone(), role_loss, readiness, coordination, runtime)
            .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", true)
            .await
            .unwrap();

        assert_eq!(commit, UnlinkCommit::RemoveNormally);
        assert!(repository.calls.lock().unwrap().contains(&Call::Latch("group-1".to_string())));
    }

    #[tokio::test]
    async fn on_demand_link_always_allowed_no_gate_touched() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let commit = service(repository, role_loss, readiness, coordination, runtime)
            .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false)
            .await
            .unwrap();

        assert_eq!(commit, UnlinkCommit::RemoveNormally);
    }

    #[tokio::test]
    async fn ready_eager_unlink_removes_atomically_via_the_readiness_and_coordination_ports() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness
            .digest_and_peer
            .lock()
            .unwrap()
            .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
        readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
            HandoffCommitResult {
                target_device_id: "device-b".to_string(),
                membership_generation: 1,
                lease_id: Some("lease-1".to_string()),
            },
        ));
        let runtime = Arc::new(FakeRuntime::default());

        let commit = service(repository, role_loss.clone(), readiness, coordination, runtime)
            .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false)
            .await
            .unwrap();

        assert!(matches!(commit, UnlinkCommit::AlreadyRemoved(Some(_))));
        assert!(role_loss.calls.lock().unwrap().contains(&Call::SettleSuccess("op-1".to_string())));
    }

    // ===== unlink =====

    #[tokio::test]
    async fn unlink_stops_the_watcher_and_removes_the_link_normally() {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
        );
        let role_loss = Arc::new(FakeRoleLoss::default());
        let readiness = Arc::new(FakeReadiness::default());
        let coordination = Arc::new(FakeCoordination::configured());
        let runtime = Arc::new(FakeRuntime::default());

        let outcome =
            service(repository.clone(), role_loss, readiness, coordination, runtime.clone())
                .unlink("/home/alice/Photos", false)
                .await
                .unwrap();

        assert!(outcome.handoff.is_none());
        assert!(runtime
            .calls
            .lock()
            .unwrap()
            .contains(&Call::StopWatch("/home/alice/Photos".to_string())));
        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&Call::RemoveLink("/home/alice/Photos".to_string())));
    }
}
