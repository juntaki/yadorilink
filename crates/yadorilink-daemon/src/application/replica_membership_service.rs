use std::sync::Arc;

use uuid::Uuid;
use yadorilink_replica_domain::session_state::{
    MembershipCommitMode, MembershipDurabilityScope, MembershipOperation,
    MembershipOperationAction, MembershipOperationState,
};

use super::model::{MembershipCommitOutcome, MembershipOperationLookup, MembershipRemoteCommand};
use super::ports::{
    HandoffTicketPort, MembershipCoordination, MembershipRepository, ReplicaReadinessPort,
};

/// Owns account-membership changes which can remove a full replica. Every
/// dependency is a port -- no `DaemonState`, no `reqwest`, no
/// `coordination_client` -- see the composition root
/// for what backs each one in production.
pub(crate) struct ReplicaMembershipService {
    device_id: String,
    repository: Arc<dyn MembershipRepository>,
    coordination: Arc<dyn MembershipCoordination>,
    tickets: Arc<dyn HandoffTicketPort>,
    readiness: Arc<dyn ReplicaReadinessPort>,
}

/// High-level command to remove a device from the account.
///
/// Coordination credentials come from the daemon's configured identity and
/// are intentionally absent from this command.
pub(crate) struct RemoveDeviceCommand {
    pub(crate) device_id: String,
    pub(crate) force: bool,
}

/// High-level command to revoke one device from one folder group.
pub(crate) struct RevokeDeviceCommand {
    pub(crate) group_id: String,
    pub(crate) device_id: String,
    pub(crate) force: bool,
}

/// Protocol-independent summary of a lease-bound handoff used by a
/// membership removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MembershipHandoffOutcome {
    pub(crate) group_id: String,
    pub(crate) target_device_id: String,
    pub(crate) lease_id: String,
    pub(crate) membership_generation: u64,
}

/// Result of a fully daemon-owned membership command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicaMembershipOutcome {
    pub(crate) handoffs: Vec<MembershipHandoffOutcome>,
    pub(crate) forced_group_ids: Vec<String>,
    /// Set only when a `--force` removal committed (or may have committed --
    /// see `MembershipCommitOutcome::Committed` on the unknown-scope path)
    /// WITHOUT ever learning which folder groups it put at risk (eager-group
    /// enumeration itself failed). The caller must render this distinctly
    /// from `forced_group_ids` -- the risk here is broader and unenumerated,
    /// not a known list, and `status` stays degraded until the operation
    /// this id names is reconciled.
    pub(crate) unknown_scope_operation_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReplicaMembershipError {
    #[error("local device identity is unavailable")]
    LocalIdentityUnavailable,
    #[error("membership target was not found")]
    TargetNotFound,
    #[error("another full replica is not ready for: {group_ids:?}")]
    ReplicaNotReady { group_ids: Vec<String> },
    #[error("handoff ticket is unavailable for folder group {group_id}")]
    TicketUnavailable { group_id: String },
    #[error("coordination commit was rejected: {detail}")]
    CoordinationRejected { detail: String },
    #[error("coordination result is ambiguous: {detail}")]
    CoordinationAmbiguous { detail: String },
    #[error("durability latch persistence failed for {group_ids:?}: {detail}")]
    DurabilityLatchFailed { group_ids: Vec<String>, detail: String },
    #[error("membership recovery is pending for operation {operation_id}: {detail}")]
    RecoveryPending { operation_id: String, detail: String },
    #[error("coordination transport failed: {detail}")]
    CoordinationTransport { detail: String },
    #[error("local persistence failed: {0}")]
    Persistence(#[from] crate::sync_error::SyncError),
    /// The coordination plane rejected a mutation with HTTP 409 -- this
    /// operation_id already names a DIFFERENT request (should be
    /// astronomically rare given fresh UUIDs, but is a genuine data-
    /// integrity signal, not a transient failure). The journal row is left
    /// exactly as it was (`Prepared`, never advanced) for operator
    /// attention; it must never be silently settled or discarded, and the
    /// caller must never fall through to `--force` on this outcome.
    #[error("operation {operation_id} conflicts with a differently-shaped request already recorded under it: {detail}")]
    OperationConflict { operation_id: String, detail: String },
    /// Persisting the Prepared journal row itself failed -- fail closed:
    /// nothing was sent to the coordination plane, so this is always safe
    /// to simply refuse the whole command (never fall through to a
    /// different membership-mutation strategy without a durable record of
    /// having tried).
    #[error(
        "could not persist the membership recovery journal for operation {operation_id}: {detail}"
    )]
    RecoveryJournalUnavailable { operation_id: String, detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupTicket {
    group_id: String,
    target_device_id: String,
    lease_id: String,
}

fn force_unprotected_groups(
    force: bool,
    unverified: bool,
    group_ids: Vec<String>,
) -> Result<Vec<String>, ReplicaMembershipError> {
    if group_ids.is_empty() && !unverified {
        return Ok(Vec::new());
    }
    if force {
        Ok(group_ids)
    } else {
        Err(ReplicaMembershipError::ReplicaNotReady { group_ids })
    }
}

/// How long a `membership_operations` row must have existed before a
/// reconciliation sweep will touch it. The row is written BEFORE the
/// coordination-plane call it guards, and that call is still in flight for
/// the whole window between the write and the response -- a sweep running
/// concurrently with that window would ask "does a receipt exist yet" and
/// get a legitimate but MISLEADING "not yet" for an operation that is about
/// to succeed a moment later, and (for the `--force`/unknown-scope path)
/// would wrongly conclude "definitely rejected" and discard a marker that
/// still needs to survive. This grace period is generous relative to any
/// single HTTP round trip specifically so a sweep never races the very
/// request that created the row it is looking at.
const MEMBERSHIP_OPERATION_RECONCILE_MIN_AGE_SECS: i64 = 30;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether a Worker lookup's `record` genuinely describes the SAME request
/// this local journal `row` believes it does -- checked before a reconciler
/// ever trusts `record.status`/`record.result` to settle/discard `row`.
/// Comparing only `action`/`removed_device_id` (an earlier version of this
/// reconciler did) is not enough: two different requests can share both
/// while differing in `mode` or which groups/targets/leases are involved,
/// and settling on the wrong one would silently discard or complete the
/// WRONG operation. Delegates the canonicalization itself to
/// `membership_operation_identity::expected_membership_remote_request` --
/// the SAME function Phase 2.1-C2-B's evidence-identity qualification uses,
/// so this reconciler and that classifier can never silently disagree on
/// what "the same request" means.
fn remote_record_matches_local(
    row: &MembershipOperation,
    record: &super::model::MembershipOperationRecord,
) -> bool {
    record.request == super::membership_operation_identity::expected_membership_remote_request(row)
}

/// Whether `mode` sends a coordination-plane ticket/lease that must be
/// released once its journal row is confirmed rejected.
fn operation_uses_tickets(mode: MembershipCommitMode) -> bool {
    matches!(mode, MembershipCommitMode::GuardedRevoke | MembershipCommitMode::HandoffRemoveDevice)
}

impl ReplicaMembershipService {
    pub(crate) fn new(
        device_id: String,
        repository: Arc<dyn MembershipRepository>,
        coordination: Arc<dyn MembershipCoordination>,
        tickets: Arc<dyn HandoffTicketPort>,
        readiness: Arc<dyn ReplicaReadinessPort>,
    ) -> Self {
        Self { device_id, repository, coordination, tickets, readiness }
    }

    pub(crate) async fn remove_device(
        &self,
        command: RemoveDeviceCommand,
    ) -> Result<ReplicaMembershipOutcome, ReplicaMembershipError> {
        self.change_membership(None, command.device_id, command.force).await
    }

    pub(crate) async fn revoke_device(
        &self,
        command: RevokeDeviceCommand,
    ) -> Result<ReplicaMembershipOutcome, ReplicaMembershipError> {
        self.change_membership(Some(command.group_id), command.device_id, command.force).await
    }

    /// Resolves `edge_id` to its `(group_id, device_id)` on the coordination
    /// plane, then runs the same guarded revoke path `revoke_device` runs.
    /// Keeping the resolution here (rather than in the CLI) means the CLI
    /// never lists edges over HTTP itself and can never race the listing
    /// against a raw delete, skipping the durability-readiness gate.
    pub(crate) async fn revoke_edge(
        &self,
        edge_id: String,
        force: bool,
    ) -> Result<ReplicaMembershipOutcome, ReplicaMembershipError> {
        if !self.coordination.is_configured() {
            return Err(ReplicaMembershipError::LocalIdentityUnavailable);
        }
        let resolved = self
            .coordination
            .resolve_edge(&edge_id)
            .await
            .map_err(|detail| ReplicaMembershipError::CoordinationTransport { detail })?;
        let Some((group_id, device_id)) = resolved else {
            // Already gone (revoked earlier, or belongs to a different
            // account view) — idempotent: there is nothing left to revoke.
            return Err(ReplicaMembershipError::TargetNotFound);
        };
        self.change_membership(Some(group_id), device_id, force).await
    }

    async fn change_membership(
        &self,
        scoped_group_id: Option<String>,
        target_device_id: String,
        force: bool,
    ) -> Result<ReplicaMembershipOutcome, ReplicaMembershipError> {
        if !self.coordination.is_configured() {
            return Err(ReplicaMembershipError::LocalIdentityUnavailable);
        }
        let (groups_at_risk, unverified) = match &scoped_group_id {
            Some(group_id) => (vec![group_id.clone()], false),
            None => match self.coordination.fetch_eager_groups(&target_device_id).await {
                Ok(groups) => (groups, false),
                Err(error) => {
                    tracing::warn!(%error, target_device_id, "could not enumerate groups at risk");
                    (Vec::new(), true)
                }
            },
        };

        let forced_group_ids;
        if target_device_id != self.device_id {
            if !unverified {
                if groups_at_risk.is_empty() {
                    match self
                        .run_plain_membership_mutation(
                            &scoped_group_id,
                            &target_device_id,
                            MembershipDurabilityScope::Known,
                            Vec::new(),
                        )
                        .await?
                    {
                        (_, MembershipCommitOutcome::Committed(_)) => {}
                        (_, MembershipCommitOutcome::DefinitelyRejected(detail)) => {
                            return Err(ReplicaMembershipError::CoordinationRejected { detail });
                        }
                        (operation_id, MembershipCommitOutcome::Ambiguous(detail)) => {
                            return Err(ReplicaMembershipError::RecoveryPending {
                                operation_id,
                                detail,
                            });
                        }
                        (operation_id, MembershipCommitOutcome::Conflict(detail)) => {
                            return Err(ReplicaMembershipError::OperationConflict {
                                operation_id,
                                detail,
                            });
                        }
                    }
                    return Ok(ReplicaMembershipOutcome {
                        handoffs: Vec::new(),
                        forced_group_ids: Vec::new(),
                        unknown_scope_operation_id: None,
                    });
                }
                if let Some((handoffs, _tickets)) = self
                    .try_ticket_bound_removal(&scoped_group_id, &target_device_id, &groups_at_risk)
                    .await?
                {
                    return Ok(ReplicaMembershipOutcome {
                        handoffs,
                        forced_group_ids: Vec::new(),
                        unknown_scope_operation_id: None,
                    });
                }
            }
            forced_group_ids = force_unprotected_groups(force, unverified, groups_at_risk.clone())?;
        } else {
            let linked_group_ids: Vec<String> =
                self.repository.list_links()?.into_iter().map(|link| link.group_id).collect();
            let mut not_ready = Vec::new();
            for group_id in &groups_at_risk {
                if !linked_group_ids.contains(group_id)
                    || !self
                        .readiness
                        .another_full_replica_is_ready_excluding(group_id, &target_device_id)
                        .await
                {
                    not_ready.push(group_id.clone());
                }
            }
            forced_group_ids = force_unprotected_groups(force, unverified, not_ready)?;
        }

        // `forced_group_ids` is only ever non-empty when `unverified` is
        // false (see `force_unprotected_groups`) -- `durability_scope`
        // captures the unverified case instead, and its own remote outcome
        // (via the same executor every other mutation goes through) is what
        // a later reconciliation pass resolves the real blast radius from,
        // not a local latch. Groups are latched `DurabilityUnknown` only
        // AFTER this operation's remote mutation is CONFIRMED committed
        // (inside `execute_membership_operation`) -- never pre-commit, so a
        // definitely-rejected or conflicting mutation never leaves a
        // false-positive latch behind.
        let durability_scope = if unverified {
            MembershipDurabilityScope::Unknown
        } else {
            MembershipDurabilityScope::Known
        };

        if force {
            self.coordination
                .record_force_override_audit(&self.device_id, &target_device_id, &forced_group_ids)
                .await;
        }

        match self
            .run_plain_membership_mutation(
                &scoped_group_id,
                &target_device_id,
                durability_scope,
                forced_group_ids.clone(),
            )
            .await?
        {
            (operation_id, MembershipCommitOutcome::Committed(_)) => Ok(ReplicaMembershipOutcome {
                handoffs: Vec::new(),
                forced_group_ids,
                // The removal itself definitely happened (and, for a KNOWN
                // scope, its forced groups are already durably latched --
                // see `execute_membership_operation`). For an UNVERIFIED
                // scope the affected-groups list still isn't known --
                // surface this operation's own id so the caller can render
                // a distinct "scope unknown" warning instead of a plain
                // success, and so reconciliation can resolve the real scope
                // later by looking this same id back up.
                unknown_scope_operation_id: if unverified { Some(operation_id) } else { None },
            }),
            (_, MembershipCommitOutcome::DefinitelyRejected(detail)) => {
                Err(ReplicaMembershipError::CoordinationRejected { detail })
            }
            (operation_id, MembershipCommitOutcome::Ambiguous(detail)) => {
                Err(ReplicaMembershipError::RecoveryPending { operation_id, detail })
            }
            (operation_id, MembershipCommitOutcome::Conflict(detail)) => {
                Err(ReplicaMembershipError::OperationConflict { operation_id, detail })
            }
        }
    }

    /// Runs a plain (non-ticket-bound) membership mutation -- `PlainRevoke`
    /// when `scoped_group_id` names a group, `PlainRemoveDevice` otherwise --
    /// through the same shared `execute_membership_operation` journal+
    /// dispatch path every other membership mutation goes through.
    /// `latch_group_ids` are latched `DurabilityUnknown` only once the
    /// remote mutation is confirmed committed.
    async fn run_plain_membership_mutation(
        &self,
        scoped_group_id: &Option<String>,
        target_device_id: &str,
        durability_scope: MembershipDurabilityScope,
        latch_group_ids: Vec<String>,
    ) -> Result<(String, MembershipCommitOutcome), ReplicaMembershipError> {
        let command = match scoped_group_id {
            Some(group_id) => MembershipRemoteCommand {
                action: MembershipOperationAction::Revoke,
                commit_mode: MembershipCommitMode::PlainRevoke,
                removed_device_id: target_device_id.to_string(),
                group_ids: vec![group_id.clone()],
                target_device_ids: Vec::new(),
                lease_ids: Vec::new(),
                durability_scope,
                latch_group_ids,
            },
            None => MembershipRemoteCommand {
                action: MembershipOperationAction::RemoveDevice,
                commit_mode: MembershipCommitMode::PlainRemoveDevice,
                removed_device_id: target_device_id.to_string(),
                group_ids: Vec::new(),
                target_device_ids: Vec::new(),
                lease_ids: Vec::new(),
                durability_scope,
                latch_group_ids,
            },
        };
        self.execute_membership_operation(command).await
    }

    async fn try_ticket_bound_removal(
        &self,
        scoped_group_id: &Option<String>,
        target_device_id: &str,
        groups_at_risk: &[String],
    ) -> Result<Option<(Vec<MembershipHandoffOutcome>, Vec<GroupTicket>)>, ReplicaMembershipError>
    {
        if groups_at_risk.is_empty() {
            return Ok(None);
        }
        let mut tickets = Vec::with_capacity(groups_at_risk.len());
        for group_id in groups_at_risk {
            let Some(grant) = self.tickets.obtain_ticket(group_id, target_device_id).await else {
                self.release_tickets(target_device_id, &tickets).await;
                return Ok(None);
            };
            let (Some(target), Some(lease_id)) = (grant.target_device_id, grant.lease_id) else {
                self.release_tickets(target_device_id, &tickets).await;
                return Ok(None);
            };
            tickets.push(GroupTicket {
                group_id: group_id.clone(),
                target_device_id: target,
                lease_id,
            });
        }

        let action = if scoped_group_id.is_some() {
            MembershipOperationAction::Revoke
        } else {
            MembershipOperationAction::RemoveDevice
        };
        let commit_mode = if scoped_group_id.is_some() {
            MembershipCommitMode::GuardedRevoke
        } else {
            MembershipCommitMode::HandoffRemoveDevice
        };
        let group_ids: Vec<String> = tickets.iter().map(|t| t.group_id.clone()).collect();
        let target_device_ids: Vec<String> =
            tickets.iter().map(|t| t.target_device_id.clone()).collect();
        let lease_ids: Vec<Option<String>> =
            tickets.iter().map(|t| Some(t.lease_id.clone())).collect();

        let command = MembershipRemoteCommand {
            action,
            commit_mode,
            removed_device_id: target_device_id.to_string(),
            group_ids,
            target_device_ids,
            lease_ids,
            // The ticket/lease mechanics already verified durability up
            // front (that's what a ticket IS), so there is no scope to
            // discover and no group left to latch after the fact.
            durability_scope: MembershipDurabilityScope::Known,
            latch_group_ids: Vec::new(),
        };

        // The Prepared row is correctness-critical. If it cannot be
        // persisted, release the provisional tickets, but fail the entire
        // command -- returning `Ok(None)` here would let `--force` start a
        // DIFFERENT unjournaled membership mutation after the journal write
        // itself already failed, which is exactly the gap
        // `RecoveryJournalUnavailable` exists to prevent.
        let (operation_id, commit) = match self.execute_membership_operation(command).await {
            Ok(result) => result,
            Err(error @ ReplicaMembershipError::RecoveryJournalUnavailable { .. }) => {
                self.release_tickets(target_device_id, &tickets).await;
                return Err(error);
            }
            Err(other) => return Err(other),
        };

        // The handoffs reported back to the caller are reconstructed from
        // the TICKET's own already-known values (group/target/lease) for
        // every mode except a single-group `GuardedRevoke`, where the
        // Worker's response carries a real `membershipGeneration` -- use
        // that when present rather than the always-`0` placeholder every
        // other mode falls back to (a display-only field the CLI doesn't
        // treat as load-bearing).
        let handoffs = |result: &super::model::MembershipCommitResult| {
            if let Some(handoff) = &result.handoff {
                debug_assert_eq!(
                    tickets.len(),
                    1,
                    "a handoff result only exists for GuardedRevoke"
                );
                if let Some(ticket) = tickets.first() {
                    return vec![MembershipHandoffOutcome {
                        group_id: ticket.group_id.clone(),
                        target_device_id: handoff.target_device_id.clone(),
                        lease_id: handoff
                            .lease_id
                            .clone()
                            .unwrap_or_else(|| ticket.lease_id.clone()),
                        membership_generation: handoff.membership_generation as u64,
                    }];
                }
            }
            tickets
                .iter()
                .map(|ticket| MembershipHandoffOutcome {
                    group_id: ticket.group_id.clone(),
                    target_device_id: ticket.target_device_id.clone(),
                    lease_id: ticket.lease_id.clone(),
                    membership_generation: 0,
                })
                .collect::<Vec<_>>()
        };

        match commit {
            MembershipCommitOutcome::Committed(result) => Ok(Some((handoffs(&result), tickets))),
            MembershipCommitOutcome::DefinitelyRejected(detail) => {
                self.release_tickets(target_device_id, &tickets).await;
                // A definitely rejected lease-bound commit is equivalent to
                // an unavailable ticket: the caller may still choose
                // `--force`.
                tracing::warn!(detail, "lease-bound membership commit was definitely rejected");
                Ok(None)
            }
            MembershipCommitOutcome::Ambiguous(detail) => {
                // The coordination plane MAY already have committed this
                // removal (Worker-side deletion could already be done) —
                // do NOT release tickets and do NOT fall through to
                // `--force` / a plain revoke-remove, which would race an
                // already-applied change. `execute_membership_operation`
                // already advanced the journal row to `Ambiguous`; surface
                // a distinct error instead of the usual `Ok(None)` "try
                // force" fallback.
                Err(ReplicaMembershipError::RecoveryPending { operation_id, detail })
            }
            MembershipCommitOutcome::Conflict(detail) => {
                tracing::error!(
                    operation_id,
                    detail,
                    "membership operation_id conflicts with a differently-shaped request already \
                     recorded -- operator attention required"
                );
                Err(ReplicaMembershipError::OperationConflict { operation_id, detail })
            }
        }
    }

    /// Opens a fresh membership-operation journal row for `command`,
    /// retrying under a NEW `operation_id` on a (should be astronomically
    /// rare) UUID collision rather than overwriting the existing row. Fails
    /// closed (no Worker call ever attempted) if the durable write itself
    /// keeps failing.
    fn open_membership_operation(
        &self,
        command: &MembershipRemoteCommand,
    ) -> Result<String, ReplicaMembershipError> {
        const MAX_ID_ATTEMPTS: usize = 4;
        let mut last_operation_id = String::new();
        for _ in 0..MAX_ID_ATTEMPTS {
            let operation_id = Uuid::new_v4().to_string();
            last_operation_id.clone_from(&operation_id);
            match self.repository.try_insert_operation(
                &operation_id,
                command.action,
                command.commit_mode,
                &command.removed_device_id,
                &command.group_ids,
                &command.target_device_ids,
                &command.lease_ids,
                command.durability_scope,
                &command.latch_group_ids,
            ) {
                Ok(true) => return Ok(operation_id),
                // A fresh UUID already names a row -- retry under another
                // one; the existing row is untouched.
                Ok(false) => continue,
                Err(persist_error) => {
                    tracing::error!(
                        error = %persist_error,
                        operation_id,
                        "refusing the membership mutation: could not persist the durable recovery \
                         journal, so the mutation must not be attempted on the coordination plane"
                    );
                    return Err(ReplicaMembershipError::RecoveryJournalUnavailable {
                        operation_id,
                        detail: persist_error,
                    });
                }
            }
        }
        Err(ReplicaMembershipError::RecoveryJournalUnavailable {
            operation_id: last_operation_id,
            detail: "could not allocate a unique membership operation id after repeated collisions"
                .to_string(),
        })
    }

    /// Latches every group in `group_ids` `DurabilityUnknown`, stopping at
    /// the first failure -- used only post-commit, so a partial failure
    /// here means the remote mutation ALREADY happened and must be retried
    /// locally, not treated as if nothing occurred.
    fn latch_forced_groups(&self, group_ids: &[String]) -> Result<(), String> {
        for group_id in group_ids {
            self.repository
                .latch_group_durability_unknown(group_id)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// The single entry point every membership-mutation call site goes
    /// through (ticket-bound revoke/remove, plain revoke, plain remove,
    /// `--force` fallbacks, unverified-scope forced removal). Fixed
    /// internal order:
    ///
    /// 1. Open a fresh `operation_id` (see `open_membership_operation`;
    ///    never reused across calls, even for a `--force` fallback that
    ///    follows a `DefinitelyRejected` guarded attempt -- reusing an id
    ///    across two DIFFERENT requests would itself trip the Worker's own
    ///    fingerprint-conflict guard). Fails closed
    ///    (`RecoveryJournalUnavailable`, no Worker call at all) if this
    ///    write itself fails.
    /// 2. Dispatch the remote mutation for `command.commit_mode`.
    /// 3. Classify the result (`Committed`/`DefinitelyRejected`/`Ambiguous`/
    ///    `Conflict`).
    /// 4. Settle the journal row to match: on `Committed`, latch
    ///    `command.latch_group_ids` THEN settle -- if the latch write
    ///    fails, advance to `LocalSettlementPending` (row kept, retried by
    ///    the next reconciliation sweep) and return `DurabilityLatchFailed`
    ///    instead of a silent success. `DefinitelyRejected` settles and
    ///    deletes the row (terminal, nothing was ever at risk). `Ambiguous`
    ///    keeps the row (unconfirmed). `Conflict` leaves the row untouched
    ///    entirely (still `Prepared`) for operator attention -- it must
    ///    never be silently settled, since a conflict means this
    ///    operation_id may not even describe what we think it does.
    async fn execute_membership_operation(
        &self,
        command: MembershipRemoteCommand,
    ) -> Result<(String, MembershipCommitOutcome), ReplicaMembershipError> {
        let operation_id = self.open_membership_operation(&command)?;

        let outcome = self.coordination.dispatch(&command, &operation_id).await;

        match &outcome {
            MembershipCommitOutcome::Committed(_) => {
                if command.durability_scope == MembershipDurabilityScope::Unknown {
                    // The remote mutation landed, but the AFFECTED-GROUPS
                    // scope is still unknown (that's the whole reason this
                    // row is `Unknown`-scope) -- the row must survive
                    // (still `Prepared`) so `reconcile_unknown_scope` can
                    // look this same operation_id back up, learn the real
                    // scope from the Worker's own result, and only then
                    // latch + discard it. Never settled here.
                } else if command.latch_group_ids.is_empty() {
                    self.repository.settle_operation(&operation_id);
                } else if let Err(detail) = self.latch_forced_groups(&command.latch_group_ids) {
                    self.repository.mark_local_settlement_pending(&operation_id, &detail);
                    return Err(ReplicaMembershipError::DurabilityLatchFailed {
                        group_ids: command.latch_group_ids.clone(),
                        detail,
                    });
                } else {
                    self.repository.settle_operation(&operation_id);
                }
            }
            MembershipCommitOutcome::DefinitelyRejected(_) => {
                self.repository.settle_operation(&operation_id);
            }
            MembershipCommitOutcome::Ambiguous(detail) => {
                self.repository.mark_ambiguous(&operation_id, detail);
            }
            MembershipCommitOutcome::Conflict(_) => {
                // Leave the row exactly as it is (`Prepared`) -- never
                // settled, never discarded.
            }
        }

        Ok((operation_id, outcome))
    }

    async fn release_tickets(&self, target_device_id: &str, tickets: &[GroupTicket]) {
        for ticket in tickets {
            if let Err(error) = self
                .tickets
                .release_ticket(
                    &ticket.group_id,
                    target_device_id,
                    &ticket.target_device_id,
                    &ticket.lease_id,
                )
                .await
            {
                tracing::warn!(
                    error,
                    group_id = ticket.group_id,
                    lease_id = ticket.lease_id,
                    "failed to release a provisional handoff ticket; coordination TTL remains the \
                     backstop"
                );
            }
        }
    }

    /// Releases every provisional handoff ticket a ticket-bound `row` still
    /// holds, once that row's remote mutation is CONFIRMED to have never
    /// committed. A no-op for non-ticket-bound modes (`row.target_device_ids`/
    /// `row.lease_ids` are empty for those, so the zip below naturally
    /// yields nothing).
    async fn release_journaled_tickets(&self, row: &MembershipOperation) {
        if !operation_uses_tickets(row.commit_mode) {
            return;
        }
        for ((group_id, target_device_id), lease_id) in
            row.group_ids.iter().zip(row.target_device_ids.iter()).zip(row.lease_ids.iter())
        {
            let Some(lease_id) = lease_id.as_deref() else { continue };
            if let Err(error) = self
                .tickets
                .release_ticket(group_id, &row.removed_device_id, target_device_id, lease_id)
                .await
            {
                tracing::warn!(
                    error,
                    operation_id = %row.operation_id,
                    group_id,
                    lease_id,
                    "failed to release a rejected membership operation's provisional ticket; \
                     coordination TTL remains the backstop"
                );
            }
        }
    }

    /// Scans every NOT-terminal-or-blocked `membership_operations` row,
    /// marking every row that failed to decode `RecoveryBlocked` (excluded
    /// from all further automatic recovery) instead of letting one
    /// malformed row abort reconciliation for every other, valid row in the
    /// same sweep. Returns only the successfully decoded rows, filtered to
    /// `states`/`durability_scope`.
    fn scan_recoverable_membership_operations(
        &self,
        states: &[MembershipOperationState],
        durability_scope: MembershipDurabilityScope,
    ) -> Vec<MembershipOperation> {
        let scan = match self.repository.scan_open_operations() {
            Ok(scan) => scan,
            Err(error) => {
                tracing::warn!(%error, "failed to scan membership operations for reconciliation");
                return Vec::new();
            }
        };
        for invalid in &scan.invalid {
            tracing::error!(
                operation_id = %invalid.operation_id,
                detail = %invalid.detail,
                "membership recovery journal row is malformed; refusing automatic recovery"
            );
            self.repository.mark_recovery_blocked(&invalid.operation_id, &invalid.detail);
        }
        scan.valid
            .into_iter()
            .filter(|row| row.durability_scope == durability_scope && states.contains(&row.state))
            .collect()
    }

    /// Best-effort reconciliation for outstanding `Unknown`-durability-scope
    /// `membership_operations` rows (a `--force` removal that proceeded
    /// without a verified list of at-risk groups). Resolved the SAME way
    /// every other membership operation is (via `query_operation`/resend --
    /// see `reconcile_ambiguous`'s own doc comment), except a confirmed
    /// `Committed` outcome converts the result's own affected-groups list
    /// into real per-group `DurabilityUnknown` latches (which a later
    /// whole-group handoff re-check can clear individually) before the row
    /// is discarded -- the one thing an ordinary `Known`-scope row never
    /// needs, since ITS groups are already latched by
    /// `execute_membership_operation` itself. Runs at daemon startup and on
    /// the same periodic cadence `run_role_loss_reconciliation_sweep` uses.
    /// Not a continuous fast-follow sweep: a row that keeps failing to
    /// resolve just stays in place (still forcing `DurabilityUnknown`
    /// account-wide) until a later attempt succeeds.
    pub(crate) async fn reconcile_unknown_scope(&self) {
        if !self.coordination.is_configured() {
            return;
        }
        let now = now_unix();
        let markers = self.scan_recoverable_membership_operations(
            &[MembershipOperationState::Prepared, MembershipOperationState::Ambiguous],
            MembershipDurabilityScope::Unknown,
        );
        for marker in markers {
            if now - marker.created_at_unix < MEMBERSHIP_OPERATION_RECONCILE_MIN_AGE_SECS {
                continue;
            }
            match self.coordination.query_operation(&marker.operation_id).await {
                Ok(MembershipOperationLookup::Found(record)) => {
                    if !remote_record_matches_local(&marker, &record) {
                        let detail = "coordination operation request does not match local journal";
                        tracing::error!(
                            operation_id = %marker.operation_id,
                            local_request = ?super::membership_operation_identity::expected_membership_remote_request(&marker),
                            remote_request = ?record.request,
                            "membership operation identity mismatch; refusing automatic settlement"
                        );
                        self.repository.mark_recovery_blocked(&marker.operation_id, detail);
                        continue;
                    }
                    match record.status {
                        super::model::MembershipRemoteStatus::Committed => {
                            // Confirmed committed -- the result's own
                            // affected-groups list is the REAL scope this
                            // row never knew (that's the whole reason it's
                            // `Unknown`-scope). A missing `result` or a
                            // missing `affectedGroupIds` field is NOT the
                            // same as a confirmed-empty scope
                            // (`Some(vec![])`) -- treating it as such would
                            // silently clear the marker without ever
                            // latching the groups it was protecting, so
                            // both go to `RecoveryBlocked` instead of being
                            // read as "nothing was affected".
                            let Some(result) = record.result else {
                                let detail =
                                    "committed remove-device operation has no result payload";
                                tracing::error!(operation_id = %marker.operation_id, detail);
                                self.repository.mark_recovery_blocked(&marker.operation_id, detail);
                                continue;
                            };
                            let Some(affected_group_ids) = result.affected_group_ids else {
                                let detail =
                                    "committed remove-device result has no affectedGroupIds field";
                                tracing::error!(operation_id = %marker.operation_id, detail);
                                self.repository.mark_recovery_blocked(&marker.operation_id, detail);
                                continue;
                            };
                            let mut latch_failed = false;
                            for group_id in &affected_group_ids {
                                if let Err(error) =
                                    self.repository.latch_group_durability_unknown(group_id)
                                {
                                    tracing::warn!(
                                        %error,
                                        group_id,
                                        operation_id = %marker.operation_id,
                                        "failed to convert an unknown-scope row into a per-group latch"
                                    );
                                    latch_failed = true;
                                }
                            }
                            if !latch_failed {
                                self.repository.discard_operation(&marker.operation_id);
                            }
                        }
                        super::model::MembershipRemoteStatus::DefinitelyRejected => {
                            // Confirmed to have never committed -- nothing
                            // is at risk, so the row no longer protects
                            // anything real.
                            tracing::info!(
                                operation_id = %marker.operation_id,
                                removed_device_id = %marker.removed_device_id,
                                "unknown-scope removal is confirmed to have never committed; \
                                 discarding the row"
                            );
                            self.repository.discard_operation(&marker.operation_id);
                        }
                    }
                }
                Ok(MembershipOperationLookup::NotFound) => {
                    // The coordination plane has never heard of this
                    // operation_id -- unlike a `DefinitelyRejected` record,
                    // this does NOT confirm the removal never happened: the
                    // original request may simply never have reached the
                    // Worker. Resend it under the same id (idempotent
                    // either way) rather than assuming rejection.
                    let command = MembershipRemoteCommand::from_row(&marker);
                    match self.coordination.dispatch(&command, &marker.operation_id).await {
                        MembershipCommitOutcome::Committed(_) => {
                            // The Worker now has a journal record under
                            // this exact operation_id -- the NEXT sweep's
                            // lookup will hit the `Found`+`Committed` arm
                            // above and complete the real per-group latch +
                            // discard from its `result.affected_group_ids`
                            // (this plain HTTP response carries no body to
                            // latch from directly).
                            tracing::info!(
                                operation_id = %marker.operation_id,
                                removed_device_id = %marker.removed_device_id,
                                "resent unknown-scope removal committed; scope will resolve on the \
                                 next sweep"
                            );
                        }
                        MembershipCommitOutcome::DefinitelyRejected(detail) => {
                            tracing::info!(
                                operation_id = %marker.operation_id,
                                removed_device_id = %marker.removed_device_id,
                                detail,
                                "resent unknown-scope removal was definitely rejected; discarding \
                                 the row"
                            );
                            self.repository.discard_operation(&marker.operation_id);
                        }
                        MembershipCommitOutcome::Ambiguous(detail) => {
                            tracing::debug!(
                                operation_id = %marker.operation_id,
                                removed_device_id = %marker.removed_device_id,
                                detail,
                                "resent unknown-scope removal is still unresolved; will retry"
                            );
                        }
                        MembershipCommitOutcome::Conflict(detail) => {
                            tracing::error!(
                                operation_id = %marker.operation_id,
                                removed_device_id = %marker.removed_device_id,
                                detail,
                                "resending an unmodified unknown-scope removal conflicted with its \
                                 own operation_id -- operator attention required"
                            );
                            self.repository.mark_recovery_blocked(&marker.operation_id, &detail);
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        operation_id = %marker.operation_id,
                        removed_device_id = %marker.removed_device_id,
                        "unknown-scope membership operation still unresolved; will retry"
                    );
                }
            }
        }
    }

    /// Best-effort reconciliation for `Known`-durability-scope
    /// `membership_operations` rows still in `Prepared`, `Ambiguous`, or
    /// `LocalSettlementPending` (a ticket-bound revoke/remove commit whose
    /// outcome could not be confirmed, or a `--force` mutation whose remote
    /// commit landed but whose post-commit durability latch failed). A
    /// stuck `Prepared` row (the daemon crashed before ever observing the
    /// commit's HTTP response, or before observing it at all) is swept the
    /// same way as `Ambiguous`: it cannot be locally distinguished from
    /// "the request never reached the Worker" versus "it reached and
    /// committed but the reply was lost". Resolved via `query_operation`
    /// rather than re-deriving the answer from eager-group membership
    /// (which breaks for `remove-device`: the removed device's own row is
    /// gone, so `GET /devices/:id/eager-groups` 404s). A `Found` record
    /// whose `request` doesn't match this row's own
    /// (`remote_record_matches_local`) is never trusted -- the row moves to
    /// `RecoveryBlocked` instead. A `Found(DefinitelyRejected)` record is a
    /// CONFIRMED negative (safe to discard, after releasing any tickets it
    /// still holds); `NotFound` is resent instead; a lookup failure leaves
    /// the row for the next sweep to retry.
    pub(crate) async fn reconcile_ambiguous(&self) {
        if !self.coordination.is_configured() {
            return;
        }
        let now = now_unix();
        let rows = self.scan_recoverable_membership_operations(
            &[
                MembershipOperationState::Prepared,
                MembershipOperationState::Ambiguous,
                MembershipOperationState::LocalSettlementPending,
            ],
            MembershipDurabilityScope::Known,
        );
        for row in rows {
            if now - row.created_at_unix < MEMBERSHIP_OPERATION_RECONCILE_MIN_AGE_SECS {
                continue;
            }
            if row.state == MembershipOperationState::LocalSettlementPending {
                // The remote mutation is ALREADY confirmed committed --
                // only the local latch failed and needs retrying, no
                // Worker call at all.
                match self.latch_forced_groups(&row.latch_group_ids) {
                    Ok(()) => {
                        tracing::info!(
                            operation_id = %row.operation_id,
                            removed_device_id = %row.removed_device_id,
                            "retried post-commit durability latch succeeded"
                        );
                        self.repository.settle_operation(&row.operation_id);
                    }
                    Err(detail) => {
                        tracing::debug!(
                            operation_id = %row.operation_id,
                            removed_device_id = %row.removed_device_id,
                            detail,
                            "post-commit durability latch still failing; will retry"
                        );
                    }
                }
                continue;
            }
            match self.coordination.query_operation(&row.operation_id).await {
                Ok(MembershipOperationLookup::Found(record)) => {
                    if !remote_record_matches_local(&row, &record) {
                        let detail = "coordination operation request does not match local journal";
                        tracing::error!(
                            operation_id = %row.operation_id,
                            local_request = ?super::membership_operation_identity::expected_membership_remote_request(&row),
                            remote_request = ?record.request,
                            "membership operation identity mismatch; refusing automatic settlement"
                        );
                        self.repository.mark_recovery_blocked(&row.operation_id, detail);
                        continue;
                    }
                    match record.status {
                        super::model::MembershipRemoteStatus::Committed => {
                            tracing::info!(
                                operation_id = %row.operation_id,
                                removed_device_id = %row.removed_device_id,
                                "membership commit is confirmed to have landed"
                            );
                            self.settle_confirmed_commit(&row).await;
                        }
                        super::model::MembershipRemoteStatus::DefinitelyRejected => {
                            tracing::info!(
                                operation_id = %row.operation_id,
                                removed_device_id = %row.removed_device_id,
                                "membership commit is confirmed to have never landed; discarding the \
                                 journal row (the caller's own --force fallback, if any, already ran)"
                            );
                            self.release_journaled_tickets(&row).await;
                            self.repository.settle_operation(&row.operation_id);
                        }
                    }
                }
                Ok(MembershipOperationLookup::NotFound) => {
                    // Unlike a `DefinitelyRejected` record, `NotFound` does
                    // not confirm the commit never landed -- the original
                    // request may never have reached the Worker at all.
                    // Resend it under the same operation_id (idempotent
                    // either way) instead of assuming rejection.
                    let command = MembershipRemoteCommand::from_row(&row);
                    match self.coordination.dispatch(&command, &row.operation_id).await {
                        MembershipCommitOutcome::Committed(_) => {
                            tracing::info!(
                                operation_id = %row.operation_id,
                                removed_device_id = %row.removed_device_id,
                                "resent membership commit landed"
                            );
                            self.settle_confirmed_commit(&row).await;
                        }
                        MembershipCommitOutcome::DefinitelyRejected(detail) => {
                            tracing::info!(
                                operation_id = %row.operation_id,
                                removed_device_id = %row.removed_device_id,
                                detail,
                                "resent membership commit was definitely rejected; discarding the \
                                 journal row"
                            );
                            self.release_journaled_tickets(&row).await;
                            self.repository.settle_operation(&row.operation_id);
                        }
                        MembershipCommitOutcome::Ambiguous(detail) => {
                            tracing::debug!(
                                operation_id = %row.operation_id,
                                removed_device_id = %row.removed_device_id,
                                detail,
                                "resent membership operation is still unresolved; will retry"
                            );
                        }
                        MembershipCommitOutcome::Conflict(detail) => {
                            tracing::error!(
                                operation_id = %row.operation_id,
                                removed_device_id = %row.removed_device_id,
                                detail,
                                "resending an unmodified membership operation conflicted with its \
                                 own operation_id -- operator attention required"
                            );
                            self.repository.mark_recovery_blocked(&row.operation_id, &detail);
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        operation_id = %row.operation_id,
                        removed_device_id = %row.removed_device_id,
                        "ambiguous membership operation still unresolved; will retry"
                    );
                }
            }
        }
    }

    /// Shared by both `Found(Committed)` and post-resend-`Committed` arms
    /// in `reconcile_ambiguous`: latches `row.latch_group_ids` (a `--force`
    /// mutation's forced groups, empty for every ticket-bound mutation)
    /// before settling `Completed`, advancing to `LocalSettlementPending`
    /// instead if the latch write itself fails so the NEXT sweep retries it
    /// directly.
    async fn settle_confirmed_commit(&self, row: &MembershipOperation) {
        if row.latch_group_ids.is_empty() {
            self.repository.settle_operation(&row.operation_id);
            return;
        }
        match self.latch_forced_groups(&row.latch_group_ids) {
            Ok(()) => self.repository.settle_operation(&row.operation_id),
            Err(detail) => {
                tracing::warn!(
                    operation_id = %row.operation_id,
                    detail,
                    "confirmed membership commit's post-commit durability latch failed; will retry"
                );
                self.repository.mark_local_settlement_pending(&row.operation_id, &detail);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use crate::sync_error::SyncError;
    use yadorilink_peer_session::peer_session::PeerHandoffTicketGrant;
    use yadorilink_replica_domain::session_state::MaterializationPolicy;
    use yadorilink_replica_domain::session_state::{
        FolderLink, InvalidMembershipOperation, MembershipOperationScan,
    };

    use super::*;
    use crate::application::model::{
        HandoffCommitResult, MembershipCommitResult, MembershipOperationRecord,
        MembershipRemoteRequest, MembershipRemoteResult, MembershipRemoteStatus,
    };
    use crate::application::ports::BoxFuture;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RepoCall {
        Settle(String),
        MarkAmbiguous(String),
        MarkRecoveryBlocked(String),
        MarkLocalSettlementPending(String),
        Discard(String),
        Latch(String),
    }

    #[derive(Default)]
    struct FakeRepository {
        calls: Mutex<Vec<RepoCall>>,
        operations: Mutex<std::collections::HashMap<String, MembershipOperation>>,
        links: Mutex<Vec<FolderLink>>,
        invalid: Mutex<Vec<InvalidMembershipOperation>>,
        insert_result: Mutex<VecDeque<Result<bool, String>>>,
        fail_latch: AtomicBool,
    }

    impl FakeRepository {
        fn with_operation(self, op: MembershipOperation) -> Self {
            self.operations.lock().unwrap().insert(op.operation_id.clone(), op);
            self
        }

        fn with_link(self, link: FolderLink) -> Self {
            self.links.lock().unwrap().push(link);
            self
        }
    }

    impl MembershipRepository for FakeRepository {
        fn try_insert_operation(
            &self,
            operation_id: &str,
            action: MembershipOperationAction,
            commit_mode: MembershipCommitMode,
            removed_device_id: &str,
            group_ids: &[String],
            target_device_ids: &[String],
            lease_ids: &[Option<String>],
            durability_scope: MembershipDurabilityScope,
            latch_group_ids: &[String],
        ) -> Result<bool, String> {
            if let Some(result) = self.insert_result.lock().unwrap().pop_front() {
                if matches!(result, Ok(true)) {
                    self.operations.lock().unwrap().insert(
                        operation_id.to_string(),
                        MembershipOperation {
                            operation_id: operation_id.to_string(),
                            action,
                            commit_mode,
                            removed_device_id: removed_device_id.to_string(),
                            group_ids: group_ids.to_vec(),
                            target_device_ids: target_device_ids.to_vec(),
                            lease_ids: lease_ids.to_vec(),
                            state: MembershipOperationState::Prepared,
                            durability_scope,
                            latch_group_ids: latch_group_ids.to_vec(),
                            last_error: None,
                            created_at_unix: now_unix(),
                            updated_at_unix: now_unix(),
                        },
                    );
                }
                return result;
            }
            self.operations.lock().unwrap().insert(
                operation_id.to_string(),
                MembershipOperation {
                    operation_id: operation_id.to_string(),
                    action,
                    commit_mode,
                    removed_device_id: removed_device_id.to_string(),
                    group_ids: group_ids.to_vec(),
                    target_device_ids: target_device_ids.to_vec(),
                    lease_ids: lease_ids.to_vec(),
                    state: MembershipOperationState::Prepared,
                    durability_scope,
                    latch_group_ids: latch_group_ids.to_vec(),
                    last_error: None,
                    created_at_unix: now_unix(),
                    updated_at_unix: now_unix(),
                },
            );
            Ok(true)
        }

        fn settle_operation(&self, operation_id: &str) {
            self.calls.lock().unwrap().push(RepoCall::Settle(operation_id.to_string()));
            self.operations.lock().unwrap().remove(operation_id);
        }

        fn mark_ambiguous(&self, operation_id: &str, _detail: &str) {
            self.calls.lock().unwrap().push(RepoCall::MarkAmbiguous(operation_id.to_string()));
            if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
                op.state = MembershipOperationState::Ambiguous;
            }
        }

        fn mark_recovery_blocked(&self, operation_id: &str, _detail: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(RepoCall::MarkRecoveryBlocked(operation_id.to_string()));
            if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
                op.state = MembershipOperationState::RecoveryBlocked;
            }
        }

        fn mark_local_settlement_pending(&self, operation_id: &str, _detail: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(RepoCall::MarkLocalSettlementPending(operation_id.to_string()));
            if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
                op.state = MembershipOperationState::LocalSettlementPending;
            }
        }

        fn discard_operation(&self, operation_id: &str) {
            self.calls.lock().unwrap().push(RepoCall::Discard(operation_id.to_string()));
            self.operations.lock().unwrap().remove(operation_id);
        }

        fn scan_open_operations(&self) -> Result<MembershipOperationScan, SyncError> {
            Ok(MembershipOperationScan {
                valid: self
                    .operations
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|op| op.state != MembershipOperationState::RecoveryBlocked)
                    .cloned()
                    .collect(),
                invalid: self.invalid.lock().unwrap().clone(),
            })
        }

        fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
            Ok(self.links.lock().unwrap().clone())
        }

        fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
            self.calls.lock().unwrap().push(RepoCall::Latch(group_id.to_string()));
            if self.fail_latch.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fake latch failure").into());
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeCoordination {
        configured: AtomicBool,
        eager_groups: Mutex<VecDeque<Result<Vec<String>, String>>>,
        dispatch: Mutex<VecDeque<MembershipCommitOutcome>>,
        dispatch_calls: Mutex<u32>,
        query: Mutex<VecDeque<Result<MembershipOperationLookup, String>>>,
        resolve_edge_result: Mutex<VecDeque<Result<Option<(String, String)>, String>>>,
        audit_calls: Mutex<u32>,
    }

    impl FakeCoordination {
        fn configured() -> Self {
            let this = Self::default();
            this.configured.store(true, Ordering::SeqCst);
            this
        }
    }

    impl MembershipCoordination for FakeCoordination {
        fn is_configured(&self) -> bool {
            self.configured.load(Ordering::SeqCst)
        }

        fn fetch_eager_groups<'a>(
            &'a self,
            _device_id: &'a str,
        ) -> BoxFuture<'a, Result<Vec<String>, String>> {
            Box::pin(async move {
                self.eager_groups.lock().unwrap().pop_front().expect("missing fake eager groups")
            })
        }

        fn dispatch<'a>(
            &'a self,
            _command: &'a MembershipRemoteCommand,
            _operation_id: &'a str,
        ) -> BoxFuture<'a, MembershipCommitOutcome> {
            Box::pin(async move {
                *self.dispatch_calls.lock().unwrap() += 1;
                self.dispatch.lock().unwrap().pop_front().expect("missing fake dispatch outcome")
            })
        }

        fn query_operation<'a>(
            &'a self,
            _operation_id: &'a str,
        ) -> BoxFuture<'a, Result<MembershipOperationLookup, String>> {
            Box::pin(async move {
                self.query.lock().unwrap().pop_front().expect("missing fake query result")
            })
        }

        fn resolve_edge<'a>(
            &'a self,
            _edge_id: &'a str,
        ) -> BoxFuture<'a, Result<Option<(String, String)>, String>> {
            Box::pin(async move {
                self.resolve_edge_result
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("missing fake resolve result")
            })
        }

        fn record_force_override_audit<'a>(
            &'a self,
            _local_device_id: &'a str,
            _target_device_id: &'a str,
            _group_ids: &'a [String],
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                *self.audit_calls.lock().unwrap() += 1;
            })
        }
    }

    #[derive(Default)]
    struct FakeTickets {
        grants: Mutex<VecDeque<Option<PeerHandoffTicketGrant>>>,
        released: Mutex<Vec<String>>,
        release_result: Mutex<VecDeque<Result<(), String>>>,
    }

    impl HandoffTicketPort for FakeTickets {
        fn obtain_ticket<'a>(
            &'a self,
            _group_id: &'a str,
            _device_id: &'a str,
        ) -> BoxFuture<'a, Option<PeerHandoffTicketGrant>> {
            Box::pin(async move { self.grants.lock().unwrap().pop_front().flatten() })
        }

        fn release_ticket<'a>(
            &'a self,
            group_id: &'a str,
            _device_id: &'a str,
            _target_device_id: &'a str,
            _lease_id: &'a str,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.released.lock().unwrap().push(group_id.to_string());
                self.release_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
            })
        }
    }

    #[derive(Default)]
    struct FakeReadiness {
        ready: Mutex<VecDeque<bool>>,
    }

    impl ReplicaReadinessPort for FakeReadiness {
        fn another_full_replica_is_ready_excluding<'a>(
            &'a self,
            _group_id: &'a str,
            _excluded_device_id: &'a str,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async move { self.ready.lock().unwrap().pop_front().unwrap_or(false) })
        }
    }

    fn service(
        repository: Arc<FakeRepository>,
        coordination: Arc<FakeCoordination>,
        tickets: Arc<FakeTickets>,
        readiness: Arc<FakeReadiness>,
    ) -> ReplicaMembershipService {
        ReplicaMembershipService::new(
            "device-a".to_string(),
            repository,
            coordination,
            tickets,
            readiness,
        )
    }

    fn grant(target: &str, lease: &str) -> Option<PeerHandoffTicketGrant> {
        Some(PeerHandoffTicketGrant {
            lease_id: Some(lease.to_string()),
            target_device_id: Some(target.to_string()),
            expires_at_unix: now_unix() + 60,
        })
    }

    fn link(group_id: &str) -> FolderLink {
        FolderLink {
            local_path: "/home/alice/Photos".to_string(),
            group_id: group_id.to_string(),
            paused: false,
            materialization_policy: MaterializationPolicy::Eager,
            max_local_size_bytes: None,
            orphaned: false,
        }
    }

    fn old_operation(
        operation_id: &str,
        state: MembershipOperationState,
        durability_scope: MembershipDurabilityScope,
    ) -> MembershipOperation {
        MembershipOperation {
            operation_id: operation_id.to_string(),
            action: MembershipOperationAction::RemoveDevice,
            commit_mode: MembershipCommitMode::PlainRemoveDevice,
            removed_device_id: "device-b".to_string(),
            group_ids: Vec::new(),
            target_device_ids: Vec::new(),
            lease_ids: Vec::new(),
            state,
            durability_scope,
            latch_group_ids: Vec::new(),
            last_error: None,
            created_at_unix: now_unix() - 1000,
            updated_at_unix: now_unix() - 1000,
        }
    }

    // ===== change_membership =====

    #[tokio::test]
    async fn unconfigured_coordination_refuses_before_touching_the_journal() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::default());
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination, tickets, readiness)
            .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::LocalIdentityUnavailable)));
    }

    #[tokio::test]
    async fn revoke_with_no_groups_at_risk_takes_the_plain_fast_path() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(Vec::new()));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        let outcome = service(repository, coordination.clone(), tickets.clone(), readiness)
            .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
            .await
            .unwrap();

        assert!(outcome.handoffs.is_empty());
        assert!(outcome.forced_group_ids.is_empty());
        assert!(tickets.grants.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ticket_bound_guarded_revoke_reports_the_real_membership_generation() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        coordination.dispatch.lock().unwrap().push_back(MembershipCommitOutcome::Committed(
            MembershipCommitResult {
                handoff: Some(HandoffCommitResult {
                    target_device_id: "device-c".to_string(),
                    membership_generation: 7,
                    lease_id: Some("lease-1".to_string()),
                }),
            },
        ));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
        let readiness = Arc::new(FakeReadiness::default());

        let outcome = service(repository, coordination, tickets, readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: false,
            })
            .await
            .unwrap();

        assert_eq!(outcome.handoffs.len(), 1);
        assert_eq!(outcome.handoffs[0].membership_generation, 7);
        assert_eq!(outcome.handoffs[0].lease_id, "lease-1");
    }

    #[tokio::test]
    async fn unavailable_ticket_without_force_refuses_with_replica_not_ready() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(None);
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination, tickets, readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: false,
            })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
    }

    #[tokio::test]
    async fn unavailable_ticket_with_force_latches_and_commits_plain() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(None);
        let readiness = Arc::new(FakeReadiness::default());

        let outcome = service(repository.clone(), coordination.clone(), tickets, readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: true,
            })
            .await
            .unwrap();

        assert_eq!(outcome.forced_group_ids, vec!["group-1".to_string()]);
        assert_eq!(*coordination.audit_calls.lock().unwrap(), 1);
        assert!(repository.calls.lock().unwrap().contains(&RepoCall::Latch("group-1".to_string())));
    }

    #[tokio::test]
    async fn definitely_rejected_ticket_bound_commit_releases_tickets_and_falls_through() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::DefinitelyRejected("gone".to_string()));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
        let readiness = Arc::new(FakeReadiness::default());

        let outcome = service(repository, coordination, tickets.clone(), readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: true,
            })
            .await
            .unwrap();

        assert_eq!(tickets.released.lock().unwrap().len(), 1);
        assert_eq!(outcome.forced_group_ids, vec!["group-1".to_string()]);
    }

    #[tokio::test]
    async fn ambiguous_ticket_bound_commit_never_releases_tickets_or_falls_through() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Ambiguous("timeout".to_string()));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination, tickets.clone(), readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: true,
            })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::RecoveryPending { .. })));
        assert!(tickets.released.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn conflict_is_reported_and_never_falls_through() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Conflict("shape mismatch".to_string()));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination.clone(), tickets, readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: true,
            })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::OperationConflict { .. })));
        assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn journal_write_failure_never_falls_through_to_the_coordination_plane() {
        let repository = Arc::new(FakeRepository::default());
        repository.insert_result.lock().unwrap().push_back(Err("disk full".to_string()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination.clone(), tickets.clone(), readiness)
            .revoke_device(RevokeDeviceCommand {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                force: true,
            })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::RecoveryJournalUnavailable { .. })));
        assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
        assert_eq!(tickets.released.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unverified_scope_forced_removal_surfaces_the_unknown_scope_operation_id() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Err("enumerate failed".to_string()));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        let outcome = service(repository, coordination, tickets, readiness)
            .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: true })
            .await
            .unwrap();

        assert!(outcome.unknown_scope_operation_id.is_some());
    }

    #[tokio::test]
    async fn unverified_scope_without_force_refuses() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Err("enumerate failed".to_string()));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination, tickets, readiness)
            .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
    }

    #[tokio::test]
    async fn self_removal_uses_the_readiness_port_not_tickets() {
        let repository = Arc::new(FakeRepository::default().with_link(link("group-1")));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());
        readiness.ready.lock().unwrap().push_back(false);

        let result = service(repository, coordination, tickets.clone(), readiness)
            .remove_device(RemoveDeviceCommand { device_id: "device-a".to_string(), force: false })
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
        assert!(tickets.grants.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn revoke_edge_resolves_then_runs_the_same_guarded_path() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .resolve_edge_result
            .lock()
            .unwrap()
            .push_back(Ok(Some(("group-1".to_string(), "device-b".to_string()))));
        coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
        let tickets = Arc::new(FakeTickets::default());
        tickets.grants.lock().unwrap().push_back(None);
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination, tickets, readiness)
            .revoke_edge("edge-1".to_string(), true)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn revoke_edge_already_gone_reports_target_not_found() {
        let repository = Arc::new(FakeRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.resolve_edge_result.lock().unwrap().push_back(Ok(None));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        let result = service(repository, coordination, tickets, readiness)
            .revoke_edge("edge-1".to_string(), true)
            .await;

        assert!(matches!(result, Err(ReplicaMembershipError::TargetNotFound)));
    }

    // ===== reconcile_unknown_scope =====

    #[tokio::test]
    async fn unknown_scope_found_committed_latches_real_groups_and_discards() {
        let repository = Arc::new(FakeRepository::default().with_operation(old_operation(
            "op-1",
            MembershipOperationState::Prepared,
            MembershipDurabilityScope::Unknown,
        )));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(
            Box::new(MembershipOperationRecord {
                status: MembershipRemoteStatus::Committed,
                action: "removeDevice".to_string(),
                removed_device_id: "device-b".to_string(),
                request_fingerprint: "fp".to_string(),
                request:
                    super::super::membership_operation_identity::expected_membership_remote_request(
                        &old_operation(
                            "op-1",
                            MembershipOperationState::Prepared,
                            MembershipDurabilityScope::Unknown,
                        ),
                    ),
                result: Some(MembershipRemoteResult {
                    affected_group_ids: Some(vec!["group-1".to_string(), "group-2".to_string()]),
                    target_device_id: None,
                    membership_generation: None,
                    lease_id: None,
                }),
                rejection_code: None,
                rejection_detail: None,
            }),
        )));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination, tickets, readiness)
            .reconcile_unknown_scope()
            .await;

        let calls = repository.calls.lock().unwrap();
        assert!(calls.contains(&RepoCall::Latch("group-1".to_string())));
        assert!(calls.contains(&RepoCall::Latch("group-2".to_string())));
        assert!(calls.contains(&RepoCall::Discard("op-1".to_string())));
    }

    #[tokio::test]
    async fn unknown_scope_not_found_resends_and_commits() {
        let repository = Arc::new(FakeRepository::default().with_operation(old_operation(
            "op-1",
            MembershipOperationState::Prepared,
            MembershipDurabilityScope::Unknown,
        )));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::NotFound));
        coordination
            .dispatch
            .lock()
            .unwrap()
            .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination.clone(), tickets, readiness)
            .reconcile_unknown_scope()
            .await;

        assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 1);
        // Committed-via-resend leaves the row for the NEXT sweep's
        // Found+Committed arm to resolve the real scope from -- never
        // settled/discarded here directly.
        assert!(!repository.calls.lock().unwrap().contains(&RepoCall::Discard("op-1".to_string())));
    }

    #[tokio::test]
    async fn unknown_scope_row_too_young_is_left_for_the_next_sweep() {
        let mut op = old_operation(
            "op-1",
            MembershipOperationState::Prepared,
            MembershipDurabilityScope::Unknown,
        );
        op.created_at_unix = now_unix();
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::configured());
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination.clone(), tickets, readiness)
            .reconcile_unknown_scope()
            .await;

        assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
        assert!(repository.calls.lock().unwrap().is_empty());
    }

    // ===== reconcile_ambiguous =====

    #[tokio::test]
    async fn ambiguous_found_committed_settles() {
        let op = old_operation(
            "op-1",
            MembershipOperationState::Ambiguous,
            MembershipDurabilityScope::Known,
        );
        let repository = Arc::new(FakeRepository::default().with_operation(op.clone()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(
            Box::new(MembershipOperationRecord {
                status: MembershipRemoteStatus::Committed,
                action: "removeDevice".to_string(),
                removed_device_id: "device-b".to_string(),
                request_fingerprint: "fp".to_string(),
                request:
                    super::super::membership_operation_identity::expected_membership_remote_request(
                        &op,
                    ),
                result: None,
                rejection_code: None,
                rejection_detail: None,
            }),
        )));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination, tickets, readiness).reconcile_ambiguous().await;

        assert!(repository.calls.lock().unwrap().contains(&RepoCall::Settle("op-1".to_string())));
    }

    #[tokio::test]
    async fn ambiguous_found_definitely_rejected_releases_tickets_and_settles() {
        let mut op = old_operation(
            "op-1",
            MembershipOperationState::Ambiguous,
            MembershipDurabilityScope::Known,
        );
        op.commit_mode = MembershipCommitMode::GuardedRevoke;
        op.group_ids = vec!["group-1".to_string()];
        op.target_device_ids = vec!["device-c".to_string()];
        op.lease_ids = vec![Some("lease-1".to_string())];
        let repository = Arc::new(FakeRepository::default().with_operation(op.clone()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(
            Box::new(MembershipOperationRecord {
                status: MembershipRemoteStatus::DefinitelyRejected,
                action: "revoke".to_string(),
                removed_device_id: "device-b".to_string(),
                request_fingerprint: "fp".to_string(),
                request:
                    super::super::membership_operation_identity::expected_membership_remote_request(
                        &op,
                    ),
                result: None,
                rejection_code: None,
                rejection_detail: None,
            }),
        )));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination, tickets.clone(), readiness)
            .reconcile_ambiguous()
            .await;

        assert_eq!(*tickets.released.lock().unwrap(), vec!["group-1".to_string()]);
        assert!(repository.calls.lock().unwrap().contains(&RepoCall::Settle("op-1".to_string())));
    }

    #[tokio::test]
    async fn identity_mismatch_blocks_recovery_instead_of_settling() {
        let op = old_operation(
            "op-1",
            MembershipOperationState::Ambiguous,
            MembershipDurabilityScope::Known,
        );
        let repository = Arc::new(FakeRepository::default().with_operation(op.clone()));
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(
            Box::new(MembershipOperationRecord {
                status: MembershipRemoteStatus::Committed,
                action: "removeDevice".to_string(),
                removed_device_id: "device-b".to_string(),
                request_fingerprint: "fp".to_string(),
                request: MembershipRemoteRequest {
                    action: "revoke".to_string(),
                    removed_device_id: "device-other".to_string(),
                    mode: "guarded".to_string(),
                    groups: Vec::new(),
                },
                result: None,
                rejection_code: None,
                rejection_detail: None,
            }),
        )));
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination, tickets, readiness).reconcile_ambiguous().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkRecoveryBlocked("op-1".to_string())));
        assert!(!repository.calls.lock().unwrap().contains(&RepoCall::Settle("op-1".to_string())));
    }

    #[tokio::test]
    async fn local_settlement_pending_retries_the_latch_without_a_remote_call() {
        let op = old_operation(
            "op-1",
            MembershipOperationState::LocalSettlementPending,
            MembershipDurabilityScope::Known,
        );
        let mut op = op;
        op.latch_group_ids = vec!["group-1".to_string()];
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::configured());
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination.clone(), tickets, readiness)
            .reconcile_ambiguous()
            .await;

        assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
        let calls = repository.calls.lock().unwrap();
        assert!(calls.contains(&RepoCall::Latch("group-1".to_string())));
        assert!(calls.contains(&RepoCall::Settle("op-1".to_string())));
    }

    #[tokio::test]
    async fn a_malformed_row_is_recovery_blocked_and_never_resent() {
        let repository = Arc::new(FakeRepository::default());
        repository.invalid.lock().unwrap().push(InvalidMembershipOperation {
            operation_id: "op-bad".to_string(),
            raw_state: Some("unknown".to_string()),
            detail: "unrecognized state".to_string(),
        });
        let coordination = Arc::new(FakeCoordination::configured());
        let tickets = Arc::new(FakeTickets::default());
        let readiness = Arc::new(FakeReadiness::default());

        service(repository.clone(), coordination.clone(), tickets, readiness)
            .reconcile_ambiguous()
            .await;

        assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkRecoveryBlocked("op-bad".to_string())));
    }
}
