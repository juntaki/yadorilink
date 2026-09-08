use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;
use yadorilink_replica_domain::session_state::{EnrollmentOperation, EnrollmentOperationState};

use super::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult, MintedInvite,
};
use super::ports::{
    EnrollmentCoordination, EnrollmentLinkPort, EnrollmentLinkRequest, EnrollmentRepository,
};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Owns the create/join pending-enrollment sagas, cross-account invite
/// acceptance (a related but deliberately simpler saga -- see
/// `accept_invite_and_link`'s own doc comment for how and why it differs),
/// and invite minting (no saga at all -- see `mint_invite`'s own doc
/// comment). Every dependency is a port -- no `DaemonState`, no `reqwest`,
/// no IPC proto -- see the composition root for what backs each one in
/// production.
pub(crate) struct EnrollmentService {
    device_id: String,
    repository: Arc<dyn EnrollmentRepository>,
    coordination: Arc<dyn EnrollmentCoordination>,
    links: Arc<dyn EnrollmentLinkPort>,
}

/// High-level create-and-link command.
///
/// Coordination credentials come from the daemon's configured identity and
/// are intentionally absent from this command.
pub(crate) struct CreateAndLinkCommand {
    pub(crate) group_name: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
}

/// High-level join-and-link command.
pub(crate) struct JoinAndLinkCommand {
    pub(crate) group_id: String,
    pub(crate) group_name: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
}

/// High-level cross-account invite-accept command. `code` is the plaintext
/// invite credential; the group it names is learned from the coordination
/// plane's accept/prepare response, not supplied here.
pub(crate) struct AcceptInviteCommand {
    pub(crate) code: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
}

/// A stable operation id derived from `(code, device_id)` rather than a
/// fresh random UUID -- see `EnrollmentService::accept_invite_and_link`'s
/// own doc comment for why: without a durable cross-restart journal for
/// this saga, retry-safety depends on a repeated command (same code, same
/// device) presenting the SAME operation_id, so the coordination plane's
/// own idempotent-redemption check recognizes it. Not a secret and not
/// sent anywhere the code itself isn't already going, so a plain SHA-256
/// hex digest (not a MAC) is enough -- collision resistance is the only
/// property this needs.
fn invite_accept_operation_id(code: &str, device_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_id.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnrollmentOutcome {
    pub(crate) operation_id: String,
    pub(crate) group_id: String,
    pub(crate) local_path: PathBuf,
    /// Set only by `accept_invite_and_link`, and only when the redeemed
    /// invite required the group owner's approval: this device finished its
    /// own half, but the membership is parked awaiting that decision and
    /// grants nothing until it is made. Always false for create/join,
    /// neither of which has an approval step.
    ///
    /// Carried on the outcome rather than being flattened into "success"
    /// because the two are materially different for the person who ran the
    /// command: one means the folder is syncing, the other means it will
    /// not sync until someone else acts.
    pub(crate) awaiting_approval: bool,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollmentError {
    #[error("local device identity is unavailable")]
    LocalIdentityUnavailable,
    #[error(
        "could not persist enrollment recovery journal for operation {operation_id}: {detail}"
    )]
    RecoveryJournalUnavailable { operation_id: String, detail: String },
    #[error("enrollment preparation was rejected: {detail}")]
    PreparationRejected { detail: String },
    #[error("enrollment preparation result is ambiguous for operation {operation_id}: {detail}")]
    PreparationAmbiguous { operation_id: String, detail: String },
    #[error("local link commit failed: {detail}")]
    LocalLinkFailed { detail: String },
    #[error("local link outcome is ambiguous for operation {operation_id}: {detail}")]
    LocalLinkAmbiguous { operation_id: String, detail: String },
    #[error("enrollment activation was rejected: {detail}")]
    ActivationRejected { detail: String },
    #[error("enrollment activation result is ambiguous for operation {operation_id}: {detail}")]
    ActivationAmbiguous { operation_id: String, detail: String },
    #[error("enrollment compensation is pending for operation {operation_id}: {detail}")]
    CompensationPending { operation_id: String, detail: String },
    #[error("enrollment operation {operation_id} conflicts with another request: {detail}")]
    OperationConflict { operation_id: String, detail: String },
    #[error("coordination transport failed: {detail}")]
    CoordinationTransport { detail: String },
    #[error("local persistence failed: {0}")]
    Persistence(#[from] crate::sync_error::SyncError),
}

/// The classified result of a `link()` failure -- distinct from a plain
/// `Result<(), String>` so a caller can tell "definitely never committed"
/// (safe to compensate: mark CancelPending, retry remote cancel) apart from
/// "may still be committed" (the link/marker/Transferred row might be fully
/// live locally; remote cancellation must never be attempted, since that
/// would delete the authorization for a link that still exists).
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollmentLinkError {
    #[error("{detail}")]
    NotCommitted { detail: String },
    #[error("{detail}")]
    CommitUncertain { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrollmentKind {
    Create,
    Join,
}

impl From<EnrollmentKind> for yadorilink_replica_domain::session_state::EnrollmentKind {
    fn from(kind: EnrollmentKind) -> Self {
        match kind {
            EnrollmentKind::Create => {
                yadorilink_replica_domain::session_state::EnrollmentKind::Create
            }
            EnrollmentKind::Join => yadorilink_replica_domain::session_state::EnrollmentKind::Join,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationDisposition {
    Finalize,
    RollBack,
    LeaveForReconciliation,
}

fn activation_disposition(outcome: &EnrollmentActivationResult) -> ActivationDisposition {
    match outcome {
        EnrollmentActivationResult::Activated
        | EnrollmentActivationResult::AlreadyActive
        // Only the CROSS-ACCOUNT invite path can produce this, and that
        // path does not go through `finish_activation` at all -- neither
        // create nor join has an approval step, so this arm is
        // unreachable from the two callers of this function. Finalize
        // anyway rather than roll back: the remote side did commit a
        // state transition, and treating a committed transition as
        // "never happened" is the one answer that could destroy local
        // state. Never `RollBack`, never left dangling.
        | EnrollmentActivationResult::AwaitingApproval => ActivationDisposition::Finalize,
        EnrollmentActivationResult::Deleted => ActivationDisposition::RollBack,
        EnrollmentActivationResult::TransientFailure { .. } => {
            ActivationDisposition::LeaveForReconciliation
        }
    }
}

impl EnrollmentService {
    pub(crate) fn new(
        device_id: String,
        repository: Arc<dyn EnrollmentRepository>,
        coordination: Arc<dyn EnrollmentCoordination>,
        links: Arc<dyn EnrollmentLinkPort>,
    ) -> Self {
        Self { device_id, repository, coordination, links }
    }

    pub(crate) async fn create_and_link(
        &self,
        command: CreateAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };

        // 1. Journal ALWAYS opens before the first remote prepare call --
        // if this write itself fails, nothing is ever sent to the
        // coordination plane (fail closed).
        let operation_id = self.open_enrollment_operation(
            yadorilink_replica_domain::session_state::EnrollmentKind::Create,
            None,
            Some(command.group_name.clone()),
            &command.absolute_path,
            storage_mode,
        )?;

        // 2. Prepare, under the SAME operation_id.
        let group_id = match self
            .coordination
            .prepare_create(&operation_id, &command.group_name, &self.device_id)
            .await
        {
            EnrollmentPrepareResult::Prepared { group_id } => group_id,
            EnrollmentPrepareResult::DefinitelyRejected { detail } => {
                self.repository.delete_operation(&operation_id)?;
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                self.mark_recovery_blocked(&operation_id, &detail);
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                // The row stays `PreparePending`; the next reconciliation
                // sweep resends the exact same prepare request under this
                // same operation_id.
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        // 3. Prepare confirmed remotely -- record it locally. A failure
        // here leaves the row `PreparePending`; the next sweep resends the
        // same prepare (idempotent by operation_id) and recovers the same
        // group_id.
        if !self.repository.mark_prepared(&operation_id, &group_id, now_unix())? {
            return Err(EnrollmentError::PreparationAmbiguous {
                operation_id,
                detail: "remote prepare succeeded but local Prepared transition could not be \
                         confirmed"
                    .to_string(),
            });
        }

        let local_path = command.absolute_path.clone();
        let link_request = EnrollmentLinkRequest {
            operation_id: operation_id.clone(),
            kind: EnrollmentKind::Create,
            device_id: self.device_id.clone(),
            group_id: group_id.clone(),
            absolute_path: command.absolute_path,
            on_demand: command.on_demand,
            acknowledge_risks: command.acknowledge_risks,
        };

        // 4. `link()` commits the local link + pending_enrollments marker +
        // this journal row's Transferred transition atomically. Its own
        // best-effort rollback on a post-commit setup failure is itself
        // fallible, so a plain `Err` here does not by itself mean nothing
        // was committed -- the port classifies the failure by reading back
        // the journal row's actual state.
        match self.links.commit(link_request).await {
            Ok(()) => {}
            Err(EnrollmentLinkError::NotCommitted { detail }) => {
                return self.compensate_failed_create_link(&operation_id, &group_id, detail).await;
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link or its activation marker may still be \
                         committed, so remote cancellation was not attempted"
                    ),
                });
            }
        }

        self.finish_activation(
            EnrollmentKind::Create,
            &group_id,
            &operation_id,
            &self.device_id.clone(),
            local_path,
        )
        .await
    }

    pub(crate) async fn join_and_link(
        &self,
        command: JoinAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        tracing::debug!(group_name = %command.group_name, group_id = %command.group_id, "starting join-and-link enrollment");
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };

        let operation_id = self.open_enrollment_operation(
            yadorilink_replica_domain::session_state::EnrollmentKind::Join,
            Some(command.group_id.clone()),
            None,
            &command.absolute_path,
            storage_mode,
        )?;

        match self
            .coordination
            .prepare_join(&operation_id, &command.group_id, &self.device_id, storage_mode)
            .await
        {
            EnrollmentPrepareResult::Prepared { .. } => {}
            EnrollmentPrepareResult::DefinitelyRejected { detail } => {
                self.repository.delete_operation(&operation_id)?;
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                self.mark_recovery_blocked(&operation_id, &detail);
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        if !self.repository.mark_prepared(&operation_id, &command.group_id, now_unix())? {
            return Err(EnrollmentError::PreparationAmbiguous {
                operation_id,
                detail: "remote prepare succeeded but local Prepared transition could not be \
                         confirmed"
                    .to_string(),
            });
        }

        let local_path = command.absolute_path.clone();
        let link_request = EnrollmentLinkRequest {
            operation_id: operation_id.clone(),
            kind: EnrollmentKind::Join,
            device_id: self.device_id.clone(),
            group_id: command.group_id.clone(),
            absolute_path: command.absolute_path,
            on_demand: command.on_demand,
            acknowledge_risks: command.acknowledge_risks,
        };
        match self.links.commit(link_request).await {
            Ok(()) => {}
            Err(EnrollmentLinkError::NotCommitted { detail }) => {
                return self
                    .compensate_failed_join_link(&operation_id, &command.group_id, detail)
                    .await;
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link or its activation marker may still be \
                         committed, so remote cancellation was not attempted"
                    ),
                });
            }
        }

        self.finish_activation(
            EnrollmentKind::Join,
            &command.group_id,
            &operation_id,
            &self.device_id.clone(),
            local_path,
        )
        .await
    }

    /// Cross-account invite acceptance: redeems an invite credential and
    /// links it locally in one crash-safe enrollment, mirroring
    /// `join_and_link`'s Pending -> Active shape at the coordination-plane
    /// level.
    ///
    /// Deliberately does NOT use `open_enrollment_operation`/the durable
    /// `enrollment_operations` journal `create_and_link`/`join_and_link`
    /// use for cross-*daemon-restart* crash recovery -- doing so would mean
    /// giving `EnrollmentKind` (and every exhaustive match over it in the
    /// recovery/diagnosis subsystem) a third variant, a change with a much
    /// larger blast radius than this feature needs yet. Instead:
    ///
    /// - `operation_id` is DERIVED deterministically from `(code,
    ///   device_id)` (a SHA-256 hex digest), not a random UUID. Re-running
    ///   this exact command (same invite code, same device) after a crash
    ///   or a transient/ambiguous error therefore always presents the SAME
    ///   operation_id, which is what makes it a safe retry rather than a
    ///   rejected "invite already used": the coordination plane's own
    ///   accept/prepare recognizes a repeated (device, operation_id) pair
    ///   as this device's own earlier redemption (see that route's own
    ///   doc comment), and `commit_plain`'s underlying `LinkLifecycleService`
    ///   allows re-linking the identical (group_id, path) pair as an
    ///   idempotent no-op.
    /// - The local link commits via `commit_plain` (the plain `yadorilink
    ///   link` shape, no `pending_enrollment` marker) rather than `commit`.
    ///   There is therefore no local crash-recovery marker for a daemon
    ///   restart to reconcile: if this process dies between a successful
    ///   local link and the matching activate call, the coordination-plane
    ///   edge is left Pending, and this device's own next restart does
    ///   NOT automatically retry it -- either the user re-runs `share
    ///   accept <code>` (safe, per the retry story above), or the
    ///   coordination plane's own pending-enrollment TTL sweep eventually
    ///   deletes the abandoned Pending row, leaving a local link that no
    ///   longer syncs rather than a silently-orphaned coordination-plane
    ///   authorization. This is a real, bounded gap relative to
    ///   create/join's full cross-restart recovery, accepted for now
    ///   rather than silently pretended away.
    /// - `commit_plain`'s failure still gets classified (`NotCommitted` vs
    ///   `CommitUncertain`), same two-variant shape `commit` uses for
    ///   create/join -- a local link that may still be live must never be
    ///   silently cancelled on the coordination plane just because this
    ///   call is reporting failure. There is no `enrollment_operations`
    ///   journal row to classify against here, so the classification reads
    ///   current local link state back directly instead (see
    ///   `commit_plain`'s own doc comment).
    pub(crate) async fn accept_invite_and_link(
        &self,
        command: AcceptInviteCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };
        let operation_id = invite_accept_operation_id(&command.code, &self.device_id);

        let group_id = match self
            .coordination
            .prepare_invite_accept(&operation_id, &command.code, &self.device_id, storage_mode)
            .await
        {
            EnrollmentPrepareResult::Prepared { group_id } => group_id,
            EnrollmentPrepareResult::DefinitelyRejected { detail } => {
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        let local_path = command.absolute_path.clone();
        match self
            .links
            .commit_plain(
                &group_id,
                &command.absolute_path,
                command.on_demand,
                command.acknowledge_risks,
            )
            .await
        {
            Ok(()) => {}
            Err(EnrollmentLinkError::NotCommitted { detail }) => {
                // Confirmed nothing was committed locally -- safe to
                // compensate. Best-effort: if the cancel call also fails,
                // the coordination plane's own pending-enrollment TTL sweep
                // is the eventual backstop, same as every other best-effort
                // cancel call in this file.
                let _ = self
                    .coordination
                    .cancel_invite_accept(&group_id, &operation_id, &self.device_id)
                    .await;
                return Err(EnrollmentError::LocalLinkFailed { detail });
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                // The local link may still be live even though this call
                // is reporting failure -- cancelling here would delete the
                // coordination-plane authorization for a group this device
                // may actually be actively linked to (see `commit_plain`'s
                // own doc comment, and `classify_link_failure`'s identical
                // reasoning for the same-account `commit` path this
                // mirrors). Leave the Pending edge in place instead: a
                // retry of this exact command is always safe (same
                // deterministic operation id), and re-commits idempotently
                // once local state is confirmed one way or the other.
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link may still be committed, so remote \
                         cancellation was not attempted"
                    ),
                });
            }
        }

        match self
            .coordination
            .activate_invite_accept(&group_id, &operation_id, &self.device_id)
            .await
        {
            EnrollmentActivationResult::Activated | EnrollmentActivationResult::AlreadyActive => {
                Ok(EnrollmentOutcome {
                    operation_id,
                    group_id,
                    local_path,
                    awaiting_approval: false,
                })
            }
            // The invite required the group owner's approval, so this
            // device's own half is complete and correct but the membership
            // is not live yet. Reported as a success, not an error: nothing
            // failed and there is nothing here to retry -- the local link
            // committed above stays, and the coordination plane's edge
            // stays, both waiting on a human. The local runtime this
            // enrollment started is running but idle; with no policy-log
            // grant it withholds every local change rather than syncing or
            // losing one, and it starts working the moment the owner
            // approves, with no further action here. The FLAG is what
            // keeps this from being reported as a completed join.
            EnrollmentActivationResult::AwaitingApproval => Ok(EnrollmentOutcome {
                operation_id,
                group_id,
                local_path,
                awaiting_approval: true,
            }),
            EnrollmentActivationResult::Deleted => {
                // Confirmed terminal: the Pending row this operation_id
                // named is permanently gone (most likely the TTL sweep won
                // a race against a very slow local link commit). Unlike
                // `finish_activation`'s marker-based rollback, the local
                // link just committed above has no marker to remove -- it
                // is left in place, orphaned from this now-gone
                // authorization, for the user to `yadorilink unlink` if
                // they don't retry with a fresh invite.
                Err(EnrollmentError::ActivationRejected {
                    detail: format!(
                        "invite-accept authorization for operation {operation_id} is gone \
                         (expired or already superseded); the local folder was linked but is \
                         not authorized -- unlink it, or request a new invite and retry"
                    ),
                })
            }
            EnrollmentActivationResult::TransientFailure { detail } => {
                Err(EnrollmentError::ActivationAmbiguous { operation_id, detail })
            }
        }
    }

    /// Mints a one-use, expiring cross-account invite for `group_id`,
    /// naming this device as the minting device -- the CLI never needs to
    /// know or supply its own device id (unlike `grant`, which names some
    /// OTHER device explicitly). No local state, no journal row: a single
    /// stateless coordination-plane call.
    pub(crate) async fn mint_invite(
        &self,
        group_id: &str,
        role: Option<&str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> Result<MintedInvite, String> {
        if !self.coordination.is_configured() {
            return Err(
                "coordination-plane address/access token not configured on this device".to_string()
            );
        }
        self.coordination.mint_invite(group_id, role, ttl_secs, requires_approval).await
    }

    /// Opens a fresh `enrollment_operations` journal row, retrying under a
    /// NEW `operation_id` on a (should be astronomically rare) UUID
    /// collision -- mirrors `replica_membership_service.rs`'s
    /// `open_membership_operation`. Fails closed (no coordination call
    /// ever attempted) if the durable write itself keeps failing.
    fn open_enrollment_operation(
        &self,
        kind: yadorilink_replica_domain::session_state::EnrollmentKind,
        group_id: Option<String>,
        group_name: Option<String>,
        local_path: &std::path::Path,
        storage_mode: &str,
    ) -> Result<String, EnrollmentError> {
        const MAX_ID_ATTEMPTS: usize = 4;
        let mut last_operation_id = String::new();
        for _ in 0..MAX_ID_ATTEMPTS {
            let operation_id = Uuid::new_v4().to_string();
            last_operation_id.clone_from(&operation_id);
            let now = now_unix();
            let operation = EnrollmentOperation {
                operation_id: operation_id.clone(),
                kind,
                group_id: group_id.clone(),
                group_name: group_name.clone(),
                device_id: self.device_id.clone(),
                local_path: local_path.to_string_lossy().to_string(),
                storage_mode: storage_mode.to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: now,
                updated_at_unix: now,
            };
            match self.repository.try_insert_operation(&operation) {
                Ok(true) => return Ok(operation_id),
                // A fresh UUID already names a row -- retry under another
                // one; the existing row is untouched.
                Ok(false) => continue,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        operation_id,
                        "refusing the enrollment: could not persist the durable recovery journal, so \
                         coordination prepare must not be attempted"
                    );
                    return Err(EnrollmentError::RecoveryJournalUnavailable {
                        operation_id,
                        detail: error.to_string(),
                    });
                }
            }
        }
        Err(EnrollmentError::RecoveryJournalUnavailable {
            operation_id: last_operation_id,
            detail: "could not allocate a unique enrollment operation id after repeated \
                      collisions"
                .to_string(),
        })
    }

    fn mark_recovery_blocked(&self, operation_id: &str, detail: &str) {
        if let Err(error) = self.repository.mark_state(
            operation_id,
            EnrollmentOperationState::RecoveryBlocked,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(
                %error,
                operation_id,
                "failed to advance an enrollment operation journal row to RecoveryBlocked"
            );
        }
    }

    fn mark_cancel_pending(&self, operation_id: &str, detail: &str) {
        if let Err(error) = self.repository.mark_state(
            operation_id,
            EnrollmentOperationState::CancelPending,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(
                %error,
                operation_id,
                "failed to advance an enrollment operation journal row to CancelPending"
            );
        }
    }

    async fn compensate_failed_create_link(
        &self,
        operation_id: &str,
        group_id: &str,
        link_error: String,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        self.mark_cancel_pending(operation_id, &link_error);
        for _ in 0..3 {
            match self.coordination.cancel_create(group_id, operation_id).await {
                EnrollmentCancellationResult::Confirmed => {
                    self.repository.delete_operation(operation_id)?;
                    return Err(EnrollmentError::LocalLinkFailed { detail: link_error });
                }
                EnrollmentCancellationResult::Conflict { detail } => {
                    self.mark_recovery_blocked(operation_id, &detail);
                    return Err(EnrollmentError::OperationConflict {
                        operation_id: operation_id.to_string(),
                        detail,
                    });
                }
                EnrollmentCancellationResult::Ambiguous { detail } => {
                    self.mark_cancel_pending(operation_id, &detail);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(EnrollmentError::CompensationPending {
            operation_id: operation_id.to_string(),
            detail: format!(
                "local link failed ({link_error}); cancellation remains durably journaled"
            ),
        })
    }

    async fn compensate_failed_join_link(
        &self,
        operation_id: &str,
        group_id: &str,
        link_error: String,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        self.mark_cancel_pending(operation_id, &link_error);
        for _ in 0..3 {
            match self.coordination.cancel_join(group_id, operation_id, &self.device_id).await {
                EnrollmentCancellationResult::Confirmed => {
                    self.repository.delete_operation(operation_id)?;
                    return Err(EnrollmentError::LocalLinkFailed { detail: link_error });
                }
                EnrollmentCancellationResult::Conflict { detail } => {
                    self.mark_recovery_blocked(operation_id, &detail);
                    return Err(EnrollmentError::OperationConflict {
                        operation_id: operation_id.to_string(),
                        detail,
                    });
                }
                EnrollmentCancellationResult::Ambiguous { detail } => {
                    self.mark_cancel_pending(operation_id, &detail);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(EnrollmentError::CompensationPending {
            operation_id: operation_id.to_string(),
            detail: format!(
                "local link failed ({link_error}); cancellation remains durably journaled"
            ),
        })
    }

    async fn finish_activation(
        &self,
        kind: EnrollmentKind,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
        local_path: PathBuf,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        let activation = match kind {
            EnrollmentKind::Create => {
                self.coordination.activate_create(group_id, operation_id).await
            }
            EnrollmentKind::Join => {
                self.coordination.activate_join(group_id, operation_id, device_id).await
            }
        };
        match activation_disposition(&activation) {
            ActivationDisposition::Finalize => {
                self.repository.settle_activated(operation_id)?;
                Ok(EnrollmentOutcome {
                    operation_id: operation_id.to_string(),
                    group_id: group_id.to_string(),
                    local_path,
                    // Create and join have no approval step at all.
                    awaiting_approval: false,
                })
            }
            ActivationDisposition::RollBack => {
                // `Deleted` is a CONFIRMED terminal answer -- see
                // `EnrollmentLinkPort::rollback`'s own doc comment for the
                // full rollback sequence and why it must not go through
                // `ReplicaRoleService::unlink`'s full-replica-handoff gate.
                let local_path_str = local_path.to_string_lossy().to_string();
                if let Err(e) = self.links.rollback(&local_path_str, operation_id).await {
                    // Leave the link and marker in place; the next
                    // reconciliation sweep retries the same orphan-and-
                    // remove compensation (it will see `Deleted` again and
                    // take this same path).
                    return Err(EnrollmentError::CompensationPending {
                        operation_id: operation_id.to_string(),
                        detail: format!(
                            "activation was rejected but the local rollback failed: {e}"
                        ),
                    });
                }
                Err(EnrollmentError::ActivationRejected {
                    detail: format!("operation {operation_id} no longer exists"),
                })
            }
            ActivationDisposition::LeaveForReconciliation => {
                Err(EnrollmentError::ActivationAmbiguous {
                    operation_id: operation_id.to_string(),
                    detail: "the local link and pending marker were kept for daemon \
                             reconciliation"
                        .to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn enrollment_outcome_keeps_operation_identity_for_recovery() {
        let outcome = EnrollmentOutcome {
            operation_id: "operation-1".to_string(),
            group_id: "group-1".to_string(),
            local_path: PathBuf::from("/tmp/group-1"),
            awaiting_approval: false,
        };

        assert_eq!(outcome.operation_id, "operation-1");
        assert_eq!(outcome.group_id, "group-1");
    }

    #[test]
    fn enrollment_errors_keep_compensation_context_structured() {
        let error = EnrollmentError::CompensationPending {
            operation_id: "operation-1".to_string(),
            detail: "cancel will be retried".to_string(),
        };

        assert!(error.to_string().contains("operation-1"));
    }

    #[test]
    fn activation_success_and_idempotent_retry_finalize() {
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::Activated),
            ActivationDisposition::Finalize
        );
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::AlreadyActive),
            ActivationDisposition::Finalize
        );
    }

    #[test]
    fn confirmed_activation_rejection_rolls_back() {
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::Deleted),
            ActivationDisposition::RollBack
        );
    }

    #[test]
    fn ambiguous_activation_never_rolls_back() {
        assert_eq!(
            activation_disposition(&EnrollmentActivationResult::TransientFailure {
                detail: "timeout".to_string()
            }),
            ActivationDisposition::LeaveForReconciliation
        );
    }

    // ===== Fakes =====

    #[derive(Default)]
    struct FakeEnrollmentRepository {
        operations: Mutex<HashMap<String, EnrollmentOperation>>,
    }

    impl EnrollmentRepository for FakeEnrollmentRepository {
        fn try_insert_operation(
            &self,
            operation: &EnrollmentOperation,
        ) -> Result<bool, crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            if operations.contains_key(&operation.operation_id) {
                return Ok(false);
            }
            operations.insert(operation.operation_id.clone(), operation.clone());
            Ok(true)
        }

        fn delete_operation(&self, operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
            self.operations.lock().unwrap().remove(operation_id);
            Ok(())
        }

        fn mark_prepared(
            &self,
            operation_id: &str,
            group_id: &str,
            now_unix: i64,
        ) -> Result<bool, crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
            op.group_id = Some(group_id.to_string());
            op.state = EnrollmentOperationState::Prepared;
            op.updated_at_unix = now_unix;
            Ok(true)
        }

        fn mark_state(
            &self,
            operation_id: &str,
            state: EnrollmentOperationState,
            error: Option<&str>,
            now_unix: i64,
        ) -> Result<bool, crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
            op.state = state;
            op.last_error = error.map(str::to_string);
            op.updated_at_unix = now_unix;
            Ok(true)
        }

        fn list_links(
            &self,
        ) -> Result<
            Vec<yadorilink_replica_domain::session_state::FolderLink>,
            crate::sync_error::SyncError,
        > {
            Ok(Vec::new())
        }

        fn scan_pending(
            &self,
        ) -> Result<
            yadorilink_replica_domain::session_state::PendingEnrollmentScan,
            crate::sync_error::SyncError,
        > {
            Ok(yadorilink_replica_domain::session_state::PendingEnrollmentScan::default())
        }

        fn settle_activated(
            &self,
            _operation_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            Ok(())
        }

        fn operation(
            &self,
            operation_id: &str,
        ) -> Result<Option<EnrollmentOperation>, crate::sync_error::SyncError> {
            Ok(self.operations.lock().unwrap().get(operation_id).cloned())
        }

        fn scan_open_operations(
            &self,
        ) -> Result<
            yadorilink_replica_domain::session_state::EnrollmentOperationScan,
            crate::sync_error::SyncError,
        > {
            Ok(yadorilink_replica_domain::session_state::EnrollmentOperationScan::default())
        }

        fn settle_activated_and_close(
            &self,
            operation_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.operations.lock().unwrap().remove(operation_id);
            Ok(())
        }

        fn move_marker_to_cancel_operation(
            &self,
            _marker: &yadorilink_replica_domain::session_state::PendingEnrollment,
            _now_unix: i64,
        ) -> Result<(), crate::sync_error::SyncError> {
            Ok(())
        }

        fn increment_attempts(
            &self,
            _operation_id: &str,
            _now_unix: i64,
        ) -> Result<i64, crate::sync_error::SyncError> {
            Ok(1)
        }

        fn rollback_local_setup_to_cancel_pending(
            &self,
            _local_path: &str,
            operation_id: &str,
            detail: &str,
            now_unix: i64,
        ) -> Result<(), crate::sync_error::SyncError> {
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(()) };
            op.state = EnrollmentOperationState::CancelPending;
            op.last_error = Some(detail.to_string());
            op.updated_at_unix = now_unix;
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum EnrollmentCall {
        PrepareCreate,
        PrepareJoin,
        PrepareInviteAccept,
        ActivateCreate,
        ActivateJoin,
        ActivateInviteAccept,
        CancelCreate,
        CancelJoin,
        CancelInviteAccept,
        MintInvite,
        LinkCommit,
        LinkRollback,
        LinkCommitPlain,
    }

    /// The arguments one `mint_invite` port call carried.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MintInviteArgs {
        group_id: String,
        role: Option<String>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    }

    #[derive(Default)]
    struct FakeCoordination {
        calls: Mutex<Vec<EnrollmentCall>>,
        prepare: Mutex<std::collections::VecDeque<EnrollmentPrepareResult>>,
        activate: Mutex<std::collections::VecDeque<EnrollmentActivationResult>>,
        cancel: Mutex<std::collections::VecDeque<EnrollmentCancellationResult>>,
        mint: Mutex<std::collections::VecDeque<Result<MintedInvite, String>>>,
        /// One entry per mint call -- the approval flag is the whole point of
        /// the option, so a test must be able to prove it survived the trip
        /// through this port rather than merely that a mint happened.
        mint_args: Mutex<Vec<MintInviteArgs>>,
        configured: std::sync::atomic::AtomicBool,
    }

    impl FakeCoordination {
        fn configured() -> Self {
            let this = Self::default();
            this.configured.store(true, std::sync::atomic::Ordering::SeqCst);
            this
        }
    }

    impl EnrollmentCoordination for FakeCoordination {
        fn is_configured(&self) -> bool {
            self.configured.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn prepare_create<'a>(
            &'a self,
            _operation_id: &'a str,
            _group_name: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::PrepareCreate);
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
            })
        }

        fn prepare_join<'a>(
            &'a self,
            _operation_id: &'a str,
            _group_id: &'a str,
            _device_id: &'a str,
            _storage_mode: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::PrepareJoin);
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
            })
        }

        fn activate_create<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::ActivateCreate);
                self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
            })
        }

        fn activate_join<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::ActivateJoin);
                self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
            })
        }

        fn cancel_create<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::CancelCreate);
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
            })
        }

        fn cancel_join<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::CancelJoin);
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
            })
        }

        fn prepare_invite_accept<'a>(
            &'a self,
            _operation_id: &'a str,
            _code: &'a str,
            _device_id: &'a str,
            _storage_mode: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::PrepareInviteAccept);
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
            })
        }

        fn activate_invite_accept<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::ActivateInviteAccept);
                self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
            })
        }

        fn cancel_invite_accept<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::CancelInviteAccept);
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
            })
        }

        fn mint_invite<'a>(
            &'a self,
            group_id: &'a str,
            role: Option<&'a str>,
            ttl_secs: Option<u64>,
            requires_approval: bool,
        ) -> super::super::ports::BoxFuture<'a, Result<MintedInvite, String>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::MintInvite);
                self.mint_args.lock().unwrap().push(MintInviteArgs {
                    group_id: group_id.to_string(),
                    role: role.map(str::to_string),
                    ttl_secs,
                    requires_approval,
                });
                self.mint.lock().unwrap().pop_front().expect("missing fake mint result")
            })
        }
    }

    #[derive(Default)]
    struct FakeLinkPort {
        calls: Mutex<Vec<EnrollmentCall>>,
        commit: Mutex<std::collections::VecDeque<Result<(), EnrollmentLinkError>>>,
        rollback: Mutex<std::collections::VecDeque<Result<(), String>>>,
        commit_plain: Mutex<std::collections::VecDeque<Result<(), EnrollmentLinkError>>>,
    }

    impl EnrollmentLinkPort for FakeLinkPort {
        fn commit<'a>(
            &'a self,
            _request: EnrollmentLinkRequest,
        ) -> super::super::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::LinkCommit);
                self.commit.lock().unwrap().pop_front().expect("missing fake commit result")
            })
        }

        fn rollback<'a>(
            &'a self,
            _local_path: &'a str,
            _operation_id: &'a str,
        ) -> super::super::ports::BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::LinkRollback);
                self.rollback.lock().unwrap().pop_front().expect("missing fake rollback result")
            })
        }

        fn commit_plain<'a>(
            &'a self,
            _group_id: &'a str,
            _absolute_path: &'a std::path::Path,
            _on_demand: bool,
            _acknowledge_risks: bool,
        ) -> super::super::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(EnrollmentCall::LinkCommitPlain);
                self.commit_plain
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("missing fake commit_plain result")
            })
        }
    }

    fn service(
        repository: Arc<FakeEnrollmentRepository>,
        coordination: Arc<FakeCoordination>,
        links: Arc<FakeLinkPort>,
    ) -> EnrollmentService {
        EnrollmentService::new("device-a".to_string(), repository, coordination, links)
    }

    fn create_command() -> CreateAndLinkCommand {
        CreateAndLinkCommand {
            group_name: "photos".to_string(),
            absolute_path: PathBuf::from("/home/alice/Photos"),
            on_demand: false,
            acknowledge_risks: false,
        }
    }

    /// A `Deleted` activation rolls back via the link port's own rollback
    /// method, never `ReplicaRoleService::unlink`'s full-replica-handoff
    /// gate -- proven here by the sequence: link commit, then activate,
    /// then rollback, nothing else.
    #[tokio::test]
    async fn deleted_activation_rolls_back_via_the_link_port() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(()));
        links.rollback.lock().unwrap().push_back(Ok(()));

        let result = service(repository, coordination.clone(), links.clone())
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })));
        assert_eq!(
            *links.calls.lock().unwrap(),
            vec![EnrollmentCall::LinkCommit, EnrollmentCall::LinkRollback]
        );
    }

    /// If the rollback itself fails, `CompensationPending` is returned so
    /// the next reconciliation sweep retries -- never treated as done.
    #[tokio::test]
    async fn rollback_failure_reports_compensation_pending() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(()));
        links.rollback.lock().unwrap().push_back(Err("disk full".to_string()));

        let result =
            service(repository, coordination, links).create_and_link(create_command()).await;

        assert!(matches!(result, Err(EnrollmentError::CompensationPending { .. })));
    }

    /// `TransientFailure` never rolls back -- the link/marker/rollback port
    /// is never called a second time.
    #[tokio::test]
    async fn transient_activation_failure_never_rolls_back() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination
            .activate
            .lock()
            .unwrap()
            .push_back(EnrollmentActivationResult::TransientFailure { detail: "503".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(()));

        let result = service(repository, coordination, links.clone())
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::ActivationAmbiguous { .. })));
        assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
    }

    /// Config missing is checked BEFORE the journal is even opened -- no
    /// journal row exists afterward, and no coordination call is ever made.
    #[tokio::test]
    async fn missing_coordination_config_never_opens_a_journal_row() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::default()); // not configured
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository.clone(), coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::LocalIdentityUnavailable)));
        assert!(repository.operations.lock().unwrap().is_empty());
        assert!(coordination.calls.lock().unwrap().is_empty());
    }

    /// A local `link()` failure that reaches a durable `CancelPending`
    /// state (the immediate cancel-with-retries also fails) leaves exactly
    /// one journal row behind, in `CancelPending`.
    #[tokio::test]
    async fn link_failure_and_cancel_failure_leaves_a_cancel_pending_row() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        for _ in 0..3 {
            coordination
                .cancel
                .lock()
                .unwrap()
                .push_back(EnrollmentCancellationResult::Ambiguous { detail: "5xx".to_string() });
        }
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
            detail: "simulated local link failure".to_string(),
        }));

        let result = service(repository.clone(), coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::CompensationPending { .. })));
        let operations = repository.operations.lock().unwrap();
        assert_eq!(operations.len(), 1, "expected one cancel-pending journal row");
        let (_, op) = operations.iter().next().unwrap();
        assert_eq!(op.group_id.as_deref(), Some("group-1"));
        assert_eq!(op.state, EnrollmentOperationState::CancelPending);
        assert_eq!(
            coordination
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| **c == EnrollmentCall::CancelCreate)
                .count(),
            3,
            "expected 3 cancel retries"
        );
    }

    /// `NotCommitted` goes through the existing compensation path and the
    /// remote cancel DOES get called -- the counterpart to the
    /// `CommitUncertain` test below, proving the two classifications route
    /// to genuinely different behavior.
    #[tokio::test]
    async fn not_committed_link_failure_calls_remote_cancel_and_reaches_cancel_pending() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
            detail: "preflight rejected, nothing committed".to_string(),
        }));

        let result = service(repository, coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        assert!(
            !matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })),
            "NotCommitted must never surface as LocalLinkAmbiguous: {result:?}"
        );
        assert_eq!(
            coordination
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| **c == EnrollmentCall::CancelCreate)
                .count(),
            1,
            "a NotCommitted failure must attempt remote cancellation"
        );
    }

    /// `CommitUncertain` must NEVER be treated as "definitely not
    /// committed": it must not mark CancelPending, must not call remote
    /// cancel, and must not delete the journal row.
    #[tokio::test]
    async fn commit_uncertain_link_failure_never_calls_remote_cancel() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::CommitUncertain {
            detail: "post-commit setup failed, and rolling back also failed".to_string(),
        }));

        let result = service(repository.clone(), coordination.clone(), links)
            .create_and_link(create_command())
            .await;

        let Err(EnrollmentError::LocalLinkAmbiguous { operation_id, .. }) = result else {
            panic!("expected LocalLinkAmbiguous, got {result:?}");
        };
        let operations = repository.operations.lock().unwrap();
        let row = operations.get(&operation_id).unwrap();
        assert_ne!(
            row.state,
            EnrollmentOperationState::CancelPending,
            "CommitUncertain must never mark CancelPending"
        );
        assert_ne!(
            row.state,
            EnrollmentOperationState::RecoveryBlocked,
            "CommitUncertain must never block/discard the journal row"
        );
        assert!(
            coordination.calls.lock().unwrap().iter().all(|c| *c != EnrollmentCall::CancelCreate),
            "CommitUncertain must never call remote cancel"
        );
    }

    /// A 409 on create prepare means this operation_id already names a
    /// differently-shaped request -- the row must move to
    /// `RecoveryBlocked`, never be treated as an ordinary rejection or
    /// silently retried.
    #[tokio::test]
    async fn create_prepare_conflict_blocks_recovery() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Conflict { detail: "409".to_string() });
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository.clone(), coordination, links)
            .create_and_link(create_command())
            .await;

        let Err(EnrollmentError::OperationConflict { operation_id, .. }) = result else {
            panic!("expected OperationConflict, got {result:?}");
        };
        let operations = repository.operations.lock().unwrap();
        assert_eq!(
            operations.get(&operation_id).unwrap().state,
            EnrollmentOperationState::RecoveryBlocked
        );
    }

    fn accept_invite_command() -> AcceptInviteCommand {
        AcceptInviteCommand {
            code: "invite-code-abc".to_string(),
            absolute_path: PathBuf::from("/home/bob/Shared"),
            on_demand: false,
            acknowledge_risks: false,
        }
    }

    #[test]
    fn invite_accept_operation_id_is_deterministic_and_scoped_to_both_inputs() {
        let a = invite_accept_operation_id("code-1", "device-a");
        let b = invite_accept_operation_id("code-1", "device-a");
        assert_eq!(a, b, "same (code, device) must always produce the same operation id");

        let different_device = invite_accept_operation_id("code-1", "device-b");
        assert_ne!(a, different_device, "a different device must produce a different id");

        let different_code = invite_accept_operation_id("code-2", "device-a");
        assert_ne!(a, different_code, "a different code must produce a different id");
    }

    #[tokio::test]
    async fn accept_invite_happy_path_activates_and_returns_outcome() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
        let links = Arc::new(FakeLinkPort::default());
        links.commit_plain.lock().unwrap().push_back(Ok(()));

        let result = service(repository, coordination.clone(), links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        let outcome = result.expect("expected a successful enrollment outcome");
        assert_eq!(outcome.group_id, "group-9");
        assert_eq!(outcome.local_path, PathBuf::from("/home/bob/Shared"));
        assert_eq!(
            *coordination.calls.lock().unwrap(),
            vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::ActivateInviteAccept]
        );
        assert!(
            !outcome.awaiting_approval,
            "an ordinary invite acceptance is a completed membership, not a request"
        );
        assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
    }

    /// An invite minted requiring the owner's approval parks the membership
    /// instead of granting it. That is a success for this device -- nothing
    /// failed, nothing is left to retry, and the local link stays -- but it
    /// is NOT a membership, and the outcome has to say so or the command
    /// that ran it reports a folder as joined when it will not sync until
    /// someone else acts.
    #[tokio::test]
    async fn accept_invite_awaiting_approval_succeeds_but_is_not_reported_as_a_membership() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
        coordination
            .activate
            .lock()
            .unwrap()
            .push_back(EnrollmentActivationResult::AwaitingApproval);
        let links = Arc::new(FakeLinkPort::default());
        links.commit_plain.lock().unwrap().push_back(Ok(()));

        let outcome = service(repository, coordination.clone(), links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await
            .expect("awaiting approval is a success, not an error: nothing failed here");

        assert!(outcome.awaiting_approval);
        assert_eq!(outcome.group_id, "group-9");
        assert_eq!(outcome.local_path, PathBuf::from("/home/bob/Shared"));
        // The local link is NOT rolled back and no cancel is sent: the
        // coordination-plane edge is legitimately parked, waiting on a
        // human, and both sides must survive until they decide.
        assert_eq!(
            *coordination.calls.lock().unwrap(),
            vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::ActivateInviteAccept]
        );
        assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
    }

    /// A definitely-rejected prepare (e.g. the invite is invalid/expired/
    /// already used) must never attempt a local link commit at all --
    /// unlike the same-account create/join paths, there is no durable
    /// journal row to open or clean up here either.
    #[tokio::test]
    async fn accept_invite_rejected_prepare_never_touches_the_link_port() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.prepare.lock().unwrap().push_back(
            EnrollmentPrepareResult::DefinitelyRejected {
                detail: "invite is invalid or already used".to_string(),
            },
        );
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository, coordination, links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })));
        assert!(links.calls.lock().unwrap().is_empty());
    }

    /// A local link failure compensates by cancelling the invite-accept
    /// Pending edge -- best-effort, but always attempted (mirrors
    /// `compensate_failed_join_link`'s reasoning, simplified since there is
    /// no local partial-state classification to make: see
    /// `accept_invite_and_link`'s own doc comment).
    #[tokio::test]
    async fn accept_invite_not_committed_link_failure_triggers_a_cancel() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        links
            .commit_plain
            .lock()
            .unwrap()
            .push_back(Err(EnrollmentLinkError::NotCommitted { detail: "disk full".to_string() }));

        let result = service(repository, coordination.clone(), links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::LocalLinkFailed { .. })));
        assert_eq!(
            *coordination.calls.lock().unwrap(),
            vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::CancelInviteAccept]
        );
    }

    /// A `CommitUncertain` classification (the local link may still be
    /// live even though `commit_plain` is reporting failure) must NEVER
    /// trigger the compensating cancel -- doing so would delete the
    /// coordination-plane authorization for a group this device may
    /// actually be actively linked to. Mirrors `commit`'s identical
    /// same-account guarantee (see `classify_link_failure`'s own doc
    /// comment and its 3 dedicated tests in enrollment_link.rs).
    #[tokio::test]
    async fn accept_invite_commit_uncertain_never_triggers_a_cancel() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        links.commit_plain.lock().unwrap().push_back(Err(EnrollmentLinkError::CommitUncertain {
            detail: "watcher start failed and the rollback itself also failed".to_string(),
        }));

        let result = service(repository, coordination.clone(), links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })));
        // Only PrepareInviteAccept ran -- no CancelInviteAccept, and no
        // ActivateInviteAccept either (this call returns before reaching
        // activate).
        assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::PrepareInviteAccept]);
    }

    /// A confirmed-gone activation (the Pending row's TTL swept it before
    /// activate ran) reports an error but does NOT roll back the local
    /// link -- there is no marker for `commit_plain` to have written, so
    /// there is nothing for a rollback to remove; the link is left in
    /// place for the user to `unlink` or retry with a fresh invite (see
    /// `accept_invite_and_link`'s own doc comment).
    #[tokio::test]
    async fn accept_invite_deleted_activation_leaves_the_link_in_place() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
        let links = Arc::new(FakeLinkPort::default());
        links.commit_plain.lock().unwrap().push_back(Ok(()));

        let result = service(repository, coordination, links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })));
        // Only the plain commit ran -- no rollback call exists on this path
        // at all (unlike `commit`'s `EnrollmentLinkPort::rollback`).
        assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
    }

    #[tokio::test]
    async fn accept_invite_missing_coordination_config_never_attempts_a_link() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::default()); // not configured
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository, coordination, links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        assert!(matches!(result, Err(EnrollmentError::LocalIdentityUnavailable)));
        assert!(links.calls.lock().unwrap().is_empty());
    }

    fn minted(role: &str, requires_approval: bool) -> MintedInvite {
        MintedInvite {
            code: "abc123".to_string(),
            invite_id: "invite-1".to_string(),
            group_id: "group-9".to_string(),
            role: role.to_string(),
            expires_at_unix: 1_800_000_000,
            requires_approval,
        }
    }

    #[tokio::test]
    async fn mint_invite_happy_path_returns_the_coordination_plane_result() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.mint.lock().unwrap().push_back(Ok(minted("viewer", false)));
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository, coordination.clone(), links)
            .mint_invite("group-9", Some("viewer"), None, false)
            .await;

        let invite = result.expect("expected a minted invite");
        assert_eq!(invite.code, "abc123");
        assert_eq!(invite.group_id, "group-9");
        assert!(!invite.requires_approval);
        assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::MintInvite]);
        assert_eq!(
            *coordination.mint_args.lock().unwrap(),
            vec![MintInviteArgs {
                group_id: "group-9".to_string(),
                role: Some("viewer".to_string()),
                ttl_secs: None,
                requires_approval: false,
            }],
        );
    }

    /// The approval flag must reach the coordination plane unchanged and
    /// independently of the role -- an owner asking for an approval-gated
    /// Editor invite must not silently get an ungated one.
    #[tokio::test]
    async fn mint_invite_forwards_the_approval_requirement_independently_of_the_role() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.mint.lock().unwrap().push_back(Ok(minted("editor", true)));
        let links = Arc::new(FakeLinkPort::default());

        let invite = service(repository, coordination.clone(), links)
            .mint_invite("group-9", Some("editor"), None, true)
            .await
            .expect("expected a minted invite");

        assert!(invite.requires_approval);
        assert_eq!(
            *coordination.mint_args.lock().unwrap(),
            vec![MintInviteArgs {
                group_id: "group-9".to_string(),
                role: Some("editor".to_string()),
                ttl_secs: None,
                requires_approval: true,
            }],
        );
    }

    /// What the caller reports is what the coordination plane recorded, not
    /// what was requested: a plane that ignored the flag must not be
    /// described as having honored it.
    #[tokio::test]
    async fn mint_invite_reports_the_coordination_planes_own_approval_answer() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.mint.lock().unwrap().push_back(Ok(minted("editor", false)));
        let links = Arc::new(FakeLinkPort::default());

        let invite = service(repository, coordination.clone(), links)
            .mint_invite("group-9", Some("editor"), None, true)
            .await
            .expect("expected a minted invite");

        assert!(!invite.requires_approval);
    }

    #[tokio::test]
    async fn mint_invite_missing_coordination_config_fails_closed() {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::default()); // not configured
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository, coordination.clone(), links)
            .mint_invite("group-9", None, None, true)
            .await;

        assert!(result.is_err());
        assert!(coordination.calls.lock().unwrap().is_empty());
    }
}
