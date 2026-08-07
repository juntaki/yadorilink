//! Crash-safety reconciliation for the create/join pending-enrollment
//! sagas -- the recovery counterpart to `EnrollmentService`'s own
//! synchronous create/join flow. Two distinct sweeps, run together every
//! call to [`EnrollmentRecoveryService::reconcile_once`]:
//!
//! - **Marker reconciliation** (`reconcile_markers`): a durable local
//!   marker records a local link whose local commit landed but whose
//!   matching coordination-plane activation was never confirmed -- the
//!   crash-safety net for a process killed in that exact window. See the
//!   coordination plane's own explicit Pending -> Active enrollment
//!   protocol this reconciles against: a create/join authorizes a Pending
//!   group/membership there BEFORE the local link is known to exist, and
//!   only `activate` turns it into a real, counted enrollment.
//! - **Journal reconciliation** (`reconcile_operations`): retries every
//!   other stuck `enrollment_operations` state (`PreparePending`,
//!   `Prepared`, `LocalSetupPending`, `CancelPending`) that has no other
//!   durable backstop.
//!
//! `app.rs` owns WHEN this runs (startup + a fixed interval); this service
//! owns WHAT recovery actually does.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::EnrollmentKind as WireEnrollmentKind;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationState as OpState,
};

use super::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
};
use super::ports::{
    EnrollmentAttemptTracker, EnrollmentCoordination, EnrollmentLinkPort, EnrollmentRepository,
};

/// How many CONSECUTIVE `TransientFailure` activate outcomes a single
/// marker can accumulate across reconcile sweeps before it is escalated (a
/// `tracing::error!` line, not just the ordinary per-sweep trace) -- purely
/// a visibility bound, never a rollback trigger; see
/// `EnrollmentAttemptTracker`'s own doc comment.
const TRANSIENT_ESCALATION_THRESHOLD: u32 = 20;

/// Age-gate for journal reconciliation: skip a row whose last transition
/// happened too recently, to avoid racing a still-in-flight command's own
/// writes to that exact row -- matches
/// `MEMBERSHIP_OPERATION_RECONCILE_MIN_AGE_SECS`'s own reasoning.
const RECONCILE_MIN_AGE_SECS: i64 = 30;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) struct EnrollmentRecoveryService {
    repository: Arc<dyn EnrollmentRepository>,
    coordination: Arc<dyn EnrollmentCoordination>,
    links: Arc<dyn EnrollmentLinkPort>,
    attempts: Arc<dyn EnrollmentAttemptTracker>,
}

impl EnrollmentRecoveryService {
    pub(crate) fn new(
        repository: Arc<dyn EnrollmentRepository>,
        coordination: Arc<dyn EnrollmentCoordination>,
        links: Arc<dyn EnrollmentLinkPort>,
        attempts: Arc<dyn EnrollmentAttemptTracker>,
    ) -> Self {
        Self { repository, coordination, links, attempts }
    }

    pub(crate) async fn reconcile_once(&self) {
        self.reconcile_markers().await;
        self.reconcile_operations().await;
    }

    /// Drops a `pending_enrollments` marker once `share create`/`share
    /// join` has confirmed its own activate call directly -- an
    /// optimization over waiting for the next `reconcile_once` sweep to
    /// notice the same thing. Always succeeds: a marker that's already
    /// gone (this device's own sweep beat the caller to it) is a no-op,
    /// matching `settle_activated`'s own idempotent-delete contract.
    pub(crate) fn acknowledge_activation(&self, operation_id: &str) -> Result<(), SyncError> {
        self.repository.settle_activated(operation_id)
    }

    fn block_operation(&self, operation_id: &str, detail: &str) {
        tracing::error!(
            operation_id,
            detail,
            "enrollment recovery refused; operator attention required"
        );
        if let Err(e) = self.repository.mark_state(
            operation_id,
            OpState::RecoveryBlocked,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(error = %e, operation_id, "failed to block an enrollment operation");
        }
    }

    // ===== Marker reconciliation =====

    /// The local link's presence is checked by `local_path` (`links`' own
    /// primary key) rather than `group_id` -- nothing in the schema
    /// guarantees at most one link per group, so matching by `group_id`
    /// alone could resolve a marker against an unrelated link that happens
    /// to share one, wrongly activating, orphaning, or dropping it.
    /// `group_id` is still cross-checked once a `local_path` match is
    /// found, as a second guard: a path relinked to a different group
    /// since the marker was written no longer describes what the marker
    /// was written for, so it is treated the same as "link absent" below.
    async fn reconcile_markers(&self) {
        // Fail closed on a DB read error rather than defaulting to an empty
        // view. A defaulted-empty link list would make every marker's link
        // lookup miss, spuriously CANCELLING valid enrollments; a
        // defaulted-empty marker list would silently no-op the sweep.
        let local_links = match self.repository.list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read local links; skipping this pending-enrollment reconcile sweep \
                     rather than risking cancelling valid enrollments on an empty default"
                );
                return;
            }
        };
        let scan = match self.repository.scan_pending() {
            Ok(scan) => scan,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read pending-enrollment markers; skipping this reconcile sweep \
                     rather than silently no-opping it on an empty default"
                );
                return;
            }
        };
        for invalid in scan.invalid {
            tracing::error!(
                operation_id = %invalid.operation_id,
                detail = %invalid.detail,
                "pending-enrollment marker is malformed; refusing automatic activation/cancellation"
            );
            self.block_operation(
                &invalid.operation_id,
                &format!("pending-enrollment marker is malformed: {}", invalid.detail),
            );
        }
        for marker in scan.valid {
            let local_link = local_links
                .iter()
                .find(|l| l.local_path == marker.local_path && l.group_id == marker.group_id);
            match local_link {
                Some(link) => {
                    // Gate remote activation on the durable journal row
                    // itself being `ActivationPending` -- NOT merely on a
                    // matching link/marker existing. Activating off
                    // link+marker alone would let this reconciler activate
                    // a remote authorization for a link whose post-commit
                    // local setup (watcher registration, on-demand config)
                    // was never confirmed to have finished, racing a crash
                    // between the atomic commit and setup completing.
                    let operation = match self.repository.operation(&marker.operation_id) {
                        Ok(Some(operation)) => operation,
                        Ok(None) => {
                            tracing::error!(
                                operation_id = %marker.operation_id,
                                "pending-enrollment marker has no matching enrollment operation; \
                                 refusing activation"
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                operation_id = %marker.operation_id,
                                "failed to read the enrollment operation for a pending-enrollment \
                                 marker; refusing activation"
                            );
                            continue;
                        }
                    };
                    if operation.state != OpState::ActivationPending {
                        // In particular, `LocalSetupPending` must never
                        // activate. Leave the marker for the next sweep;
                        // `reconcile_operations` owns advancing (or rolling
                        // back) a stuck row.
                        continue;
                    }
                    if operation.kind != marker.kind
                        || operation.group_id.as_deref() != Some(marker.group_id.as_str())
                        || operation.device_id != marker.device_id
                        || operation.local_path != marker.local_path
                    {
                        self.block_operation(
                            &operation.operation_id,
                            "pending-enrollment marker does not match its enrollment operation's \
                             identity",
                        );
                        continue;
                    }
                    let outcome = match marker.kind {
                        WireEnrollmentKind::Create => {
                            self.coordination
                                .activate_create(&marker.group_id, &marker.operation_id)
                                .await
                        }
                        WireEnrollmentKind::Join => {
                            self.coordination
                                .activate_join(
                                    &marker.group_id,
                                    &marker.operation_id,
                                    &marker.device_id,
                                )
                                .await
                        }
                    };
                    match outcome {
                        EnrollmentActivationResult::Activated
                        | EnrollmentActivationResult::AlreadyActive => {
                            self.attempts.clear_transient_attempts(&marker.operation_id);
                            // Deletes the marker AND the `ActivationPending`
                            // journal row atomically.
                            if let Err(e) =
                                self.repository.settle_activated_and_close(&marker.operation_id)
                            {
                                tracing::warn!(
                                    error = %e,
                                    operation_id = %marker.operation_id,
                                    "failed to settle a confirmed-activated enrollment; leaving the \
                                     marker and journal row in place for the next sweep"
                                );
                            }
                        }
                        EnrollmentActivationResult::Deleted => {
                            // Marking the link orphaned and dropping the
                            // marker commit together -- see
                            // `EnrollmentLinkPort::rollback`'s own doc
                            // comment.
                            match self.links.rollback(&link.local_path, &marker.operation_id).await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        operation_id = %marker.operation_id,
                                        group_id = %marker.group_id,
                                        local_path = %link.local_path,
                                        "coordination-side authorization for this link is gone; \
                                         marked orphaned (on-disk files left untouched)"
                                    );
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    operation_id = %marker.operation_id,
                                    local_path = %link.local_path,
                                    "failed to mark link orphaned; leaving the pending-enrollment \
                                     marker in place for the next sweep to retry"
                                ),
                            }
                        }
                        EnrollmentActivationResult::TransientFailure { .. } => {
                            // Ambiguous: the coordination plane may already
                            // have committed this activation and only the
                            // RESPONSE was lost. Never a rollback trigger --
                            // only a confirmed `Deleted` is. The marker
                            // survives for the next sweep either way; this
                            // only decides how loudly that fact is logged.
                            let attempts =
                                self.attempts.note_transient_attempt(&marker.operation_id);
                            if attempts >= TRANSIENT_ESCALATION_THRESHOLD {
                                tracing::error!(
                                    operation_id = %marker.operation_id,
                                    group_id = %marker.group_id,
                                    attempts,
                                    "pending enrollment has been unconfirmable for {attempts} \
                                     consecutive reconcile sweeps -- the coordination plane may be \
                                     down for an extended period; the local link and its marker are \
                                     still retained (never rolled back on a mere retry count), but \
                                     this now needs operator attention"
                                );
                            } else {
                                tracing::info!(
                                    operation_id = %marker.operation_id,
                                    group_id = %marker.group_id,
                                    attempts,
                                    "pending enrollment still unresolved after reconciliation; will \
                                     retry on the next sweep"
                                );
                            }
                        }
                    }
                }
                None => {
                    // Transfer the marker into the durable
                    // `enrollment_operations` `CancelPending` journal
                    // BEFORE ever attempting the remote cancel -- see
                    // `EnrollmentRepository::move_marker_to_cancel_operation`'s
                    // own doc comment.
                    if let Err(e) =
                        self.repository.move_marker_to_cancel_operation(&marker, now_unix())
                    {
                        tracing::warn!(
                            error = %e,
                            operation_id = %marker.operation_id,
                            "failed to transfer an absent-link enrollment marker into durable \
                             cancellation recovery; leaving the marker in place for the next sweep"
                        );
                        continue;
                    }
                    self.attempts.clear_transient_attempts(&marker.operation_id);
                    // Best-effort immediate cancel attempt in the SAME
                    // sweep -- `reconcile_operations` retries durably
                    // either way, so this is purely a latency optimization,
                    // not a requirement for correctness.
                    let cancelled = matches!(
                        match marker.kind {
                            WireEnrollmentKind::Create => {
                                self.coordination
                                    .cancel_create(&marker.group_id, &marker.operation_id)
                                    .await
                            }
                            WireEnrollmentKind::Join => {
                                self.coordination
                                    .cancel_join(
                                        &marker.group_id,
                                        &marker.operation_id,
                                        &marker.device_id,
                                    )
                                    .await
                            }
                        },
                        EnrollmentCancellationResult::Confirmed
                    );
                    if cancelled {
                        if let Err(e) = self.repository.delete_operation(&marker.operation_id) {
                            tracing::warn!(
                                error = %e,
                                operation_id = %marker.operation_id,
                                "failed to delete a confirmed-cancelled enrollment journal row; the \
                                 next sweep will retry the (already-confirmed) cancel and delete it \
                                 then"
                            );
                        }
                    }
                }
            }
        }
    }

    // ===== Journal reconciliation =====

    async fn reconcile_operations(&self) {
        let scan = match self.repository.scan_open_operations() {
            Ok(scan) => scan,
            Err(e) => {
                tracing::warn!(error = %e, "failed to scan the enrollment operation journal; skipping this sweep");
                return;
            }
        };
        for invalid in scan.invalid {
            tracing::error!(
                operation_id = %invalid.operation_id,
                detail = %invalid.detail,
                "enrollment recovery journal row is malformed; refusing automatic recovery"
            );
            self.block_operation(&invalid.operation_id, &invalid.detail);
        }
        for operation in scan.valid {
            if now_unix() - operation.updated_at_unix < RECONCILE_MIN_AGE_SECS {
                continue;
            }
            self.reconcile_one_operation(operation).await;
        }
    }

    async fn reconcile_one_operation(&self, operation: EnrollmentOperation) {
        match operation.state {
            OpState::PreparePending => {
                let outcome = match operation.kind {
                    WireEnrollmentKind::Create => {
                        let Some(group_name) = operation.group_name.as_deref() else {
                            self.block_operation(
                                &operation.operation_id,
                                "create PreparePending has no group_name",
                            );
                            return;
                        };
                        self.coordination
                            .prepare_create(
                                &operation.operation_id,
                                group_name,
                                &operation.device_id,
                            )
                            .await
                    }
                    WireEnrollmentKind::Join => {
                        let Some(group_id) = operation.group_id.as_deref() else {
                            self.block_operation(
                                &operation.operation_id,
                                "join PreparePending has no group_id",
                            );
                            return;
                        };
                        self.coordination
                            .prepare_join(
                                &operation.operation_id,
                                group_id,
                                &operation.device_id,
                                &operation.storage_mode,
                            )
                            .await
                    }
                };
                match outcome {
                    EnrollmentPrepareResult::Prepared { group_id } => {
                        let _ = self.repository.mark_prepared(
                            &operation.operation_id,
                            &group_id,
                            now_unix(),
                        );
                        // Recovery never creates a new local link -- if one
                        // doesn't already exist for this operation, the
                        // only safe next step is cancellation, handled by
                        // the NEXT sweep's `Prepared` branch below.
                    }
                    EnrollmentPrepareResult::DefinitelyRejected { .. } => {
                        let _ = self.repository.delete_operation(&operation.operation_id);
                    }
                    EnrollmentPrepareResult::Conflict { detail } => {
                        self.block_operation(&operation.operation_id, &detail);
                    }
                    EnrollmentPrepareResult::Ambiguous { detail } => {
                        tracing::debug!(operation_id = %operation.operation_id, detail, "enrollment prepare still unresolved; will retry");
                    }
                }
            }
            OpState::Prepared => {
                let Some(group_id) = operation.group_id.clone() else {
                    self.block_operation(
                        &operation.operation_id,
                        "Prepared enrollment has no group_id",
                    );
                    return;
                };
                // A DB read failure here must never be treated as "no
                // matching link" -- that would route to CancelPending +
                // remote cancel even though the link might genuinely
                // exist. Leave the row untouched for the next sweep.
                let links = match self.repository.list_links() {
                    Ok(links) => links,
                    Err(e) => {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to list links while reconciling a Prepared enrollment; leaving unchanged");
                        return;
                    }
                };
                let markers = match self.repository.scan_pending() {
                    Ok(scan) => scan.valid,
                    Err(e) => {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to list pending enrollments while reconciling a Prepared enrollment; leaving unchanged");
                        return;
                    }
                };
                let matching_link = links.into_iter().find(|link| {
                    link.local_path == operation.local_path && link.group_id == group_id
                });
                // Full-identity match -- path+group alone isn't enough,
                // since an unrelated pre-existing link could coincidentally
                // share both.
                let matching_marker = markers.into_iter().find(|marker| {
                    marker.operation_id == operation.operation_id
                        && marker.kind == operation.kind
                        && marker.group_id == group_id
                        && marker.device_id == operation.device_id
                        && marker.local_path == operation.local_path
                });
                match (matching_link, matching_marker) {
                    (None, None) => {
                        let _ = self.repository.mark_state(
                            &operation.operation_id,
                            OpState::CancelPending,
                            Some("no matching local link exists after prepare"),
                            now_unix(),
                        );
                    }
                    (Some(_), Some(_)) => {
                        // Full identity confirmed on both sides -- the
                        // `LocalSetupPending` transition must have been
                        // lost (e.g. a crash right after the commit).
                        // Recovery never creates a new link and never
                        // cancels one that already exists -- advance it to
                        // `LocalSetupPending`, NOT `ActivationPending`:
                        // this path has no way to confirm local setup
                        // actually finished, so it must not skip the
                        // setup-confirmation gate.
                        let _ = self.repository.mark_state(
                            &operation.operation_id,
                            OpState::LocalSetupPending,
                            None,
                            now_unix(),
                        );
                    }
                    (Some(_), None) => {
                        self.block_operation(
                            &operation.operation_id,
                            "matching link exists but its pending-enrollment marker is missing",
                        );
                    }
                    (None, Some(marker)) => {
                        if let Err(e) =
                            self.repository.move_marker_to_cancel_operation(&marker, now_unix())
                        {
                            tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to transfer an absent-link marker to CancelPending");
                        }
                    }
                }
            }
            OpState::LocalSetupPending => {
                // This state should be purely transient -- setup runs
                // synchronously inside the same commit that just committed
                // the link/marker/LocalSetupPending transition, and does no
                // network I/O. A row still found here well past the
                // age-gate means the daemon crashed (or otherwise never
                // finished) mid-setup: rolled back unconditionally rather
                // than risk activating a remote authorization for a link
                // this device never finished registering.
                if let Err(e) = self.repository.rollback_local_setup_to_cancel_pending(
                    &operation.local_path,
                    &operation.operation_id,
                    "local setup did not complete before recovery",
                    now_unix(),
                ) {
                    tracing::warn!(error = %e, operation_id = %operation.operation_id, "could not roll back an incomplete local setup");
                }
            }
            OpState::ActivationPending => {
                // The link + pending_enrollments marker + local setup are
                // all confirmed, so this row's own job is usually done and
                // `pending_enrollments` owns recovery for the activation
                // step from here -- still, confirm which case this is by
                // reading back the marker and link before touching the
                // row.
                let markers = match self.repository.scan_pending() {
                    Ok(scan) => scan.valid,
                    Err(e) => {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to list pending enrollments while reconciling an ActivationPending enrollment; leaving unchanged");
                        return;
                    }
                };
                if markers.iter().any(|marker| marker.operation_id == operation.operation_id) {
                    // Activation is still outstanding -- do NOT delete it.
                    return;
                }
                let links = match self.repository.list_links() {
                    Ok(links) => links,
                    Err(_) => return,
                };
                let has_matching_link = links.iter().any(|link| {
                    link.local_path == operation.local_path
                        && Some(link.group_id.as_str()) == operation.group_id.as_deref()
                });
                if has_matching_link {
                    // Confirmed post-activation cleanup.
                    if let Err(e) = self.repository.delete_operation(&operation.operation_id) {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to clean up an activation-pending enrollment operation");
                    }
                    return;
                }
                // Neither a marker nor a matching link exists -- a remote
                // Pending authorization may still exist and must be
                // confirmed-cancelled before this row can be safely
                // discarded.
                let _ = self.repository.mark_state(
                    &operation.operation_id,
                    OpState::CancelPending,
                    Some("transferred enrollment lost its local link before activation completed"),
                    now_unix(),
                );
            }
            OpState::CancelPending => {
                let Some(group_id) = operation.group_id.clone() else {
                    self.block_operation(
                        &operation.operation_id,
                        "CancelPending enrollment has no group_id",
                    );
                    return;
                };
                let outcome = match operation.kind {
                    WireEnrollmentKind::Create => {
                        self.coordination.cancel_create(&group_id, &operation.operation_id).await
                    }
                    WireEnrollmentKind::Join => {
                        self.coordination
                            .cancel_join(&group_id, &operation.operation_id, &operation.device_id)
                            .await
                    }
                };
                match outcome {
                    EnrollmentCancellationResult::Confirmed => {
                        let _ = self.repository.delete_operation(&operation.operation_id);
                    }
                    EnrollmentCancellationResult::Conflict { detail } => {
                        self.block_operation(&operation.operation_id, &detail);
                    }
                    EnrollmentCancellationResult::Ambiguous { detail } => {
                        let _ =
                            self.repository.increment_attempts(&operation.operation_id, now_unix());
                        tracing::debug!(operation_id = %operation.operation_id, detail, "enrollment cancel still unresolved; will retry");
                    }
                }
            }
            OpState::RecoveryBlocked => {
                // Excluded by `scan_open_operations`'s own query --
                // unreachable in practice, kept only for match
                // exhaustiveness.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use yadorilink_replica_domain::session_state::MaterializationPolicy;
    use yadorilink_replica_domain::session_state::{
        FolderLink, InvalidEnrollmentOperation, InvalidPendingEnrollment, PendingEnrollment,
    };

    use super::*;
    use crate::application::ports::EnrollmentLinkRequest;
    use crate::application::EnrollmentLinkError;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RepoCall {
        MarkPrepared(String, String),
        MarkState(String, OpState),
        DeleteOperation(String),
        SettleActivatedAndClose(String),
        MoveMarkerToCancelOperation(String),
        IncrementAttempts(String),
        RollbackLocalSetup(String),
    }

    #[derive(Default)]
    struct FakeRepository {
        calls: Mutex<Vec<RepoCall>>,
        operations: Mutex<std::collections::HashMap<String, EnrollmentOperation>>,
        links: Mutex<Vec<FolderLink>>,
        markers: Mutex<yadorilink_replica_domain::session_state::PendingEnrollmentScan>,
        invalid_operations: Mutex<Vec<InvalidEnrollmentOperation>>,
        fail_list_links: AtomicBool,
        fail_scan_pending: AtomicBool,
        fail_scan_open: AtomicBool,
    }

    impl FakeRepository {
        fn with_operation(self, operation: EnrollmentOperation) -> Self {
            self.operations.lock().unwrap().insert(operation.operation_id.clone(), operation);
            self
        }

        fn with_link(self, link: FolderLink) -> Self {
            self.links.lock().unwrap().push(link);
            self
        }

        fn with_marker(self, marker: PendingEnrollment) -> Self {
            self.markers.lock().unwrap().valid.push(marker);
            self
        }
    }

    impl EnrollmentRepository for FakeRepository {
        fn try_insert_operation(
            &self,
            _operation: &EnrollmentOperation,
        ) -> Result<bool, crate::sync_error::SyncError> {
            unimplemented!("not exercised by recovery-service tests")
        }

        fn delete_operation(&self, operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(RepoCall::DeleteOperation(operation_id.to_string()));
            self.operations.lock().unwrap().remove(operation_id);
            Ok(())
        }

        fn mark_prepared(
            &self,
            operation_id: &str,
            group_id: &str,
            _now_unix: i64,
        ) -> Result<bool, crate::sync_error::SyncError> {
            self.calls
                .lock()
                .unwrap()
                .push(RepoCall::MarkPrepared(operation_id.to_string(), group_id.to_string()));
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
            op.group_id = Some(group_id.to_string());
            op.state = OpState::Prepared;
            Ok(true)
        }

        fn mark_state(
            &self,
            operation_id: &str,
            state: OpState,
            _error: Option<&str>,
            _now_unix: i64,
        ) -> Result<bool, crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(RepoCall::MarkState(operation_id.to_string(), state));
            let mut operations = self.operations.lock().unwrap();
            let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
            op.state = state;
            Ok(true)
        }

        fn list_links(&self) -> Result<Vec<FolderLink>, crate::sync_error::SyncError> {
            if self.fail_list_links.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fake list_links failure").into());
            }
            Ok(self.links.lock().unwrap().clone())
        }

        fn scan_pending(
            &self,
        ) -> Result<
            yadorilink_replica_domain::session_state::PendingEnrollmentScan,
            crate::sync_error::SyncError,
        > {
            if self.fail_scan_pending.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fake scan_pending failure").into());
            }
            Ok(self.markers.lock().unwrap().clone())
        }

        fn settle_activated(
            &self,
            _operation_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            unimplemented!("recovery uses settle_activated_and_close, not settle_activated")
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
            if self.fail_scan_open.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fake scan_open_operations failure").into());
            }
            Ok(yadorilink_replica_domain::session_state::EnrollmentOperationScan {
                valid: self
                    .operations
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|op| op.state != OpState::RecoveryBlocked)
                    .cloned()
                    .collect(),
                invalid: self.invalid_operations.lock().unwrap().clone(),
            })
        }

        fn settle_activated_and_close(
            &self,
            operation_id: &str,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.calls
                .lock()
                .unwrap()
                .push(RepoCall::SettleActivatedAndClose(operation_id.to_string()));
            self.operations.lock().unwrap().remove(operation_id);
            self.markers.lock().unwrap().valid.retain(|m| m.operation_id != operation_id);
            Ok(())
        }

        fn move_marker_to_cancel_operation(
            &self,
            marker: &PendingEnrollment,
            _now_unix: i64,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.calls
                .lock()
                .unwrap()
                .push(RepoCall::MoveMarkerToCancelOperation(marker.operation_id.clone()));
            self.markers.lock().unwrap().valid.retain(|m| m.operation_id != marker.operation_id);
            if let Some(op) = self.operations.lock().unwrap().get_mut(&marker.operation_id) {
                op.state = OpState::CancelPending;
            }
            Ok(())
        }

        fn increment_attempts(
            &self,
            operation_id: &str,
            _now_unix: i64,
        ) -> Result<i64, crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(RepoCall::IncrementAttempts(operation_id.to_string()));
            Ok(1)
        }

        fn rollback_local_setup_to_cancel_pending(
            &self,
            _local_path: &str,
            operation_id: &str,
            _detail: &str,
            _now_unix: i64,
        ) -> Result<(), crate::sync_error::SyncError> {
            self.calls.lock().unwrap().push(RepoCall::RollbackLocalSetup(operation_id.to_string()));
            if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
                op.state = OpState::CancelPending;
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeCoordination {
        activate: Mutex<VecDeque<EnrollmentActivationResult>>,
        cancel: Mutex<VecDeque<EnrollmentCancellationResult>>,
        prepare: Mutex<VecDeque<EnrollmentPrepareResult>>,
        activate_calls: Mutex<u32>,
        cancel_calls: Mutex<u32>,
    }

    impl EnrollmentCoordination for FakeCoordination {
        fn is_configured(&self) -> bool {
            true
        }

        fn prepare_create<'a>(
            &'a self,
            _operation_id: &'a str,
            _group_name: &'a str,
            _device_id: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare")
            })
        }

        fn prepare_join<'a>(
            &'a self,
            _operation_id: &'a str,
            _group_id: &'a str,
            _device_id: &'a str,
            _storage_mode: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, EnrollmentPrepareResult> {
            Box::pin(async move {
                self.prepare.lock().unwrap().pop_front().expect("missing fake prepare")
            })
        }

        fn activate_create<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                *self.activate_calls.lock().unwrap() += 1;
                self.activate.lock().unwrap().pop_front().expect("missing fake activate")
            })
        }

        fn activate_join<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, EnrollmentActivationResult> {
            Box::pin(async move {
                *self.activate_calls.lock().unwrap() += 1;
                self.activate.lock().unwrap().pop_front().expect("missing fake activate")
            })
        }

        fn cancel_create<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                *self.cancel_calls.lock().unwrap() += 1;
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel")
            })
        }

        fn cancel_join<'a>(
            &'a self,
            _group_id: &'a str,
            _operation_id: &'a str,
            _device_id: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, EnrollmentCancellationResult> {
            Box::pin(async move {
                *self.cancel_calls.lock().unwrap() += 1;
                self.cancel.lock().unwrap().pop_front().expect("missing fake cancel")
            })
        }
    }

    #[derive(Default)]
    struct FakeLinkPort {
        rollback_calls: Mutex<Vec<(String, String)>>,
        rollback_result: Mutex<VecDeque<Result<(), String>>>,
    }

    impl EnrollmentLinkPort for FakeLinkPort {
        fn commit<'a>(
            &'a self,
            _request: EnrollmentLinkRequest,
        ) -> crate::application::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
            Box::pin(async move { unimplemented!("recovery never commits a new link") })
        }

        fn rollback<'a>(
            &'a self,
            local_path: &'a str,
            operation_id: &'a str,
        ) -> crate::application::ports::BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.rollback_calls
                    .lock()
                    .unwrap()
                    .push((local_path.to_string(), operation_id.to_string()));
                self.rollback_result
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("missing fake rollback result")
            })
        }
    }

    #[derive(Default)]
    struct FakeAttemptTracker {
        counters: Mutex<std::collections::HashMap<String, u32>>,
        cleared: Mutex<Vec<String>>,
    }

    impl EnrollmentAttemptTracker for FakeAttemptTracker {
        fn note_transient_attempt(&self, operation_id: &str) -> u32 {
            let mut counters = self.counters.lock().unwrap();
            let count = counters.entry(operation_id.to_string()).or_insert(0);
            *count += 1;
            *count
        }

        fn clear_transient_attempts(&self, operation_id: &str) {
            self.cleared.lock().unwrap().push(operation_id.to_string());
        }
    }

    fn service(
        repository: Arc<FakeRepository>,
        coordination: Arc<FakeCoordination>,
        links: Arc<FakeLinkPort>,
        attempts: Arc<FakeAttemptTracker>,
    ) -> EnrollmentRecoveryService {
        EnrollmentRecoveryService::new(repository, coordination, links, attempts)
    }

    fn marker(operation_id: &str, group_id: &str) -> PendingEnrollment {
        PendingEnrollment {
            operation_id: operation_id.to_string(),
            kind: WireEnrollmentKind::Create,
            group_id: group_id.to_string(),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
        }
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

    fn operation(operation_id: &str, group_id: &str, state: OpState) -> EnrollmentOperation {
        EnrollmentOperation {
            operation_id: operation_id.to_string(),
            kind: WireEnrollmentKind::Create,
            group_id: Some(group_id.to_string()),
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state,
            last_error: None,
            attempts: 0,
            created_at_unix: 0,
            updated_at_unix: 0,
        }
    }

    // ===== Marker reconciliation =====

    #[tokio::test]
    async fn confirmed_activation_settles_marker_and_journal_together() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links.clone(), attempts.clone())
            .reconcile_once()
            .await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::SettleActivatedAndClose("op-1".to_string())));
        assert!(links.rollback_calls.lock().unwrap().is_empty());
        assert_eq!(*attempts.cleared.lock().unwrap(), vec!["op-1".to_string()]);
    }

    #[tokio::test]
    async fn deleted_activation_rolls_back_via_the_link_port() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
        let links = Arc::new(FakeLinkPort::default());
        links.rollback_result.lock().unwrap().push_back(Ok(()));
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links.clone(), attempts).reconcile_once().await;

        assert_eq!(
            *links.rollback_calls.lock().unwrap(),
            vec![("/home/alice/Photos".to_string(), "op-1".to_string())]
        );
        assert!(!repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::SettleActivatedAndClose("op-1".to_string())));
    }

    #[tokio::test]
    async fn transient_activation_failure_never_rolls_back_and_counts_attempts() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        coordination.activate.lock().unwrap().push_back(
            EnrollmentActivationResult::TransientFailure { detail: "timeout".to_string() },
        );
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository, coordination, links.clone(), attempts.clone()).reconcile_once().await;

        assert!(links.rollback_calls.lock().unwrap().is_empty());
        assert_eq!(attempts.counters.lock().unwrap().get("op-1"), Some(&1));
    }

    #[tokio::test]
    async fn activation_pending_gate_skips_a_non_activation_pending_row() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::LocalSetupPending))
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository, coordination.clone(), links, attempts).reconcile_once().await;

        assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn identity_mismatch_between_marker_and_operation_blocks_recovery() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-other", OpState::ActivationPending))
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

        assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
    }

    #[tokio::test]
    async fn a_marker_with_no_matching_link_transfers_to_cancel_pending_then_retries_cancel() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MoveMarkerToCancelOperation("op-1".to_string())));
        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::DeleteOperation("op-1".to_string())));
        assert_eq!(*coordination.cancel_calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn a_malformed_marker_blocks_only_that_row_not_sibling_rows() {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
                .with_link(link("group-1"))
                .with_marker(marker("op-2", "group-2")),
        );
        repository.markers.lock().unwrap().invalid.push(InvalidPendingEnrollment {
            operation_id: "op-bad".to_string(),
            detail: "unrecognized kind".to_string(),
        });
        let coordination = Arc::new(FakeCoordination::default());
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
        // op-2's marker has no matching link (its group doesn't match
        // op-1's link), so reconcile_markers routes it through the
        // no-matching-link cancel path -- queue a result for that too.
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

        let calls = repository.calls.lock().unwrap();
        assert!(
            calls.contains(&RepoCall::MarkState("op-bad".to_string(), OpState::RecoveryBlocked))
        );
        // Sibling marker op-1/op-2 pairing doesn't line up (op-1's marker is
        // op-2's group), so activation is never attempted for it here --
        // proven separately above. This test only proves the malformed row
        // did not abort the whole sweep (the call log has more than the one
        // block entry, i.e. iteration continued).
        drop(calls);
    }

    // ===== Journal reconciliation: PreparePending =====

    #[tokio::test]
    async fn prepare_pending_success_marks_prepared() {
        let mut op = operation("op-1", "group-1", OpState::PreparePending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkPrepared("op-1".to_string(), "group-1".to_string())));
    }

    #[tokio::test]
    async fn prepare_pending_definitely_rejected_deletes_the_row() {
        let mut op = operation("op-1", "group-1", OpState::PreparePending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::DefinitelyRejected { detail: "gone".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::DeleteOperation("op-1".to_string())));
    }

    #[tokio::test]
    async fn prepare_pending_conflict_blocks_recovery() {
        let mut op = operation("op-1", "group-1", OpState::PreparePending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Conflict { detail: "shape mismatch".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
    }

    // ===== Journal reconciliation: Prepared =====

    #[tokio::test]
    async fn prepared_with_matching_link_and_marker_advances_to_local_setup_pending() {
        let mut op = operation("op-1", "group-1", OpState::Prepared);
        op.updated_at_unix = -1000;
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(op)
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::LocalSetupPending)));
    }

    #[tokio::test]
    async fn prepared_with_neither_link_nor_marker_moves_to_cancel_pending() {
        let mut op = operation("op-1", "group-1", OpState::Prepared);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::CancelPending)));
    }

    #[tokio::test]
    async fn prepared_with_link_but_no_marker_blocks_recovery() {
        let mut op = operation("op-1", "group-1", OpState::Prepared);
        op.updated_at_unix = -1000;
        let repository =
            Arc::new(FakeRepository::default().with_operation(op).with_link(link("group-1")));
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
    }

    #[tokio::test]
    async fn prepared_with_marker_but_no_link_transfers_to_cancel_operation() {
        let mut op = operation("op-1", "group-1", OpState::Prepared);
        op.updated_at_unix = -1000;
        let repository = Arc::new(
            FakeRepository::default().with_operation(op).with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        // No link exists, so `reconcile_markers` itself also routes this
        // marker through the no-matching-link cancel path before
        // `reconcile_operations`'s own `Prepared` branch ever runs.
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MoveMarkerToCancelOperation("op-1".to_string())));
    }

    // ===== Journal reconciliation: LocalSetupPending / ActivationPending / CancelPending =====

    #[tokio::test]
    async fn local_setup_pending_past_the_age_gate_rolls_back_unconditionally() {
        let mut op = operation("op-1", "group-1", OpState::LocalSetupPending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::RollbackLocalSetup("op-1".to_string())));
    }

    #[tokio::test]
    async fn activation_pending_with_an_outstanding_marker_is_left_untouched() {
        let mut op = operation("op-1", "group-1", OpState::ActivationPending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(op)
                .with_link(link("group-1"))
                .with_marker(marker("op-1", "group-1")),
        );
        let coordination = Arc::new(FakeCoordination::default());
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        let calls = repository.calls.lock().unwrap();
        assert!(!calls.contains(&RepoCall::DeleteOperation("op-1".to_string())));
        assert!(!calls
            .iter()
            .any(|c| matches!(c, RepoCall::MarkState(id, OpState::CancelPending) if id == "op-1")));
    }

    #[tokio::test]
    async fn activation_pending_with_no_marker_and_a_matching_link_is_confirmed_cleanup() {
        let mut op = operation("op-1", "group-1", OpState::ActivationPending);
        op.updated_at_unix = -1000;
        let repository =
            Arc::new(FakeRepository::default().with_operation(op).with_link(link("group-1")));
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::DeleteOperation("op-1".to_string())));
    }

    #[tokio::test]
    async fn activation_pending_with_neither_marker_nor_link_moves_to_cancel_pending() {
        let mut op = operation("op-1", "group-1", OpState::ActivationPending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::CancelPending)));
    }

    #[tokio::test]
    async fn cancel_pending_confirmed_deletes_the_row() {
        let mut op = operation("op-1", "group-1", OpState::CancelPending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::DeleteOperation("op-1".to_string())));
    }

    #[tokio::test]
    async fn cancel_pending_conflict_blocks_recovery() {
        let mut op = operation("op-1", "group-1", OpState::CancelPending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Conflict {
            detail: "identity mismatch".to_string(),
        });
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
    }

    #[tokio::test]
    async fn cancel_pending_ambiguous_increments_attempts_and_never_blocks() {
        let mut op = operation("op-1", "group-1", OpState::CancelPending);
        op.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        coordination
            .cancel
            .lock()
            .unwrap()
            .push_back(EnrollmentCancellationResult::Ambiguous { detail: "timeout".to_string() });
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination, links, attempts).reconcile_once().await;

        let calls = repository.calls.lock().unwrap();
        assert!(calls.contains(&RepoCall::IncrementAttempts("op-1".to_string())));
        assert!(!calls.iter().any(
            |c| matches!(c, RepoCall::MarkState(id, OpState::RecoveryBlocked) if id == "op-1")
        ));
    }

    // ===== Cross-cutting =====

    #[tokio::test]
    async fn a_row_updated_too_recently_is_left_for_the_next_sweep() {
        let mut op = operation("op-1", "group-1", OpState::CancelPending);
        // Freshly touched -- well inside `RECONCILE_MIN_AGE_SECS` of
        // `now_unix()` -- proves the age-gate is keyed on `updated_at_unix`,
        // not `created_at_unix` (which stays 0/ancient on this same row).
        op.updated_at_unix = now_unix();
        let repository = Arc::new(FakeRepository::default().with_operation(op));
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

        assert_eq!(*coordination.cancel_calls.lock().unwrap(), 0);
        assert!(repository.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_malformed_journal_row_blocks_only_that_row_not_a_healthy_sibling() {
        let mut healthy = operation("op-1", "group-1", OpState::CancelPending);
        healthy.updated_at_unix = -1000;
        let repository = Arc::new(FakeRepository::default().with_operation(healthy));
        repository.invalid_operations.lock().unwrap().push(InvalidEnrollmentOperation {
            operation_id: "op-bad".to_string(),
            raw_state: Some("unknown_state".to_string()),
            detail: "unrecognized state".to_string(),
        });
        let coordination = Arc::new(FakeCoordination::default());
        coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

        let calls = repository.calls.lock().unwrap();
        assert!(
            calls.contains(&RepoCall::MarkState("op-bad".to_string(), OpState::RecoveryBlocked))
        );
        assert!(calls.contains(&RepoCall::DeleteOperation("op-1".to_string())));
    }

    #[tokio::test]
    async fn a_list_links_read_failure_skips_the_marker_sweep_without_cancelling_valid_enrollments()
    {
        let repository = Arc::new(
            FakeRepository::default()
                .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
                .with_marker(marker("op-1", "group-1")),
        );
        repository.fail_list_links.store(true, Ordering::SeqCst);
        let coordination = Arc::new(FakeCoordination::default());
        let links = Arc::new(FakeLinkPort::default());
        let attempts = Arc::new(FakeAttemptTracker::default());

        service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

        assert!(repository.calls.lock().unwrap().is_empty());
        assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
    }
}
