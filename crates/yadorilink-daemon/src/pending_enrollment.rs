//! A durable local marker for a create/join whose local link has already
//! been committed but whose matching coordination-plane activation has not
//! yet been confirmed — the crash-safety net for a process killed in that
//! exact window. See the coordination plane's own explicit Pending -> Active
//! enrollment protocol for the server side this reconciles against: a
//! create/join authorizes a Pending group/membership there BEFORE the local
//! link is known to exist, and only `activate` turns it into a real, counted
//! enrollment. If the caller is killed after committing the local link but
//! before either confirming activation or compensating a failure, this
//! marker is what lets the next reconciliation pass finish the job instead
//! of leaving a stranded local link with no matching server-side record (or
//! vice versa).
//!
//! Deliberately NOT a general journal: it records only the handful of fields
//! needed to retry activation or notice there is nothing left to activate
//! (see [`reconcile`], run both on daemon startup and periodically
//! thereafter, alongside its other crash-recovery passes such as
//! `SyncState::reset_stale_hydrating_to_placeholder`).
//!
//! Markers are persisted in `SyncState`'s SQLite database (the
//! `pending_enrollments` table) rather than a separate file, so a marker for
//! a link can be written in the same transaction as the link itself
//! ([`yadorilink_sync_core::index::SyncState::add_link_with_pending_enrollment`]) --
//! a local link is never committed without a durable trace of the
//! coordination-side enrollment it depends on. A marker's ordinary lifecycle
//! is: written atomically with its link's commit, removed once the matching
//! activate call is confirmed (either by the caller directly, or by
//! [`reconcile`]). It only survives to be swept by `reconcile` if the
//! process that would have removed it (or the daemon itself) was killed in
//! between.

use std::sync::Arc;

pub use yadorilink_sync_core::index::PendingEnrollment;
use yadorilink_sync_core::index::SyncState;
pub use yadorilink_sync_core::types::EnrollmentKind;

use crate::coordination_client::ActivateOutcome;
use crate::daemon_state::DaemonState;

/// How many CONSECUTIVE `TransientFailure` activate outcomes a single
/// marker can accumulate across reconcile sweeps before it is escalated (a
/// `tracing::error!` line, not just the ordinary per-sweep trace) -- see
/// `DaemonState::note_pending_enrollment_transient_attempt`'s doc comment.
/// Purely a visibility bound: the retry itself is never abandoned and the
/// local link/marker are never rolled back on a mere attempt count (only a
/// confirmed `Deleted` outcome does that). At the default
/// `PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL`, this is a small number of
/// minutes' worth of an unconfirmable coordination plane -- long enough to
/// absorb an ordinary transient blip, short enough that a real outage
/// surfaces promptly rather than sitting silent.
const TRANSIENT_ESCALATION_THRESHOLD: u32 = 20;

/// Persists a marker for a local link that was just committed but whose
/// server-side activation has not been confirmed yet. Replaces any existing
/// marker for the same `operation_id` (idempotent: re-recording after a
/// retry that reaches this point again is a plain overwrite, not a
/// duplicate entry). Prefer
/// [`yadorilink_sync_core::index::SyncState::add_link_with_pending_enrollment`]
/// when the link itself is being created in the same step, so the two
/// writes commit atomically.
pub fn record(sync_state: &SyncState, marker: PendingEnrollment) {
    if let Err(e) = sync_state.record_pending_enrollment(&marker) {
        tracing::warn!(error = %e, "failed to persist pending-enrollment marker");
    }
}

/// Removes a marker once its activation (or compensating rollback) has been
/// confirmed — the ordinary, non-crash end of its lifecycle. A no-op if the
/// marker is already gone.
pub fn remove(sync_state: &SyncState, operation_id: &str) {
    if let Err(e) = sync_state.remove_pending_enrollment(operation_id) {
        tracing::warn!(error = %e, "failed to remove pending-enrollment marker");
    }
}

/// Every marker currently outstanding, for a caller that wants to inspect
/// them without also reconciling (e.g. tests).
pub fn list(sync_state: &SyncState) -> Vec<PendingEnrollment> {
    sync_state.list_pending_enrollments().unwrap_or_default()
}

/// Abstracts the coordination-plane activate/cancel calls `reconcile` needs,
/// so it can be exercised against a fake without real networking --
/// production always uses [`RealCoordinationEnrollment`], which delegates to
/// `coordination_client`'s free functions.
pub trait CoordinationEnrollment {
    fn activate_create(
        &self,
        group_id: &str,
        operation_id: &str,
    ) -> impl std::future::Future<Output = ActivateOutcome> + Send;
    fn activate_join(
        &self,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> impl std::future::Future<Output = ActivateOutcome> + Send;
    fn cancel_create(
        &self,
        group_id: &str,
        operation_id: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
    fn cancel_join(
        &self,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
}

struct RealCoordinationEnrollment<'a> {
    addr: &'a str,
    access_token: &'a str,
}

impl CoordinationEnrollment for RealCoordinationEnrollment<'_> {
    async fn activate_create(&self, group_id: &str, operation_id: &str) -> ActivateOutcome {
        crate::coordination_client::activate_create(
            self.addr,
            self.access_token,
            group_id,
            operation_id,
        )
        .await
    }
    async fn activate_join(
        &self,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> ActivateOutcome {
        crate::coordination_client::activate_join(
            self.addr,
            self.access_token,
            group_id,
            operation_id,
            device_id,
        )
        .await
    }
    async fn cancel_create(&self, group_id: &str, operation_id: &str) -> bool {
        crate::coordination_client::cancel_create(
            self.addr,
            self.access_token,
            group_id,
            operation_id,
        )
        .await
    }
    async fn cancel_join(&self, group_id: &str, operation_id: &str, device_id: &str) -> bool {
        crate::coordination_client::cancel_join(
            self.addr,
            self.access_token,
            group_id,
            operation_id,
            device_id,
        )
        .await
    }
}

/// Reconciliation: for every marker left over from a previous run (or a
/// previous sweep), retry the coordination-plane activation if the local
/// link it names is still present, or cancel the still-Pending row if it is
/// not. Run both on daemon startup and periodically thereafter (see
/// `app.rs`'s `PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL`).
pub async fn reconcile(state: &Arc<DaemonState>, coordination_addr: &str, access_token: &str) {
    reconcile_with(state, &RealCoordinationEnrollment { addr: coordination_addr, access_token })
        .await
}

/// The testable half of [`reconcile`] — takes the coordination client as a
/// parameter so a test can supply a fake [`CoordinationEnrollment`] instead
/// of making real network calls.
///
/// The local link's presence is checked by `local_path` (`links`' own
/// primary key, and the field `SyncState::add_link_with_pending_enrollment`
/// commits the marker for) rather than `group_id` -- nothing in the schema
/// guarantees at most one link per group, so matching by `group_id` alone
/// could resolve a marker against an unrelated link that happens to share
/// one, wrongly activating, orphaning, or dropping it. `group_id` is still
/// cross-checked once a `local_path` match is found, as a second guard:
/// a path relinked to a different group since the marker was written no
/// longer describes what the marker was written for, so it is treated the
/// same as "link absent" below.
///
/// Branches on `activate_create`/`activate_join`'s [`ActivateOutcome`]:
/// - `Success`/`AlreadyActive`: the enrollment is done either way (activate
///   is idempotent by `operation_id`), so the marker is dropped.
/// - `Deleted`: the coordination-side group/ACL row is confirmed
///   permanently gone (cancelled or removed server-side, not just
///   unreachable) -- the marker is dropped and the local link is marked
///   [`orphaned`](yadorilink_sync_core::index::FolderLink::orphaned) so sync
///   stops treating it as live. Its on-disk files are never touched.
/// - `TransientFailure`: leaves the marker (and its link) in place for the
///   next sweep to retry -- this covers a network error, a timeout, or a
///   non-404 rejection, none of which say anything final about the row, so
///   none of them ever roll anything back. Bounded only in how loudly it is
///   logged: past `TRANSIENT_ESCALATION_THRESHOLD` consecutive sweeps for
///   the same marker, an escalating error line replaces the ordinary retry
///   trace (see `DaemonState::note_pending_enrollment_transient_attempt`),
///   so an extended coordination-plane outage surfaces instead of retrying
///   invisibly forever -- the retry itself is never abandoned or bounded.
///
/// A marker whose link is absent has nothing left for `remove_link` to
/// clean up that this device's own link table doesn't already reflect; the
/// only outstanding side is the coordination plane's still-Pending row, so
/// it is cancelled (best-effort) instead of activating something with no
/// local copy behind it. Either the cancel lands, or the coordination plane
/// is unreachable and its own TTL sweep is the eventual backstop -- there is
/// nothing further this device can do locally either way, so the marker is
/// dropped rather than retried forever.
async fn reconcile_with(state: &Arc<DaemonState>, client: &impl CoordinationEnrollment) {
    let sync_state = &state.sync_state;
    // Fail closed on a DB read error rather than defaulting to an empty view.
    // A defaulted-empty link list would make every marker's link lookup miss,
    // sending each outstanding enrollment down the "link absent" branch and
    // spuriously CANCELLING valid enrollments; a defaulted-empty marker list
    // would silently no-op the sweep. Neither is safe on a transient error, so
    // skip this sweep entirely and let the next one retry once the DB is
    // readable again.
    let local_links = match sync_state.list_links() {
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
    let markers = match sync_state.list_pending_enrollments() {
        Ok(markers) => markers,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to read pending-enrollment markers; skipping this reconcile sweep rather \
                 than silently no-opping it on an empty default"
            );
            return;
        }
    };
    for marker in markers {
        let local_link = local_links
            .iter()
            .find(|l| l.local_path == marker.local_path && l.group_id == marker.group_id);
        match local_link {
            Some(link) => {
                let outcome = match marker.kind {
                    EnrollmentKind::Create => {
                        client.activate_create(&marker.group_id, &marker.operation_id).await
                    }
                    EnrollmentKind::Join => {
                        client
                            .activate_join(
                                &marker.group_id,
                                &marker.operation_id,
                                &marker.device_id,
                            )
                            .await
                    }
                };
                match outcome {
                    ActivateOutcome::Success | ActivateOutcome::AlreadyActive => {
                        state.clear_pending_enrollment_transient_attempts(&marker.operation_id);
                        remove(sync_state, &marker.operation_id);
                    }
                    ActivateOutcome::Deleted => {
                        // Marking the link orphaned and dropping the marker
                        // commit together (one SQLite transaction) --
                        // dropping the marker first and orphaning second
                        // would let a crash in between lose the marker
                        // without ever having orphaned the link, leaving a
                        // phantom-active link nothing will ever retry or
                        // orphan again. See
                        // `SyncState::orphan_link_and_remove_pending_enrollment`'s
                        // doc comment.
                        match sync_state.orphan_link_and_remove_pending_enrollment(
                            &link.local_path,
                            &marker.operation_id,
                        ) {
                            Ok(()) => {
                                state.clear_pending_enrollment_transient_attempts(
                                    &marker.operation_id,
                                );
                                // The watcher is what feeds this link into
                                // every downstream sync path (local-change
                                // detection, broadcast, peer reconciliation)
                                // -- stopping it now, not just at the next
                                // restart, is what makes "orphaned" actually
                                // mean "no longer a live sync target"
                                // immediately, not just on the next daemon
                                // start.
                                crate::link_manager::stop_link_watch(state, &link.local_path);
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
                    ActivateOutcome::TransientFailure => {
                        // Ambiguous: the coordination plane may already have
                        // committed this activation and only the RESPONSE
                        // was lost (a network error, a timeout, or a 5xx --
                        // `coordination_client::post_activate` folds all
                        // three into this same outcome). Never a rollback
                        // trigger -- only a confirmed `Deleted` is. The
                        // marker survives for the next sweep either way;
                        // this only decides how loudly that fact is logged.
                        let attempts =
                            state.note_pending_enrollment_transient_attempt(&marker.operation_id);
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
                let cancelled = match marker.kind {
                    EnrollmentKind::Create => {
                        client.cancel_create(&marker.group_id, &marker.operation_id).await
                    }
                    EnrollmentKind::Join => {
                        client
                            .cancel_join(&marker.group_id, &marker.operation_id, &marker.device_id)
                            .await
                    }
                };
                let _ = cancelled; // best-effort either way; see doc comment above.
                state.clear_pending_enrollment_transient_attempts(&marker.operation_id);
                remove(sync_state, &marker.operation_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use yadorilink_sync_core::index::SyncState;

    use super::*;

    /// `local_path` matches `test_state_with_link`'s own default fixture
    /// path ("/tmp/photos") so a marker built by this helper resolves
    /// against the link the reconcile-outcome tests below register --
    /// `reconcile_with` now matches a marker to a link by `local_path`, not
    /// just `group_id` (see its own doc comment for why).
    fn sample(operation_id: &str) -> PendingEnrollment {
        PendingEnrollment {
            operation_id: operation_id.to_string(),
            kind: EnrollmentKind::Join,
            group_id: "group-1".to_string(),
            device_id: "device-1".to_string(),
            local_path: "/tmp/photos".to_string(),
        }
    }

    #[test]
    fn record_then_list_round_trips() {
        let sync_state = SyncState::open_in_memory().unwrap();
        record(&sync_state, sample("op-1"));
        let markers = list(&sync_state);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].operation_id, "op-1");
    }

    #[test]
    fn recording_the_same_operation_id_twice_replaces_rather_than_duplicates() {
        let sync_state = SyncState::open_in_memory().unwrap();
        record(&sync_state, sample("op-1"));
        let mut updated = sample("op-1");
        updated.local_path = "/tmp/elsewhere".to_string();
        record(&sync_state, updated);

        let markers = list(&sync_state);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].local_path, "/tmp/elsewhere");
    }

    #[test]
    fn remove_drops_only_the_named_marker() {
        let sync_state = SyncState::open_in_memory().unwrap();
        record(&sync_state, sample("op-1"));
        record(&sync_state, {
            let mut m = sample("op-2");
            m.group_id = "group-2".to_string();
            m
        });

        remove(&sync_state, "op-1");

        let markers = list(&sync_state);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].operation_id, "op-2");
    }

    #[test]
    fn remove_on_an_unknown_operation_id_is_a_no_op() {
        let sync_state = SyncState::open_in_memory().unwrap();
        record(&sync_state, sample("op-1"));

        remove(&sync_state, "not-a-real-operation-id");

        assert_eq!(list(&sync_state).len(), 1);
    }

    #[test]
    fn list_on_a_fresh_database_is_empty_not_an_error() {
        let sync_state = SyncState::open_in_memory().unwrap();
        assert!(list(&sync_state).is_empty());
    }

    // --- reconcile, against a fake coordination client ---------------------

    /// A [`CoordinationEnrollment`] whose activate calls always return a
    /// fixed, test-chosen [`ActivateOutcome`] and whose cancel calls always
    /// succeed, recording which operation ids they were called for so a
    /// test can assert on the "link absent" branch's cancel-then-remove
    /// behavior.
    struct FakeCoordinationEnrollment {
        activate_outcome: ActivateOutcome,
        cancelled_operation_ids: Mutex<Vec<String>>,
    }

    impl FakeCoordinationEnrollment {
        fn always(activate_outcome: ActivateOutcome) -> Self {
            Self { activate_outcome, cancelled_operation_ids: Mutex::new(Vec::new()) }
        }
    }

    impl CoordinationEnrollment for FakeCoordinationEnrollment {
        async fn activate_create(&self, _group_id: &str, _operation_id: &str) -> ActivateOutcome {
            self.activate_outcome
        }
        async fn activate_join(
            &self,
            _group_id: &str,
            _operation_id: &str,
            _device_id: &str,
        ) -> ActivateOutcome {
            self.activate_outcome
        }
        async fn cancel_create(&self, _group_id: &str, operation_id: &str) -> bool {
            self.cancelled_operation_ids.lock().unwrap().push(operation_id.to_string());
            true
        }
        async fn cancel_join(&self, _group_id: &str, operation_id: &str, _device_id: &str) -> bool {
            self.cancelled_operation_ids.lock().unwrap().push(operation_id.to_string());
            true
        }
    }

    fn test_state_with_link(local_path: &str, group_id: &str) -> Arc<DaemonState> {
        use yadorilink_local_storage::FsBlockStore;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        sync_state.add_link(local_path, group_id).unwrap();
        DaemonState::new("device-a".into(), sync_state, store)
    }

    /// `Success`: the marker is dropped and the link is left exactly as it
    /// was (not orphaned).
    #[tokio::test]
    async fn reconcile_on_success_removes_the_marker_and_leaves_the_link_active() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::Success);

        reconcile_with(&state, &client).await;

        assert!(list(&state.sync_state).is_empty());
        assert!(!state.sync_state.list_links().unwrap()[0].orphaned);
    }

    /// `AlreadyActive`: activate is idempotent by `operation_id`, so this is
    /// treated exactly like `Success` -- the marker is dropped, the link
    /// stays active.
    #[tokio::test]
    async fn reconcile_on_already_active_removes_the_marker_and_leaves_the_link_active() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::AlreadyActive);

        reconcile_with(&state, &client).await;

        assert!(list(&state.sync_state).is_empty());
        assert!(!state.sync_state.list_links().unwrap()[0].orphaned);
    }

    /// `Deleted`: the coordination-side row is permanently gone -- the
    /// marker is dropped AND the local link is marked orphaned, but its
    /// entry stays in `list_links` (never deleted, never touches disk).
    #[tokio::test]
    async fn reconcile_on_deleted_removes_the_marker_and_orphans_the_link() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::Deleted);

        reconcile_with(&state, &client).await;

        assert!(list(&state.sync_state).is_empty());
        let links = state.sync_state.list_links().unwrap();
        assert_eq!(links.len(), 1, "the link itself must never be deleted, only marked orphaned");
        assert!(links[0].orphaned);
    }

    /// `TransientFailure`: nothing is final yet -- the marker survives for
    /// the next sweep, and the link is untouched.
    #[tokio::test]
    async fn reconcile_on_transient_failure_leaves_the_marker_in_place() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::TransientFailure);

        reconcile_with(&state, &client).await;

        let markers = list(&state.sync_state);
        assert_eq!(markers.len(), 1, "a transient failure must not drop the marker");
        assert_eq!(markers[0].operation_id, "op-1");
        assert!(!state.sync_state.list_links().unwrap()[0].orphaned);
    }

    // --- activate-response-loss fault injection (fix/activate-response-loss) --
    //
    // The bug this closes: a device's CLI create/join call used to roll back
    // its just-committed local link (and the pending-enrollment marker
    // guarding it) on ANY activate failure, including one where the
    // coordination plane's response was merely lost (a transport error,
    // timeout, or 5xx) after the plane had ALREADY committed the
    // activation. That reintroduced exactly the phantom-full-replica hazard
    // (a coordination-plane edge with no local copy behind it) this whole
    // Pending -> Active protocol exists to prevent -- except inverted: now
    // the LOCAL link/marker were the ones wrongly deleted while the
    // coordination-plane side stayed Active. The tests below cover the
    // daemon-side half of the fix: given that the local link and marker
    // survive an ambiguous activate response (never rolled back -- see the
    // CLI's own `share.rs` unit tests for that half), `reconcile` correctly
    // resolves the marker once it can reach the coordination plane again,
    // and never gives up retrying just because a run of attempts so far
    // came back ambiguous.

    /// The exact scenario this fix addresses: the CLI's own activate call
    /// got back an ambiguous (lost-response) outcome, so -- per the fix --
    /// it left the local link and its pending-enrollment marker retained
    /// rather than rolling them back. This test starts from that retained
    /// state directly (the CLI-side half already proved it is what gets left
    /// behind) and simulates the coordination plane, once reachable again,
    /// confirming that the ORIGINAL activate call had in fact already
    /// committed (`AlreadyActive`) -- reconcile must finalize the marker away
    /// and leave the link active, not orphaned, exactly as if nothing had
    /// ever gone wrong.
    #[tokio::test]
    async fn activate_commits_but_response_is_lost_then_reconcile_finalizes_to_active() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));

        // Before reconcile ever runs: the link and its marker are both still
        // present -- the lost-response outcome must never have deleted
        // either of them client-side.
        assert_eq!(list(&state.sync_state).len(), 1);
        assert!(!state.sync_state.list_links().unwrap()[0].orphaned);

        // The coordination plane, once reachable again, confirms the
        // ORIGINAL activate call actually landed.
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::AlreadyActive);
        reconcile_with(&state, &client).await;

        assert!(list(&state.sync_state).is_empty(), "the marker must be finalized away");
        let links = state.sync_state.list_links().unwrap();
        assert_eq!(links.len(), 1, "the local link must never have been removed");
        assert!(
            !links[0].orphaned,
            "a confirmed activation must leave the link active, not orphaned"
        );
    }

    /// An explicit, confirmed "this operation was never activated" (a 404
    /// from the coordination plane, surfaced here as `Deleted`) is the ONLY
    /// outcome that rolls anything back -- covered already by
    /// `reconcile_on_deleted_removes_the_marker_and_orphans_the_link` above.
    /// This test just pins the contrast the fix hinges on: an ambiguous
    /// outcome and a confirmed-deleted outcome must never be treated the
    /// same way twice in a row for the same marker -- a transient blip
    /// followed by a genuine not-found still orphans correctly, and does not
    /// get stuck retrying something the plane has now definitively answered.
    #[tokio::test]
    async fn transient_failure_followed_by_a_confirmed_deleted_still_rolls_back_correctly() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));

        let transient = FakeCoordinationEnrollment::always(ActivateOutcome::TransientFailure);
        reconcile_with(&state, &transient).await;
        assert_eq!(list(&state.sync_state).len(), 1, "still ambiguous -- marker must survive");
        assert!(!state.sync_state.list_links().unwrap()[0].orphaned);

        let deleted = FakeCoordinationEnrollment::always(ActivateOutcome::Deleted);
        reconcile_with(&state, &deleted).await;
        assert!(list(&state.sync_state).is_empty(), "now confirmed gone -- marker must be dropped");
        assert!(state.sync_state.list_links().unwrap()[0].orphaned);
    }

    /// A coordination plane that stays unreachable across many consecutive
    /// sweeps must never cause the marker (or its link) to be dropped or
    /// rolled back on attempt count alone -- only a confirmed `Deleted` does
    /// that. The retry keeps running past
    /// `TRANSIENT_ESCALATION_THRESHOLD` sweeps; escalation only changes how
    /// loudly it's logged (see `reconcile_with`'s `TransientFailure` arm),
    /// which this test can't observe directly, so it asserts the underlying
    /// counter `reconcile_with` drives crossed the threshold instead.
    #[tokio::test]
    async fn bounded_retry_never_drops_the_marker_but_crosses_the_escalation_threshold() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        record(&state.sync_state, sample("op-1"));
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::TransientFailure);

        for _ in 0..(TRANSIENT_ESCALATION_THRESHOLD + 3) {
            reconcile_with(&state, &client).await;
            // Never dropped, never orphaned, on any single sweep.
            assert_eq!(list(&state.sync_state).len(), 1);
            assert!(!state.sync_state.list_links().unwrap()[0].orphaned);
        }

        assert!(
            state.pending_enrollment_transient_attempts_for("op-1")
                >= TRANSIENT_ESCALATION_THRESHOLD,
            "the attempt counter reconcile_with drives must have crossed the escalation threshold \
             after this many consecutive ambiguous sweeps"
        );

        // Once the plane is reachable again and confirms the activation, the
        // marker resolves normally and its attempt counter is cleared, not
        // left to pollute a future, unrelated operation id.
        let recovered = FakeCoordinationEnrollment::always(ActivateOutcome::AlreadyActive);
        reconcile_with(&state, &recovered).await;
        assert!(list(&state.sync_state).is_empty());
        assert_eq!(state.pending_enrollment_transient_attempts_for("op-1"), 0);
    }

    /// A marker must resolve against the link whose `local_path` it names,
    /// never an unrelated link that merely shares its `group_id` -- otherwise a
    /// `Deleted` outcome could orphan the wrong folder.
    ///
    /// This test used to say two live links "can (in principle -- nothing in the
    /// schema forbids it) share a `group_id`". That is no longer true and was
    /// never safe: the schema now refuses a second live link for a group,
    /// because the file index is group-scoped while every scan is root-scoped
    /// and authoritative, so two live roots tombstone each other's files on
    /// every device. The state is forged here rather than built through
    /// `add_link` (which now refuses it) because it remains REACHABLE on a
    /// database written before that rule existed -- and matching a marker to the
    /// right folder is exactly what must keep working while a user recovers from
    /// it.
    #[tokio::test]
    async fn reconcile_matches_the_marker_to_its_own_local_path_not_just_its_group_id() {
        let state = test_state_with_link("/tmp/photos", "group-1");
        // A second, unrelated link that happens to share "group-1".
        state.sync_state.force_second_live_link_for_test("/tmp/unrelated", "group-1").unwrap();
        let mut marker = sample("op-1");
        marker.local_path = "/tmp/photos".to_string();
        record(&state.sync_state, marker);
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::Deleted);

        reconcile_with(&state, &client).await;

        let links = state.sync_state.list_links().unwrap();
        let photos = links.iter().find(|l| l.local_path == "/tmp/photos").unwrap();
        let unrelated = links.iter().find(|l| l.local_path == "/tmp/unrelated").unwrap();
        assert!(photos.orphaned, "the marker's own local_path must be the one orphaned");
        assert!(
            !unrelated.orphaned,
            "an unrelated link that merely shares the same group_id must be untouched"
        );
    }

    /// A marker whose local link is absent (never landed, or was already
    /// removed) has nothing left to activate -- `reconcile_with` cancels the
    /// still-Pending coordination-side row instead and drops the marker,
    /// without ever calling activate at all.
    #[tokio::test]
    async fn reconcile_with_no_matching_local_link_cancels_and_removes_the_marker() {
        let store_dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        record(&state.sync_state, sample("op-1"));
        // `activate_outcome` is irrelevant here -- with no matching link,
        // `reconcile_with` must take the cancel path and never call activate.
        let client = FakeCoordinationEnrollment::always(ActivateOutcome::Success);

        reconcile_with(&state, &client).await;

        assert!(list(&state.sync_state).is_empty());
        assert_eq!(client.cancelled_operation_ids.lock().unwrap().as_slice(), ["op-1"]);
    }
}
