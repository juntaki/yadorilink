//! `RecoverySnapshotReader` answers "what local evidence exists for one
//! `(domain, operation_id)` recovery key, all read from a SINGLE consistent
//! point in time" -- genuinely cross-cluster, spanning `links`,
//! `pending_enrollments`, `enrollment_operations`, `membership_operations`,
//! `durability_unknown_latches`, and `role_loss_operations` depending on the
//! key's domain. Not a single-table repository, and not an atomic WRITE
//! transaction either (this type never writes) -- it holds a plain
//! `Arc<SyncDatabase>`, same shape as every other repository, but exists
//! purely for its own consistent-read-snapshot reason: reading each table
//! independently through the owning repository (`LinkRepository::
//! link_gate_for_group`, `EnrollmentRepository::get_enrollment_operation`,
//! etc.) would check out a SEPARATE pooled connection per call, and a
//! reconciler running concurrently on another connection could mutate a link
//! or marker between two such independent reads -- producing a snapshot that
//! describes a combination that never actually coexisted. `Deferred` fixes
//! the SQLite read snapshot at the first statement executed inside the
//! transaction and keeps it fixed (under WAL) regardless of what other
//! connections commit while this transaction is still open.
//!
//! Relocated from `yadorilink-sync-core::repository::recovery_snapshot`
//! (Phase 7D-10): `ReplicaCoordinator` already held its own field of this
//! type (`replica_coordinator.rs`, since Phase 7D-10.2), so this move is
//! purely the type definition catching up to an accessor that already
//! existed and worked -- `yadorilink-sync-core::index::SyncState`'s own
//! copy of this type, and its `recovery_snapshot_reader()` accessor, were
//! never a real production caller (confirmed via a workspace-wide grep):
//! only `SyncState`'s own test suite exercised them, which moved here
//! alongside the production code (see this module's own `tests` submodule).

use std::sync::Arc;

use crate::recovery::{
    LocalObservation, LocalRecoveryEvidence, RecoveryDomain, RecoveryLocalSnapshot,
    RecoveryOperationKey,
};
use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::enrollment::{row_to_enrollment_operation, row_to_pending_enrollment};
use yadorilink_sync_sqlite::membership_operation::row_to_membership_operation;
use yadorilink_sync_sqlite::role_loss_operation::row_to_role_loss_operation_strict;

pub struct RecoverySnapshotReader {
    database: Arc<SyncDatabase>,
}

impl RecoverySnapshotReader {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Reads every piece of local recovery evidence for one
    /// `(domain, operation_id)` from a SINGLE SQLite read transaction --
    /// never by calling `get_enrollment_operation`/`list_links`/
    /// `get_membership_operation`/etc. independently. Read-only: never
    /// writes, never calls the coordination plane, never advances `attempts`
    /// or any other counter. See [`RecoveryLocalSnapshot`]'s own doc comment
    /// for what this distinguishes: an absent operation row
    /// (`OperationNotFound`), a present-but-corrupt one
    /// (`InvalidOperation`), and a genuine database read failure (`Err`) are
    /// three different things that must never be collapsed into each other.
    pub fn recovery_local_snapshot(
        &self,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        // This is a genuinely read-only, multi-statement snapshot across
        // several tables -- `SyncDatabase::read` only checks out a plain
        // `&Connection` (no owned transaction), so a `Deferred` transaction
        // is opened directly on it via `unchecked_transaction` (the rusqlite
        // API for exactly this: a transaction built from a shared `&Connection`
        // reference rather than requiring `&mut`). It fixes the SQLite read
        // snapshot at its first statement and holds it for every domain
        // dispatch below, without taking `SyncDatabase`'s writer_gate --
        // unlike `write`/`write_immediate`, nothing here ever mutates state.
        self.database.read::<_, SyncError>(|conn| {
            let tx = conn.unchecked_transaction()?;
            let result = match key.domain {
                RecoveryDomain::Enrollment => Self::snapshot_enrollment_in_tx(&tx, key)?,
                RecoveryDomain::Membership => Self::snapshot_membership_in_tx(&tx, key)?,
                RecoveryDomain::RoleLoss => Self::snapshot_role_loss_in_tx(&tx, key)?,
            };
            tx.commit()?;
            Ok(result)
        })
    }

    fn snapshot_enrollment_in_tx(
        tx: &rusqlite::Transaction<'_>,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        let decoded = {
            let mut stmt = tx.prepare(
                "SELECT operation_id, kind, group_id, group_name, device_id, local_path, \
                        storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix \
                 FROM enrollment_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query([key.operation_id.as_str()])?;
            match rows.next()? {
                None => None,
                Some(row) => {
                    let raw_state: Option<String> = row.get(7).ok();
                    Some((row_to_enrollment_operation(row), raw_state))
                }
            }
        };

        let operation = match decoded {
            None => {
                return Ok(RecoveryLocalSnapshot::OperationNotFound { key: key.clone() });
            }
            Some((Err(error), raw_state)) => {
                return Ok(RecoveryLocalSnapshot::InvalidOperation {
                    key: key.clone(),
                    raw_state,
                    detail: error.to_string(),
                });
            }
            Some((Ok(operation), _)) => operation,
        };

        // Always search by `local_path`, regardless of whether `group_id`
        // has resolved yet -- C2-A reports whatever local evidence exists,
        // it does not decide what's expected for the operation's own
        // state. A `Create` row still `PreparePending` (no `group_id` yet)
        // can still have a live link sitting at its own `local_path` (e.g.
        // this path already belongs to a different group); skipping the
        // lookup would hide that link as `ConfirmedAbsent` instead of
        // surfacing it for Phase 2.1-C2-B to qualify.
        let link = Self::observe_link_by_path(tx, &operation.local_path)?;
        let pending_marker = Self::observe_pending_enrollment(tx, &operation.operation_id)?;

        Ok(RecoveryLocalSnapshot::Found(Box::new(LocalRecoveryEvidence::Enrollment(
            crate::recovery::EnrollmentLocalEvidence { operation, link, pending_marker },
        ))))
    }

    fn snapshot_membership_in_tx(
        tx: &rusqlite::Transaction<'_>,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        let decoded = {
            let mut stmt = tx.prepare(
                "SELECT operation_id, action, commit_mode, removed_device_id, group_ids, \
                        target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                        last_error, created_at_unix, updated_at_unix \
                 FROM membership_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query([key.operation_id.as_str()])?;
            match rows.next()? {
                None => None,
                Some(row) => {
                    let raw_state: Option<String> = row.get(7).ok();
                    Some((row_to_membership_operation(row), raw_state))
                }
            }
        };

        let operation = match decoded {
            None => {
                return Ok(RecoveryLocalSnapshot::OperationNotFound { key: key.clone() });
            }
            Some((Err(error), raw_state)) => {
                return Ok(RecoveryLocalSnapshot::InvalidOperation {
                    key: key.clone(),
                    raw_state,
                    detail: error.to_string(),
                });
            }
            Some((Ok(operation), _)) => operation,
        };

        // The union of both group-id sources this operation could latch --
        // sorted and deduplicated so the result never depends on row order
        // or which of the two lists a group happened to come from.
        let mut candidate_group_ids: Vec<String> =
            operation.group_ids.iter().chain(operation.latch_group_ids.iter()).cloned().collect();
        candidate_group_ids.sort();
        candidate_group_ids.dedup();

        let present_durability_latches = if candidate_group_ids.is_empty() {
            Vec::new()
        } else {
            let placeholders =
                candidate_group_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let sql = format!(
                "SELECT group_id FROM durability_unknown_latches WHERE group_id IN ({placeholders}) \
                 ORDER BY group_id"
            );
            let mut stmt = tx.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(candidate_group_ids.iter()), |r| {
                    r.get::<_, String>(0)
                })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        Ok(RecoveryLocalSnapshot::Found(Box::new(LocalRecoveryEvidence::Membership(
            crate::recovery::MembershipLocalEvidence { operation, present_durability_latches },
        ))))
    }

    fn snapshot_role_loss_in_tx(
        tx: &rusqlite::Transaction<'_>,
        key: &RecoveryOperationKey,
    ) -> Result<RecoveryLocalSnapshot, SyncError> {
        let decoded = {
            let mut stmt = tx.prepare(
                "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                        worker_membership_generation, action, state, local_path, attempts, \
                        created_at_unix, updated_at_unix \
                 FROM role_loss_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query([key.operation_id.as_str()])?;
            match rows.next()? {
                None => None,
                Some(row) => {
                    let raw_state: Option<String> = row.get(7).ok();
                    Some((row_to_role_loss_operation_strict(row), raw_state))
                }
            }
        };

        let operation = match decoded {
            None => {
                return Ok(RecoveryLocalSnapshot::OperationNotFound { key: key.clone() });
            }
            Some((Err(error), raw_state)) => {
                return Ok(RecoveryLocalSnapshot::InvalidOperation {
                    key: key.clone(),
                    raw_state,
                    detail: error.to_string(),
                });
            }
            Some((Ok(operation), _)) => operation,
        };

        let link = match operation.local_path.as_deref() {
            Some(local_path) => Self::observe_link_by_path(tx, local_path)?,
            // No specific path recorded -- fall back to every live link for
            // this group; more than one candidate is `Ambiguous`, never
            // resolved by picking one arbitrarily.
            None => Self::observe_link_by_group(tx, &operation.group_id)?,
        };

        Ok(RecoveryLocalSnapshot::Found(Box::new(LocalRecoveryEvidence::RoleLoss(
            crate::recovery::RoleLossLocalEvidence { operation, link },
        ))))
    }

    /// Reads the `links` row at exactly this `local_path`, regardless of
    /// which `group_id` it actually names -- deliberately NOT filtered by
    /// the operation's own expected `group_id`. Filtering by both would
    /// report `ConfirmedAbsent` for a link that genuinely exists at this
    /// path but under a DIFFERENT group, hiding exactly the
    /// identity-conflicting link a diagnosis classifier (Phase 2.1-C2-B)
    /// most needs to see -- mirrors how `observe_pending_enrollment`
    /// deliberately keeps a marker whose other fields disagree with the
    /// operation instead of filtering it out.
    fn observe_link_by_path(
        tx: &rusqlite::Transaction<'_>,
        local_path: &str,
    ) -> Result<LocalObservation<crate::recovery::LocalLinkEvidence>, SyncError> {
        let mut stmt = tx.prepare(
            "SELECT local_path, group_id, paused, materialization_policy, orphaned, root_token \
             FROM links WHERE local_path = ?1",
        )?;
        let rows = stmt.query(rusqlite::params![local_path])?;
        Self::collect_local_link_evidence(rows)
    }

    fn observe_link_by_group(
        tx: &rusqlite::Transaction<'_>,
        group_id: &str,
    ) -> Result<LocalObservation<crate::recovery::LocalLinkEvidence>, SyncError> {
        let mut stmt = tx.prepare(
            "SELECT local_path, group_id, paused, materialization_policy, orphaned, root_token \
             FROM links WHERE group_id = ?1 ORDER BY local_path",
        )?;
        let rows = stmt.query(rusqlite::params![group_id])?;
        Self::collect_local_link_evidence(rows)
    }

    /// Steps through `rows` itself with `rusqlite::Rows::next`, not
    /// `Statement::query_map(...).collect()` -- the two error sources that
    /// call chain conflates must stay distinguishable. Advancing the
    /// cursor (`rows.next()?`) can fail for reasons that mean the DATABASE
    /// itself cannot be trusted right now (I/O, corruption, a broken
    /// connection) -- that must propagate as `Err(SyncError)`, the same as
    /// every other genuine read failure. Decoding a row that WAS
    /// successfully read (`row_to_local_link_evidence`) can fail for a
    /// completely different reason -- this one row's own shape is bad (e.g.
    /// an unrecognized `materialization_policy`) -- which is a
    /// `LocalObservation::Invalid`, not a database-wide failure. Folding
    /// both into one `Result` (as an earlier version of this function's
    /// `query_map(...).collect()` did) reported a real SQLite execution
    /// error the same way as a single corrupt row, which would make Phase
    /// 2.1-C2-B trust the REST of a database it cannot actually read.
    fn collect_local_link_evidence(
        mut rows: rusqlite::Rows<'_>,
    ) -> Result<LocalObservation<crate::recovery::LocalLinkEvidence>, SyncError> {
        let mut decoded = Vec::new();
        while let Some(row) = rows.next()? {
            match row_to_local_link_evidence(row) {
                Ok(link) => decoded.push(link),
                Err(error) => {
                    return Ok(LocalObservation::Invalid { detail: error.to_string() });
                }
            }
        }
        Ok(match decoded.len() {
            0 => LocalObservation::ConfirmedAbsent,
            1 => LocalObservation::Found(decoded.into_iter().next().expect("length checked above")),
            n => LocalObservation::Ambiguous { detail: format!("{n} candidate links") },
        })
    }

    fn observe_pending_enrollment(
        tx: &rusqlite::Transaction<'_>,
        operation_id: &str,
    ) -> Result<LocalObservation<crate::recovery::PendingEnrollmentEvidence>, SyncError> {
        let mut stmt = tx.prepare(
            "SELECT operation_id, kind, group_id, device_id, local_path \
             FROM pending_enrollments WHERE operation_id = ?1",
        )?;
        let mut rows = stmt.query([operation_id])?;
        Ok(match rows.next()? {
            None => LocalObservation::ConfirmedAbsent,
            Some(row) => match row_to_pending_enrollment(row) {
                Ok(marker) => LocalObservation::Found(crate::recovery::PendingEnrollmentEvidence {
                    operation_id: marker.operation_id,
                    kind: marker.kind,
                    group_id: marker.group_id,
                    device_id: marker.device_id,
                    local_path: marker.local_path,
                }),
                Err(error) => LocalObservation::Invalid { detail: error.to_string() },
            },
        })
    }
}

/// Strict decode for [`crate::recovery::LocalLinkEvidence`] -- unlike
/// `ReplicaCoordinator::link_repository().list_links()`'s
/// `MaterializationPolicy::from_db_str`, this never panics on an
/// unrecognized `materialization_policy` value: a recovery snapshot must
/// surface a corrupt link row as [`crate::recovery::LocalObservation::Invalid`],
/// never crash the daemon process trying to diagnose it.
pub(crate) fn row_to_local_link_evidence(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::recovery::LocalLinkEvidence> {
    let local_path: String = r.get(0)?;
    let group_id: String = r.get(1)?;
    let paused: i64 = r.get(2)?;
    let policy_raw: String = r.get(3)?;
    let orphaned: i64 = r.get(4)?;
    let root_token: Option<String> = r.get(5)?;
    let materialization_policy = match policy_raw.as_str() {
        "eager" => MaterializationPolicy::Eager,
        "ondemand" => MaterializationPolicy::OnDemand,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown materialization policy: {other}"),
                )),
            ));
        }
    };
    Ok(crate::recovery::LocalLinkEvidence {
        group_id,
        local_path,
        materialization_policy,
        paused: paused != 0,
        orphaned: orphaned != 0,
        root_token_present: root_token.is_some(),
    })
}

#[cfg(test)]
mod tests {

    use crate::recovery::tests::{
        insert_valid_enrollment_op, insert_valid_membership_op, insert_valid_role_loss_op,
    };
    use crate::replica_coordinator::ReplicaCoordinator;
    use yadorilink_replica_domain::session_state::{
        EnrollmentKind, EnrollmentOperation, EnrollmentOperationState, MembershipCommitMode,
        MembershipDurabilityScope, MembershipOperationAction, MembershipOperationState,
        PendingEnrollment, RoleLossAction, RoleLossOperationParams,
    };

    #[test]
    fn recovery_local_snapshot_enrollment_found_with_exact_link_and_marker() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::ActivationPending,
                last_error: None,
                attempts: 1,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();
        state
            .enrollment_repository()
            .add_link_with_pending_enrollment(
                "/home/alice/Photos",
                "group-1",
                &PendingEnrollment {
                    operation_id: "op-1".to_string(),
                    kind: EnrollmentKind::Create,
                    group_id: "group-1".to_string(),
                    device_id: "device-a".to_string(),
                    local_path: "/home/alice/Photos".to_string(),
                },
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) = snapshot else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        assert_eq!(evidence.operation.operation_id, "op-1");
        assert!(matches!(evidence.link, crate::recovery::LocalObservation::Found(_)));
        assert!(matches!(evidence.pending_marker, crate::recovery::LocalObservation::Found(_)));
    }

    /// `LocalRecoveryEvidence::summary()` must produce exactly the same
    /// `RecoveryOperationSummary` `recovery::inventory()` does for the SAME
    /// underlying row -- both now call the identical per-domain helper, so
    /// this pins that they can never independently drift.
    #[test]
    fn recovery_local_snapshot_summary_matches_inventory_summary_for_enrollment() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let from_snapshot = evidence.summary();

        let inv = crate::recovery::inventory(&state).unwrap();
        let from_inventory =
            inv.valid.into_iter().find(|op| op.operation_id == "op-1").expect("row in inventory");

        assert_eq!(from_snapshot, from_inventory);
    }

    #[test]
    fn recovery_local_snapshot_summary_matches_inventory_summary_for_membership() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_membership_op(&state, "op-1");

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Membership,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let from_snapshot = evidence.summary();

        let inv = crate::recovery::inventory(&state).unwrap();
        let from_inventory =
            inv.valid.into_iter().find(|op| op.operation_id == "op-1").expect("row in inventory");

        assert_eq!(from_snapshot, from_inventory);
    }

    #[test]
    fn recovery_local_snapshot_summary_matches_inventory_summary_for_role_loss() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_role_loss_op(&state, "op-1");

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::RoleLoss,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let from_snapshot = evidence.summary();

        let inv = crate::recovery::inventory(&state).unwrap();
        let from_inventory =
            inv.valid.into_iter().find(|op| op.operation_id == "op-1").expect("row in inventory");

        assert_eq!(from_snapshot, from_inventory);
    }

    #[test]
    fn recovery_local_snapshot_membership_reports_only_actually_present_latches() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .membership_operation_repository()
            .try_insert_membership_operation(
                "op-1",
                MembershipOperationAction::RemoveDevice,
                MembershipCommitMode::HandoffRemoveDevice,
                "device-b",
                &["g1".to_string(), "g2".to_string()],
                &["device-x".to_string(), "device-y".to_string()],
                &[Some("lease-1".to_string()), Some("lease-2".to_string())],
                MembershipOperationState::Prepared,
                MembershipDurabilityScope::Known,
                &["g2".to_string(), "g3".to_string()],
                None,
                1,
            )
            .unwrap();
        state.role_loss_operation_repository().latch_group_durability_unknown("g2").unwrap();
        state.role_loss_operation_repository().latch_group_durability_unknown("g3").unwrap();
        // g1 is a candidate (it's in operation.group_ids) but deliberately
        // left unlatched -- must NOT appear in present_durability_latches.

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Membership,
            operation_id: "op-1".to_string(),
        };
        let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) = snapshot else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Membership(evidence) = *evidence else {
            panic!("expected Membership evidence");
        };
        assert_eq!(evidence.present_durability_latches, vec!["g2".to_string(), "g3".to_string()]);
    }

    #[test]
    fn recovery_local_snapshot_role_loss_found_with_exact_link() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
        state
            .role_loss_operation_repository()
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-c",
                    target_device_id: "device-d",
                    lease_id: None,
                    action: RoleLossAction::Demote,
                    local_path: Some("/home/alice/Photos"),
                    now_unix: 1,
                },
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::RoleLoss,
            operation_id: "op-1".to_string(),
        };
        let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) = snapshot else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::RoleLoss(evidence) = *evidence else {
            panic!("expected RoleLoss evidence");
        };
        assert!(matches!(evidence.link, crate::recovery::LocalObservation::Found(_)));
    }

    #[test]
    fn recovery_local_snapshot_reports_operation_not_found() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "does-not-exist".to_string(),
        };
        let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
        assert!(matches!(
            snapshot,
            crate::recovery::RecoveryLocalSnapshot::OperationNotFound { .. }
        ));
    }

    #[test]
    fn recovery_local_snapshot_reports_invalid_operation_for_a_malformed_row() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO enrollment_operations \
                    (operation_id, kind, group_id, group_name, device_id, local_path, \
                     storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix) \
                 VALUES ('op-malformed', 'create', 'group-1', NULL, 'device-a', '/tmp/broken', \
                    'eager', 'from-the-future', NULL, 0, 1, 1)",
                [],
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-malformed".to_string(),
        };
        let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
        let crate::recovery::RecoveryLocalSnapshot::InvalidOperation { raw_state, .. } = snapshot
        else {
            panic!("expected InvalidOperation, got {snapshot:?}");
        };
        assert_eq!(raw_state.as_deref(), Some("from-the-future"));
    }

    /// `EnrollmentOperation::storage_mode` on a Create row records the
    /// CALLER's own requested local materialization mode
    /// (`CreateAndLinkCommand::on_demand`, see
    /// `EnrollmentService::create_and_link`) -- a completely different
    /// concept from the remote creator edge's own always-"eager" wire
    /// construction. A Create row legitimately requesting on-demand local
    /// materialization must decode as `Found`, never `InvalidOperation`.
    #[test]
    fn recovery_local_snapshot_accepts_an_on_demand_create_row_as_valid() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: None,
                group_name: Some("photos".to_string()),
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "on-demand".to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
        assert!(
            matches!(snapshot, crate::recovery::RecoveryLocalSnapshot::Found(_)),
            "expected Found, got {snapshot:?}"
        );
    }

    #[test]
    fn recovery_local_snapshot_propagates_a_genuine_db_read_failure() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute_batch("DROP TABLE enrollment_operations")
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let result = state.recovery_snapshot_reader().recovery_local_snapshot(&key);
        assert!(
            result.is_err(),
            "a genuine DB read failure must propagate as an error, never as an empty/absent result"
        );
    }

    #[test]
    fn recovery_local_snapshot_resolves_by_domain_even_when_the_same_id_exists_in_all_three_tables()
    {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-shared");
        insert_valid_membership_op(&state, "op-shared");
        insert_valid_role_loss_op(&state, "op-shared");

        let enrollment_key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-shared".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&enrollment_key).unwrap()
        else {
            panic!("expected Found for enrollment domain");
        };
        assert!(matches!(*evidence, crate::recovery::LocalRecoveryEvidence::Enrollment(_)));

        let membership_key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Membership,
            operation_id: "op-shared".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&membership_key).unwrap()
        else {
            panic!("expected Found for membership domain");
        };
        assert!(matches!(*evidence, crate::recovery::LocalRecoveryEvidence::Membership(_)));

        let role_loss_key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::RoleLoss,
            operation_id: "op-shared".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&role_loss_key).unwrap()
        else {
            panic!("expected Found for role-loss domain");
        };
        assert!(matches!(*evidence, crate::recovery::LocalRecoveryEvidence::RoleLoss(_)));
    }

    #[test]
    fn recovery_local_snapshot_keeps_a_marker_whose_operation_id_matches_but_other_fields_dont() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::ActivationPending,
                last_error: None,
                attempts: 1,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();
        // A marker under the SAME operation_id but naming a DIFFERENT
        // group/device/path -- C2-A must not filter this out or treat it
        // specially; spotting the mismatch is Phase 2.1-C2-B's own
        // identity-qualification job, not this snapshot's.
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO pending_enrollments \
                    (operation_id, kind, group_id, device_id, local_path) \
                 VALUES ('op-1', 'create', 'group-DIFFERENT', 'device-DIFFERENT', '/tmp/other')",
                [],
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        let crate::recovery::LocalObservation::Found(marker) = evidence.pending_marker else {
            panic!("expected the mismatched marker to still be Found, not filtered");
        };
        assert_eq!(marker.group_id, "group-DIFFERENT");
    }

    #[test]
    fn recovery_local_snapshot_surfaces_a_link_whose_group_id_conflicts_with_the_operation() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        // A link genuinely exists at this operation's local_path, but under
        // a DIFFERENT group_id than the operation itself names -- this must
        // be surfaced as Found (with its own, conflicting group_id), never
        // filtered into ConfirmedAbsent. Hiding it would hide exactly the
        // identity conflict a diagnosis classifier (Phase 2.1-C2-B) most
        // needs to see.
        state.link_repository().add_link("/home/alice/Photos", "group-CONFLICTING").unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::ActivationPending,
                last_error: None,
                attempts: 1,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        let crate::recovery::LocalObservation::Found(link) = evidence.link else {
            panic!("expected the conflicting link to still be Found, not filtered");
        };
        assert_eq!(link.group_id, "group-CONFLICTING");
    }

    #[test]
    fn recovery_local_snapshot_role_loss_multiple_link_candidates_is_ambiguous() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        // A DB-level constraint refuses two LIVE links for the same
        // group_id (see `insert_link_row`'s own `AmbiguousLink` guard, now
        // also enforced at the SQLite layer), so real ambiguity here can
        // only arise from an orphaned row left behind at an old path
        // alongside a live link at a new one -- both still name group-1.
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO links (local_path, group_id, orphaned) \
                 VALUES ('/home/alice/Photos-old', 'group-1', 1)",
                [],
            )
            .unwrap();
        state.link_repository().add_link("/home/alice/Photos-new", "group-1").unwrap();
        state
            .role_loss_operation_repository()
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-c",
                    target_device_id: "device-d",
                    lease_id: None,
                    action: RoleLossAction::Demote,
                    local_path: None,
                    now_unix: 1,
                },
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::RoleLoss,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::RoleLoss(evidence) = *evidence else {
            panic!("expected RoleLoss evidence");
        };
        assert!(matches!(evidence.link, crate::recovery::LocalObservation::Ambiguous { .. }));
    }

    #[test]
    fn recovery_local_snapshot_reports_invalid_for_a_malformed_pending_marker() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::ActivationPending,
                last_error: None,
                attempts: 1,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO pending_enrollments \
                    (operation_id, kind, group_id, device_id, local_path) \
                 VALUES ('op-1', 'not-a-kind', 'group-1', 'device-a', '/home/alice/Photos')",
                [],
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        assert!(matches!(
            evidence.pending_marker,
            crate::recovery::LocalObservation::Invalid { .. }
        ));
    }

    #[test]
    fn recovery_local_snapshot_reports_confirmed_absent_when_no_link_or_marker_exists() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        assert!(matches!(evidence.link, crate::recovery::LocalObservation::ConfirmedAbsent));
        assert!(matches!(
            evidence.pending_marker,
            crate::recovery::LocalObservation::ConfirmedAbsent
        ));
    }

    #[test]
    fn recovery_local_snapshot_enrollment_surfaces_a_link_at_its_path_even_with_no_group_id_yet() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        // A Create row still PreparePending has no group_id yet, but its
        // own local_path might already be occupied by an EXISTING link
        // belonging to a different group entirely -- C2-A must still
        // surface it, not silently skip the lookup because group_id is
        // still None.
        state.link_repository().add_link("/data/photos", "group-existing").unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: None,
                group_name: Some("photos".to_string()),
                device_id: "device-a".to_string(),
                local_path: "/data/photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        let crate::recovery::LocalObservation::Found(link) = evidence.link else {
            panic!("expected the pre-existing link to still be Found, not skipped");
        };
        assert_eq!(link.group_id, "group-existing");
    }

    #[test]
    fn recovery_local_snapshot_enrollment_confirmed_absent_when_group_id_is_none_and_no_link_exists(
    ) {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .enrollment_repository()
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: None,
                group_name: Some("photos".to_string()),
                device_id: "device-a".to_string(),
                local_path: "/data/photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        assert!(matches!(evidence.link, crate::recovery::LocalObservation::ConfirmedAbsent));
    }

    #[test]
    fn recovery_local_snapshot_reports_invalid_for_a_malformed_link_row() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO links (local_path, group_id, materialization_policy) \
                 VALUES ('/home/alice/Photos', 'group-1', 'not-a-real-policy')",
                [],
            )
            .unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };
        let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
            panic!("expected Enrollment evidence");
        };
        assert!(matches!(evidence.link, crate::recovery::LocalObservation::Invalid { .. }));
    }

    #[test]
    fn recovery_local_snapshot_enrollment_link_lookup_propagates_a_genuine_db_read_failure() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state.database().pool_for_test().get().unwrap().execute_batch("DROP TABLE links").unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let result = state.recovery_snapshot_reader().recovery_local_snapshot(&key);
        assert!(
            result.is_err(),
            "a genuine `links` read failure must propagate as an error, never as Invalid or \
             ConfirmedAbsent"
        );
    }

    #[test]
    fn recovery_local_snapshot_role_loss_group_link_lookup_propagates_a_genuine_db_read_failure() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .role_loss_operation_repository()
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-c",
                    target_device_id: "device-d",
                    lease_id: None,
                    action: RoleLossAction::Demote,
                    local_path: None,
                    now_unix: 1,
                },
            )
            .unwrap();
        state.database().pool_for_test().get().unwrap().execute_batch("DROP TABLE links").unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::RoleLoss,
            operation_id: "op-1".to_string(),
        };
        let result = state.recovery_snapshot_reader().recovery_local_snapshot(&key);
        assert!(
            result.is_err(),
            "a genuine `links` read failure must propagate as an error, never as Invalid or \
             ConfirmedAbsent"
        );
    }

    #[test]
    fn recovery_local_snapshot_is_read_only() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state
            .enrollment_repository()
            .add_link_with_pending_enrollment(
                "/home/alice/Photos",
                "group-1",
                &PendingEnrollment {
                    operation_id: "op-1".to_string(),
                    kind: EnrollmentKind::Create,
                    group_id: "group-1".to_string(),
                    device_id: "device-a".to_string(),
                    local_path: "/home/alice/Photos".to_string(),
                },
            )
            .unwrap();

        let before_op = state.enrollment_repository().get_enrollment_operation("op-1").unwrap();
        let before_links = state.link_repository().list_links().unwrap();
        let before_markers = state.enrollment_repository().list_pending_enrollments().unwrap();

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Enrollment,
            operation_id: "op-1".to_string(),
        };
        let _ = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();

        assert_eq!(
            before_op,
            state.enrollment_repository().get_enrollment_operation("op-1").unwrap()
        );
        assert_eq!(before_links, state.link_repository().list_links().unwrap());
        assert_eq!(
            before_markers,
            state.enrollment_repository().list_pending_enrollments().unwrap()
        );
    }

    /// Proves the exact SQLite property `recovery_local_snapshot` depends on:
    /// once a `Deferred` transaction has executed its first read, later
    /// reads in the SAME transaction see the database as of that first
    /// read, even if another connection commits a write in between (WAL's
    /// readers-never-blocked-by-writers guarantee). An implementation that
    /// read the operation row and its related rows through separate pool
    /// checkouts (losing this fixed snapshot) would not have this property.
    #[test]
    fn deferred_read_transaction_snapshot_is_isolated_from_a_concurrent_commit() {
        let dir = tempfile::tempdir().unwrap();
        let state = ReplicaCoordinator::open(dir.path().join("state.db")).unwrap();
        state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();

        let mut conn_a = state.database().pool_for_test().get().unwrap();
        let tx_a =
            conn_a.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred).unwrap();
        let paused_before: i64 = tx_a
            .query_row(
                "SELECT paused FROM links WHERE local_path = ?1",
                ["/home/alice/Photos"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(paused_before, 0);

        // A DIFFERENT connection commits a write while tx_a is still open.
        let conn_b = state.database().pool_for_test().get().unwrap();
        conn_b
            .execute("UPDATE links SET paused = 1 WHERE local_path = ?1", ["/home/alice/Photos"])
            .unwrap();
        drop(conn_b);

        // tx_a must still observe the state as of its own first read.
        let paused_during: i64 = tx_a
            .query_row(
                "SELECT paused FROM links WHERE local_path = ?1",
                ["/home/alice/Photos"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            paused_during, 0,
            "a Deferred transaction must keep its snapshot fixed across a concurrent commit"
        );
        tx_a.commit().unwrap();

        // A FRESH transaction now sees the committed write.
        let paused_after: i64 = state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .query_row(
                "SELECT paused FROM links WHERE local_path = ?1",
                ["/home/alice/Photos"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(paused_after, 1);
    }

    /// The operation row's own `state`/`updated_at_unix` can stay UNCHANGED
    /// while related evidence (here: a durability latch) changes -- the
    /// revision must still change, or Phase 2.1-C2-C's stale-snapshot
    /// re-check would miss it and combine stale local evidence with fresh
    /// remote evidence.
    #[test]
    fn recovery_local_snapshot_revision_changes_when_a_related_latch_changes_but_the_operation_row_does_not(
    ) {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_membership_op(&state, "op-1");

        let key = crate::recovery::RecoveryOperationKey {
            domain: crate::recovery::RecoveryDomain::Membership,
            operation_id: "op-1".to_string(),
        };
        let crate::recovery::RecoveryLocalSnapshot::Found(before) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };

        // Latches this group -- the operation row itself is untouched.
        state.role_loss_operation_repository().latch_group_durability_unknown("group-1").unwrap();

        let crate::recovery::RecoveryLocalSnapshot::Found(after) =
            state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
        else {
            panic!("expected Found");
        };

        assert_eq!(
            before.revision().state,
            after.revision().state,
            "sanity: the operation row's own state must be unchanged by this test"
        );
        assert_ne!(
            before.revision(),
            after.revision(),
            "a related-evidence change (here: a new durability latch) must change the revision \
             even though the operation row's own state/updated_at_unix did not"
        );
    }
}
