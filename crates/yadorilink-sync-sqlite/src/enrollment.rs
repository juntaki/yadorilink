//! `EnrollmentRepository` owns the `pending_enrollments` and
//! `enrollment_operations` tables. It also owns the small set of
//! cross-table atomic methods that commit a `links` row together with a
//! `pending_enrollments`/`enrollment_operations` row in one SQLite
//! transaction -- enrollment is the "guard" concept protecting a link's
//! still-unconfirmed coordination-plane state, so it is the natural owner
//! of the atomic transition, mirroring this codebase's own precedent of an
//! orchestrating type reaching into what it protects.
//!
//! Moved here from `yadorilink-sync-core::repository::enrollment` (Phase
//! 7D-9F, ninth pass): its own value types (`EnrollmentOperation`/
//! `PendingEnrollment`/`EnrollmentOperationState`/`EnrollmentKind`/their two
//! `*Scan`/`Invalid*` siblings) already moved to
//! `yadorilink_replica_domain::session_state`, a crate this one already
//! depends on (see that module's own doc comment for why the earlier
//! "stays crate-local" reasoning for `EnrollmentKind` did not hold up); the
//! only other blocker, `scan_all_enrollment_operations`'s own use of
//! `crate::recovery::{InvalidRecoveryOperation, RecoveryDomain}`, was
//! already resolved by the eighth pass's relocation of those two types to
//! `yadorilink_replica_domain::recovery`.

use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use crate::read_inventory_operation_id;
use yadorilink_replica_domain::recovery::{
    InvalidRecoveryOperation, InventoryScanResult, RecoveryDomain,
};
use yadorilink_replica_domain::session_state::{
    EnrollmentKind, EnrollmentOperation, EnrollmentOperationScan, EnrollmentOperationState,
    InvalidEnrollmentOperation, InvalidPendingEnrollment, PendingEnrollment, PendingEnrollmentScan,
};
use yadorilink_sqlite_runtime::SyncDatabase;

pub struct EnrollmentRepository {
    database: Arc<SyncDatabase>,
}

impl EnrollmentRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Writes to `links` as well as its own enrollment tables in one
    /// transaction to preserve atomicity -- decomposing this into separate
    /// `LinkRepository`/`EnrollmentRepository` calls would reopen the exact
    /// crash window the single transaction exists to close. A future
    /// cross-repository "commit store" (Commit 14 candidate) may formalize
    /// this; it is not a design flaw to fix now.
    /// Commits a new local link together with the pending-enrollment marker
    /// that guards its still-unconfirmed coordination-plane activation, in
    /// one SQLite transaction. Ordering matters: without this, a crash
    /// between the two writes could commit a real local link with no local
    /// trace of the still-Pending coordination-side row it depends on --
    /// exactly the stranded-link case this table's crash-safe create/join
    /// protocol exists to prevent. Wrapping both in a single transaction makes that
    /// window impossible rather than merely narrow; if either write fails,
    /// neither lands, and the caller's own enroll operation can abort
    /// cleanly with no local trace at all.
    pub fn add_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollment,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT OR REPLACE INTO pending_enrollments \
                 (operation_id, kind, group_id, device_id, local_path) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    marker.operation_id,
                    marker.kind.as_db_str(),
                    marker.group_id,
                    marker.device_id,
                    marker.local_path,
                ],
            )?;
            crate::link::LinkRepository::insert_link_row(tx, local_path, group_id)?;
            Ok(())
        })
    }

    /// Writes to `links` as well as its own enrollment tables in one
    /// transaction to preserve atomicity -- decomposing this into separate
    /// `LinkRepository`/`EnrollmentRepository` calls would reopen the exact
    /// crash window the single transaction exists to close. A future
    /// cross-repository "commit store" (Commit 14 candidate) may formalize
    /// this; it is not a design flaw to fix now.
    /// Removes a link row and its pending-enrollment marker in ONE SQLite
    /// transaction — the all-or-nothing rollback for a link whose post-commit
    /// setup failed. Doing the two deletes as separate writes (as the earlier
    /// rollback path did) could remove the link but leave the marker if the
    /// second write failed, stranding a marker that names a local path with no
    /// link behind it until a later reconciliation pass. One transaction makes
    /// that half-state impossible: either both rows are gone or neither is.
    /// Mirrors [`Self::orphan_link_and_remove_pending_enrollment`]. Absent
    /// row(s) are not an error — a `DELETE` that matches nothing is a no-op,
    /// matching the idempotence every other enrollment-marker write already
    /// has.
    pub fn remove_link_and_pending_marker(
        &self,
        local_path: &str,
        operation_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
            tx.execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
            Ok(())
        })
    }

    /// Writes to `links` as well as its own enrollment tables in one
    /// transaction to preserve atomicity -- decomposing this into separate
    /// `LinkRepository`/`EnrollmentRepository` calls would reopen the exact
    /// crash window the single transaction exists to close. A future
    /// cross-repository "commit store" (Commit 14 candidate) may formalize
    /// this; it is not a design flaw to fix now.
    /// Marks a link orphaned and drops the pending-enrollment marker that
    /// diagnosed it as such, in one SQLite transaction -- the `Deleted`
    /// activation outcome's reconciliation step.
    /// Ordering matters the same way it does for
    /// `add_link_with_pending_enrollment`: doing this as two separate writes
    /// would let a crash between them drop the marker without ever having
    /// orphaned the link, leaving a phantom-active link that is never
    /// retried (its marker is gone) and never orphaned (the flag was never
    /// set) -- silently stuck forever. One transaction makes that window
    /// impossible. A link that has since been unlinked (no longer present)
    /// is not an error here: the marker is still dropped (there is nothing
    /// left to orphan), matching `reconcile`'s "link absent" branch for
    /// every other activation outcome.
    pub fn orphan_link_and_remove_pending_enrollment(
        &self,
        local_path: &str,
        operation_id: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("UPDATE links SET orphaned = 1 WHERE local_path = ?1", [local_path])?;
            tx.execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
            Ok(())
        })
    }

    /// Persists a marker for a local link that was just committed but whose
    /// coordination-plane activation has not been confirmed yet. Replaces
    /// any existing marker for the same `operation_id` (idempotent).
    /// `add_link_with_pending_enrollment` is the atomic version used when
    /// the link itself is being created in the same step; this standalone
    /// form exists for callers (and tests) that only need the marker.
    pub fn record_pending_enrollment(
        &self,
        marker: &PendingEnrollment,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO pending_enrollments \
                 (operation_id, kind, group_id, device_id, local_path) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    marker.operation_id,
                    marker.kind.as_db_str(),
                    marker.group_id,
                    marker.device_id,
                    marker.local_path,
                ],
            )?;
            Ok(())
        })
    }

    /// Removes a marker once its activation (or compensating cancel) has
    /// been confirmed. A no-op if the marker is already gone.
    pub fn remove_pending_enrollment(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM pending_enrollments WHERE operation_id = ?1",
                [operation_id],
            )?;
            Ok(())
        })
    }

    /// Every pending-enrollment marker currently outstanding. Fails the
    /// WHOLE read (not silently, not by panicking) if ANY row's `kind`
    /// column doesn't decode -- callers that need one malformed row to never
    /// block recovery of every other marker in the same sweep should use
    /// [`Self::scan_pending_enrollments`] instead.
    pub fn list_pending_enrollments(&self) -> Result<Vec<PendingEnrollment>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, kind, group_id, device_id, local_path FROM \
                 pending_enrollments",
            )?;
            let rows = stmt.query_map([], row_to_pending_enrollment)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Every pending-enrollment marker, split into rows that decoded
    /// successfully and rows that didn't -- mirrors
    /// [`Self::scan_open_enrollment_operations`] so ONE malformed marker (an
    /// unrecognized `kind` string) can never abort reconciliation for every
    /// other marker in the same sweep. Reconciliation must never attempt to
    /// activate or cancel anything on behalf of an `invalid` row -- see
    /// callers in `pending_enrollment.rs` for how a malformed marker with a
    /// matching `enrollment_operations` row instead blocks that operation
    /// (`RecoveryBlocked`) for operator attention.
    pub fn scan_pending_enrollments(&self) -> Result<PendingEnrollmentScan, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, kind, group_id, device_id, local_path FROM \
                 pending_enrollments",
            )?;
            let mut rows = stmt.query([])?;
            let mut scan = PendingEnrollmentScan::default();
            while let Some(row) = rows.next()? {
                let operation_id: String = row.get(0)?;
                match row_to_pending_enrollment(row) {
                    Ok(marker) => scan.valid.push(marker),
                    Err(error) => scan
                        .invalid
                        .push(InvalidPendingEnrollment { operation_id, detail: error.to_string() }),
                }
            }
            Ok(scan)
        })
    }

    /// Opens a new `enrollment_operations` row -- see
    /// [`EnrollmentOperation`]'s doc comment. Unlike the pre-Commit-4
    /// idempotent-upsert idiom, an existing row under the same
    /// `operation_id` is NEVER overwritten -- `operation_id` is a fresh UUID
    /// minted by the caller for every new enrollment attempt, so a conflict
    /// means either a genuine UUID collision or a bug, and silently
    /// clobbering the existing row could destroy in-flight recovery state.
    /// Returns `Ok(false)` (not an error) on conflict, so the caller can
    /// retry under a fresh id.
    pub fn try_insert_enrollment_operation(
        &self,
        operation: &EnrollmentOperation,
    ) -> Result<bool, SyncSqliteError> {
        validate_enrollment_operation(operation).map_err(SyncSqliteError::CorruptState)?;
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "INSERT INTO enrollment_operations \
                    (operation_id, kind, group_id, group_name, device_id, local_path, \
                     storage_mode, state, last_error, attempts, created_at_unix, \
                     updated_at_unix) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(operation_id) DO NOTHING",
                rusqlite::params![
                    operation.operation_id,
                    operation.kind.as_db_str(),
                    operation.group_id,
                    operation.group_name,
                    operation.device_id,
                    operation.local_path,
                    operation.storage_mode,
                    operation.state.as_db_str(),
                    operation.last_error,
                    operation.attempts,
                    operation.created_at_unix,
                    operation.updated_at_unix,
                ],
            )?)
        })?;
        Ok(changed == 1)
    }

    /// Reads a single `enrollment_operations` row by id, if it still exists.
    pub fn get_enrollment_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<EnrollmentOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, kind, group_id, group_name, device_id, local_path, \
                        storage_mode, state, last_error, attempts, created_at_unix, \
                        updated_at_unix \
                 FROM enrollment_operations WHERE operation_id = ?1",
            )?;
            let mut rows = stmt.query_map([operation_id], row_to_enrollment_operation)?;
            match rows.next() {
                Some(row) => Ok(Some(row?)),
                None => Ok(None),
            }
        })
    }

    /// Every `enrollment_operations` row NOT in a terminal or blocked state
    /// (there is no terminal state today -- every resolved row is deleted --
    /// so this excludes only `recovery-blocked`), split into successfully
    /// decoded rows and rows that failed to decode. Mirrors
    /// [`Self::scan_open_membership_operations`]'s own doc comment for why
    /// this is a deny-list: an unrecognized `state` string still surfaces
    /// here instead of silently sitting outside every future sweep.
    pub fn scan_open_enrollment_operations(
        &self,
    ) -> Result<EnrollmentOperationScan, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, kind, group_id, group_name, device_id, local_path, \
                        storage_mode, state, last_error, attempts, created_at_unix, \
                        updated_at_unix \
                 FROM enrollment_operations WHERE state != 'recovery_blocked' \
                 ORDER BY created_at_unix",
            )?;
            let mut rows = stmt.query([])?;
            let mut scan = EnrollmentOperationScan::default();
            while let Some(row) = rows.next()? {
                let operation_id: String = row.get(0)?;
                let raw_state: Option<String> = row.get(7).ok();
                match row_to_enrollment_operation(row) {
                    Ok(operation) => scan.valid.push(operation),
                    Err(error) => scan.invalid.push(InvalidEnrollmentOperation {
                        operation_id,
                        raw_state,
                        detail: error.to_string(),
                    }),
                }
            }
            Ok(scan)
        })
    }

    /// Every `enrollment_operations` row, INCLUDING `recovery_blocked` --
    /// unlike [`Self::scan_open_enrollment_operations`], which deliberately
    /// excludes blocked rows because ordinary reconciliation must never act
    /// on one. A read-only inventory (`recovery::inventory`) needs the
    /// opposite: a blocked row is exactly the kind of thing an operator most
    /// needs to see, so it gets its own unfiltered query rather than ever
    /// being asked to reuse the sweep's deny-list.
    pub fn scan_all_enrollment_operations(
        &self,
    ) -> Result<InventoryScanResult<EnrollmentOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, kind, group_id, group_name, device_id, local_path, \
                        storage_mode, state, last_error, attempts, created_at_unix, \
                        updated_at_unix \
                 FROM enrollment_operations ORDER BY created_at_unix",
            )?;
            let mut rows = stmt.query([])?;
            let mut scan = InventoryScanResult::default();
            while let Some(row) = rows.next()? {
                let raw_state: Option<String> = row.get(7).ok();
                let Some(operation_id) = read_inventory_operation_id(row, 0)? else {
                    scan.invalid.push(InvalidRecoveryOperation {
                        operation_id: None,
                        domain: RecoveryDomain::Enrollment,
                        raw_state,
                        detail: "operation_id is not valid TEXT".to_string(),
                    });
                    continue;
                };
                match row_to_enrollment_operation(row) {
                    Ok(operation) => scan.valid.push(operation),
                    Err(error) => scan.invalid.push(InvalidRecoveryOperation {
                        operation_id: Some(operation_id),
                        domain: RecoveryDomain::Enrollment,
                        raw_state,
                        detail: error.to_string(),
                    }),
                }
            }
            Ok(scan)
        })
    }

    /// Advances a `PreparePending` row to `Prepared` once coordination
    /// prepare confirms `group_id` -- returns `Ok(false)` if the row is no
    /// longer `PreparePending` (already advanced, or gone).
    pub fn mark_enrollment_operation_prepared(
        &self,
        operation_id: &str,
        group_id: &str,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE enrollment_operations SET group_id = ?1, state = 'prepared', \
                    last_error = NULL, updated_at_unix = ?2 \
                 WHERE operation_id = ?3 AND state = 'prepare_pending'",
                rusqlite::params![group_id, now_unix, operation_id],
            )?)
        })?;
        Ok(changed == 1)
    }

    /// Advances an enrollment-operation row to an arbitrary `new_state`
    /// (`CancelPending`, `RecoveryBlocked`, or a retry's `last_error` bump)
    /// -- matching [`Self::mark_membership_operation_state`]. Returns
    /// `Ok(false)` if `operation_id` no longer names a row.
    pub fn mark_enrollment_operation_state(
        &self,
        operation_id: &str,
        new_state: EnrollmentOperationState,
        last_error: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE enrollment_operations SET state = ?1, last_error = ?2, \
                    updated_at_unix = ?3 \
                 WHERE operation_id = ?4",
                rusqlite::params![new_state.as_db_str(), last_error, now_unix, operation_id],
            )?)
        })?;
        Ok(changed > 0)
    }

    /// Bumps an enrollment-operation's retry counter -- purely a visibility
    /// aid, matching [`Self::increment_role_loss_operation_attempts`]; never
    /// gates whether a retry happens.
    pub fn increment_enrollment_operation_attempts(
        &self,
        operation_id: &str,
        now_unix: i64,
    ) -> Result<i64, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "UPDATE enrollment_operations SET attempts = attempts + 1, updated_at_unix = ?1 \
                 WHERE operation_id = ?2 RETURNING attempts",
                rusqlite::params![now_unix, operation_id],
                |r| r.get(0),
            )?)
        })
    }

    /// Deletes an `enrollment_operations` row once its cancel is confirmed
    /// -- idempotent, matching [`Self::delete_role_loss_operation`].
    pub fn delete_enrollment_operation(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM enrollment_operations WHERE operation_id = ?1",
                [operation_id],
            )?;
            Ok(())
        })
    }

    /// Deletes the `pending_enrollments` marker AND the matching
    /// `ActivationPending` `enrollment_operations` row together, atomically,
    /// once remote activation is confirmed (`Success`/`AlreadyActive`).
    /// Deleting only the marker (the pre-Commit-5 behavior) left the
    /// journal row to a LATER, non-atomic sweep of a different reconciler to
    /// clean up -- a crash in between left a marker-less `ActivationPending`
    /// row with no durable link to it. `changed != 1` on the journal DELETE
    /// (the row was not `ActivationPending`, or was already gone) leaves the
    /// whole transaction rolled back -- the marker is NOT dropped in that
    /// case, since some other invariant about this operation is already
    /// unexpected and it is safer to leave both for the next sweep to sort
    /// out than to silently discard the marker without a matching row.
    pub fn settle_activated_enrollment(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
            let changed = tx.execute(
                "DELETE FROM enrollment_operations WHERE operation_id = ?1 AND state = \
                 'activation_pending'",
                [operation_id],
            )?;
            if changed != 1 {
                return Err(SyncSqliteError::CorruptState(format!(
                    "enrollment operation {operation_id} was not ActivationPending while \
                     settling its confirmed activation"
                )));
            }
            Ok(())
        })
    }

    /// Writes to `links` as well as its own enrollment tables in one
    /// transaction to preserve atomicity -- decomposing this into separate
    /// `LinkRepository`/`EnrollmentRepository` calls would reopen the exact
    /// crash window the single transaction exists to close. A future
    /// cross-repository "commit store" (Commit 14 candidate) may formalize
    /// this; it is not a design flaw to fix now.
    /// Commits a local link, its `pending_enrollments` activation marker,
    /// AND advances the matching `enrollment_operations` row to
    /// `LocalSetupPending`, all in ONE SQLite transaction -- the atomic
    /// handoff from "nothing committed yet" to "link/marker committed, but
    /// local setup (watcher registration, on-demand config) not yet
    /// confirmed". Deliberately NOT `ActivationPending` yet: remote
    /// activation must never be attempted until [`Self::mark_enrollment_activation_pending`]
    /// confirms the fallible post-commit setup actually finished, or the
    /// pending-enrollment reconciler could activate a remote authorization
    /// for a link whose watcher this device never finished registering.
    /// `changed != 1` on the journal UPDATE means the row wasn't `Prepared`
    /// (already advanced, blocked, or gone) -- the whole transaction is
    /// rolled back rather than committing a link with no consistent journal
    /// state behind it.
    ///
    /// A `Join` marker additionally records this instant as the group's
    /// local history floor, in this same transaction -- see the inline
    /// comment at that statement for why it has to be here and nowhere
    /// later.
    pub fn add_link_with_pending_enrollment_and_begin_setup(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollment,
        now_unix: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::link::LinkRepository::insert_link_row(tx, local_path, group_id)?;
            tx.execute(
                "INSERT OR REPLACE INTO pending_enrollments \
                 (operation_id, kind, group_id, device_id, local_path) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    marker.operation_id,
                    marker.kind.as_db_str(),
                    marker.group_id,
                    marker.device_id,
                    marker.local_path,
                ],
            )?;
            // Joining an existing group starts this device's local `files`
            // history for it HERE, at an arbitrary point in the group's own
            // life. Every path the group already holds arrives afterwards
            // through `upsert_file_in_tx`, which numbers a path it is seeing
            // for the first time from `version_seq = 1` no matter how much
            // history that path already has elsewhere -- so, read from
            // `files` alone, a file created years ago on another device is
            // indistinguishable from one this device itself created just
            // now. Recording the join instant is what keeps the rewind
            // planning layer from reading the first kind as the second and
            // reporting a whole inherited folder as "created since the
            // target"; see `crate::rewind_plan::classify_without_history`
            // for the inference this bounds.
            //
            // Written HERE, in the transaction that commits the link, and
            // not from any later step, for two independent reasons. The
            // marker carrying `kind` is deleted as soon as the enrollment
            // settles (`settle_activated_enrollment`), so a later reader has
            // nothing left to distinguish a join from a create by. And the
            // floor must be durable before the first synced row can land, or
            // a crash in between leaves rows this device cannot honestly
            // reason about with nothing recording that.
            //
            // `Create` deliberately writes nothing: a folder this device
            // originated locally has no inherited history to guard against,
            // its `version_seq = 1` rows really are its own first
            // admissions, and a target before the folder existed is
            // correctly answered `Delete`.
            //
            // The plain link commit (`LinkRepository::add_link`, which
            // `share accept` and `yadorilink link` use and which carries no
            // marker at all) records the same floor for the same reason --
            // see that method.
            if marker.kind == EnrollmentKind::Join {
                crate::rewind_plan::record_local_history_floor_for_a_first_link(tx, group_id)?;
            }
            let changed = tx.execute(
                "UPDATE enrollment_operations SET state = 'local_setup_pending', group_id = ?1, \
                    last_error = NULL, updated_at_unix = ?2 \
                 WHERE operation_id = ?3 AND state = 'prepared'",
                rusqlite::params![group_id, now_unix, marker.operation_id],
            )?;
            if changed != 1 {
                return Err(SyncSqliteError::CorruptState(format!(
                    "enrollment operation {} was not in Prepared state while committing its \
                     local link",
                    marker.operation_id
                )));
            }
            Ok(())
        })
    }

    /// Advances a `LocalSetupPending` row to `ActivationPending` once the
    /// fallible post-commit local setup (watcher registration, on-demand
    /// config) is confirmed to have finished -- ONLY past this point may the
    /// pending-enrollment reconciler attempt remote activation. Returns
    /// `Ok(false)` (not an error) if the row is no longer `LocalSetupPending`
    /// (e.g. a concurrent recovery sweep already rolled it back after this
    /// row sat past its age-gate) -- the caller must NOT retroactively roll
    /// back a local setup that already succeeded in that case, but also must
    /// not attempt remote activation itself.
    pub fn mark_enrollment_activation_pending(
        &self,
        operation_id: &str,
        now_unix: i64,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE enrollment_operations SET state = 'activation_pending', \
                    last_error = NULL, updated_at_unix = ?1 \
                 WHERE operation_id = ?2 AND state = 'local_setup_pending'",
                rusqlite::params![now_unix, operation_id],
            )?)
        })?;
        Ok(changed == 1)
    }

    /// Writes to `links` as well as its own enrollment tables in one
    /// transaction to preserve atomicity -- decomposing this into separate
    /// `LinkRepository`/`EnrollmentRepository` calls would reopen the exact
    /// crash window the single transaction exists to close. A future
    /// cross-repository "commit store" (Commit 14 candidate) may formalize
    /// this; it is not a design flaw to fix now.
    /// Rolls a `LocalSetupPending` link + pending marker back to
    /// `CancelPending`, atomically. Used both by `link()`'s own post-commit
    /// setup-failure rollback path, and by recovery when a row is found
    /// still `LocalSetupPending` well past its age-gate (the daemon crashed
    /// mid-setup). Deletes the link row and the pending marker, and returns
    /// the enrollment_operations row to `CancelPending` so the
    /// coordination-side Pending authorization is still cancelled durably.
    /// If the transaction itself fails, the caller must leave the operation
    /// exactly as it was (`LocalSetupPending`) rather than assume any of
    /// this happened -- see the caller's own handling.
    ///
    /// Deliberately does NOT undo the `group_local_history_floor` row a
    /// `Join` commit wrote. A floor is not link state: it says when this
    /// device's own `files` history for the group begins, and `files` rows
    /// survive an unlink (every `DELETE FROM files` outside a re-bootstrap
    /// install is keyed by path). Clearing it here could therefore drop a
    /// boundary that still bounds real, still-present rows -- an earlier
    /// re-bootstrap's, for a group being re-linked. Leaving it can only make
    /// a later answer more conservative, and for a link that really was
    /// rolled back the group has no rows for it to bound at all.
    pub fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        operation_id: &str,
        detail: &str,
        now_unix: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
            tx.execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
            let changed = tx.execute(
                "UPDATE enrollment_operations SET state = 'cancel_pending', last_error = ?1, \
                    updated_at_unix = ?2 \
                 WHERE operation_id = ?3 AND state = 'local_setup_pending'",
                rusqlite::params![detail, now_unix, operation_id],
            )?;
            if changed != 1 {
                return Err(SyncSqliteError::CorruptState(format!(
                    "could not return local-setup-pending enrollment operation {operation_id} to \
                     CancelPending"
                )));
            }
            Ok(())
        })
    }

    /// Transfers a `pending_enrollments` marker whose local link is absent
    /// into a durable `enrollment_operations` `CancelPending` row,
    /// atomically -- the absent-link reconciliation path (E6/E8 in the
    /// review this implements). Without this, dropping the marker directly
    /// and cancelling best-effort (the pre-Commit-4 behavior) could lose the
    /// only durable record of an outstanding coordination-side Pending
    /// authorization if the cancel call itself never lands. `storage_mode`
    /// is not tracked by `PendingEnrollment`, so a fixed placeholder is
    /// used -- cancellation never reads it.
    pub fn move_pending_enrollment_to_cancel_operation(
        &self,
        marker: &PendingEnrollment,
        now_unix: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let existing: Option<(String, String, String, String, String)> = tx
                .query_row(
                    "SELECT kind, group_id, device_id, local_path, state \
                     FROM enrollment_operations WHERE operation_id = ?1",
                    [&marker.operation_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()?;
            match existing {
                None => {
                    tx.execute(
                        "INSERT INTO enrollment_operations \
                            (operation_id, kind, group_id, group_name, device_id, local_path, \
                             storage_mode, state, last_error, attempts, created_at_unix, \
                             updated_at_unix) \
                         VALUES (?1, ?2, ?3, NULL, ?4, ?5, 'on-demand', 'cancel_pending', NULL, \
                                 0, ?6, ?6)",
                        rusqlite::params![
                            marker.operation_id,
                            marker.kind.as_db_str(),
                            marker.group_id,
                            marker.device_id,
                            marker.local_path,
                            now_unix,
                        ],
                    )?;
                }
                Some((kind, group_id, device_id, local_path, state))
                    if kind == marker.kind.as_db_str()
                        && group_id == marker.group_id
                        && device_id == marker.device_id
                        && local_path == marker.local_path
                        && matches!(
                            state.as_str(),
                            "prepared"
                                | "local_setup_pending"
                                | "activation_pending"
                                | "cancel_pending"
                        ) =>
                {
                    let changed = tx.execute(
                        "UPDATE enrollment_operations \
                         SET state = 'cancel_pending', last_error = 'local link is absent', \
                             updated_at_unix = ?1 \
                         WHERE operation_id = ?2",
                        rusqlite::params![now_unix, marker.operation_id],
                    )?;
                    if changed != 1 {
                        return Err(SyncSqliteError::CorruptState(format!(
                            "pending-enrollment marker {} conflicts with an existing enrollment \
                             operation",
                            marker.operation_id
                        )));
                    }
                }
                Some(_) => {
                    return Err(SyncSqliteError::CorruptState(format!(
                        "pending-enrollment marker {} conflicts with an existing enrollment \
                         operation",
                        marker.operation_id
                    )));
                }
            }
            tx.execute(
                "DELETE FROM pending_enrollments WHERE operation_id = ?1",
                [&marker.operation_id],
            )?;
            Ok(())
        })
    }
}

// `pub`, not `pub(crate)`: `yadorilink-sync-core::repository::recovery_snapshot::
// RecoverySnapshotReader` (genuinely cross-repository/cross-crate, staying
// behind in that crate -- see its own doc comment) decodes an
// `enrollment_operations`/`pending_enrollments` row itself inside its own
// single consistent-read `Deferred` transaction, and must reuse the exact
// same shape-validated decoder rather than duplicate
// `validate_enrollment_operation`'s rules a second time -- same precedent as
// `row_to_membership_operation`/`row_to_role_loss_operation_strict`'s own
// `pub` bump (Phase 7D-9F, eighth pass).
pub fn row_to_pending_enrollment(r: &rusqlite::Row<'_>) -> rusqlite::Result<PendingEnrollment> {
    let kind_raw: String = r.get(1)?;
    let kind = EnrollmentKind::try_from_db_str(&kind_raw)
        .map_err(|error| enrollment_decode_error(1, error))?;
    Ok(PendingEnrollment {
        operation_id: r.get(0)?,
        kind,
        group_id: r.get(2)?,
        device_id: r.get(3)?,
        local_path: r.get(4)?,
    })
}

fn enrollment_decode_error(column_index: usize, detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column_index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, detail.into())),
    )
}

/// Shape validation matching each `kind`/`state` combination's own
/// requirements -- see [`EnrollmentOperation::group_id`]/
/// [`EnrollmentOperation::group_name`]'s doc comments.
pub(crate) fn validate_enrollment_operation(operation: &EnrollmentOperation) -> Result<(), String> {
    if operation.operation_id.is_empty() {
        return Err("empty enrollment operation id".to_string());
    }
    if operation.attempts < 0 {
        return Err(format!("negative enrollment attempts: {}", operation.attempts));
    }
    if operation.device_id.is_empty() {
        return Err("empty enrollment device id".to_string());
    }
    if operation.local_path.is_empty() {
        return Err("empty enrollment local path".to_string());
    }
    if !matches!(operation.storage_mode.as_str(), "eager" | "on-demand") {
        return Err(format!("invalid enrollment storage mode: {}", operation.storage_mode));
    }
    match operation.kind {
        EnrollmentKind::Create => match operation.state {
            EnrollmentOperationState::PreparePending => {
                if operation.group_name.as_deref().unwrap_or("").is_empty() {
                    return Err("create PreparePending requires group_name".to_string());
                }
            }
            // A conflict/malformed-row block can land at ANY point in the
            // lifecycle, including before prepare ever resolved a
            // group_id -- never require one here, or a genuinely blocked
            // row from that early window would itself become permanently
            // unreadable (a malformed row hiding behind its own
            // "malformed" marking).
            EnrollmentOperationState::RecoveryBlocked => {}
            EnrollmentOperationState::Prepared
            | EnrollmentOperationState::LocalSetupPending
            | EnrollmentOperationState::ActivationPending
            | EnrollmentOperationState::CancelPending => {
                if operation.group_id.as_deref().unwrap_or("").is_empty() {
                    return Err(format!(
                        "create state {:?} requires a resolved group_id",
                        operation.state
                    ));
                }
            }
        },
        EnrollmentKind::Join => {
            if operation.group_id.as_deref().unwrap_or("").is_empty() {
                return Err("join enrollment operation requires group_id".to_string());
            }
        }
    }
    Ok(())
}

// `pub` for the same cross-crate `RecoverySnapshotReader` reason as
// [`row_to_pending_enrollment`] above.
pub fn row_to_enrollment_operation(r: &rusqlite::Row<'_>) -> rusqlite::Result<EnrollmentOperation> {
    let kind_raw: String = r.get(1)?;
    let state_raw: String = r.get(7)?;
    let kind = EnrollmentKind::try_from_db_str(&kind_raw)
        .map_err(|error| enrollment_decode_error(1, error))?;
    let state = EnrollmentOperationState::try_from_db_str(&state_raw)
        .map_err(|error| enrollment_decode_error(7, error))?;
    let operation = EnrollmentOperation {
        operation_id: r.get(0)?,
        kind,
        group_id: r.get(2)?,
        group_name: r.get(3)?,
        device_id: r.get(4)?,
        local_path: r.get(5)?,
        storage_mode: r.get(6)?,
        state,
        last_error: r.get(8)?,
        attempts: r.get(9)?,
        created_at_unix: r.get(10)?,
        updated_at_unix: r.get(11)?,
    };
    validate_enrollment_operation(&operation).map_err(|error| enrollment_decode_error(7, error))?;
    Ok(operation)
}

/// What a link commit means for the rewind planning layer, driven end to
/// end through the real writers -- no hand-written
/// `group_local_history_floor` row anywhere, and no hand-written `files`
/// row either.
///
/// The scenario is the ordinary one: a folder group has been in use for a
/// while, a second device joins it, and the next day someone asks that
/// device what the folder looked like a month ago. Everything the group
/// already held reaches the new device AFTER its join, and
/// `file_index::upsert_file_in_tx` numbers a path it is seeing for the first
/// time from `version_seq = 1` regardless of how much history that path has
/// elsewhere -- so, from `files` alone, a years-old file is shaped exactly
/// like one this device just created. Without the floor the preview reports
/// the whole inherited folder as `Delete` ("all of this was created since
/// then"), with `unavailable = 0` suppressing every hedge a renderer would
/// otherwise show.
#[cfg(test)]
mod local_history_floor_tests {
    use super::*;
    use crate::rewind_plan::compute_rewind_plan;
    use yadorilink_replica_domain::file::FileRecord;
    use yadorilink_replica_domain::rewind::RewindPathAction;

    const DEVICE: &str = "device-1";
    const GROUP: &str = "group-1";
    const LOCAL_PATH: &str = "/folders/shared";
    /// The distance a preview like `--at 30d` asks about.
    const THIRTY_DAYS_NANOS: i64 = 30 * 24 * 60 * 60 * 1_000_000_000;

    /// Full schema, pooled exactly as production opens it -- DAG tables
    /// first, since `yadorilink_sqlite_runtime::init_schema` assumes
    /// `changes`/`pruned_changes` already exist. Mirrors
    /// `rebootstrap_store`'s own `open_full_test_db`.
    fn open_full_test_db() -> Arc<SyncDatabase> {
        Arc::new(
            SyncDatabase::open_in_memory(|conn| {
                crate::dag_store::init_dag_schema(conn).map_err(|e| {
                    yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
                })?;
                yadorilink_sqlite_runtime::init_schema(conn)
            })
            .expect("open in-memory db"),
        )
    }

    /// Walks an enrollment through the real journal states and commits its
    /// link through the real production entry point -- the same call the
    /// daemon's own link adapter makes for both `share create` and
    /// `share join`. Nothing here reaches around
    /// [`EnrollmentRepository::add_link_with_pending_enrollment_and_begin_setup`].
    fn commit_link_through_enrollment(db: &Arc<SyncDatabase>, kind: EnrollmentKind) {
        let repository = EnrollmentRepository::new(db.clone());
        let operation_id = "operation-1";
        assert!(
            repository
                .try_insert_enrollment_operation(&EnrollmentOperation {
                    operation_id: operation_id.to_string(),
                    kind,
                    group_id: Some(GROUP.to_string()),
                    // Required of a `Create` row while it is still
                    // `PreparePending`, and meaningless for a `Join`.
                    group_name: matches!(kind, EnrollmentKind::Create)
                        .then(|| "Shared".to_string()),
                    device_id: DEVICE.to_string(),
                    local_path: LOCAL_PATH.to_string(),
                    storage_mode: "eager".to_string(),
                    state: EnrollmentOperationState::PreparePending,
                    last_error: None,
                    attempts: 0,
                    created_at_unix: 0,
                    updated_at_unix: 0,
                })
                .unwrap(),
            "the journal row must be inserted"
        );
        assert!(
            repository.mark_enrollment_operation_prepared(operation_id, GROUP, 1).unwrap(),
            "prepare must advance the row, or the commit below would refuse it"
        );
        repository
            .add_link_with_pending_enrollment_and_begin_setup(
                LOCAL_PATH,
                GROUP,
                &PendingEnrollment {
                    operation_id: operation_id.to_string(),
                    kind,
                    group_id: GROUP.to_string(),
                    device_id: DEVICE.to_string(),
                    local_path: LOCAL_PATH.to_string(),
                },
                2,
            )
            .expect("the link commit must succeed");
    }

    /// Admits one file through the real file-index write chokepoint, the
    /// way an incoming change from a peer does. `origin_device_id` is
    /// another device precisely because this models a file the GROUP
    /// already had -- but the row it produces still carries
    /// `version_seq = 1`, which is the whole problem.
    fn admit_file(db: &Arc<SyncDatabase>, path: &str, size: u64) {
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::file_index::upsert_file_in_tx(
                tx,
                GROUP,
                &FileRecord {
                    path: path.to_string(),
                    size,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: false,
                },
                "device-that-was-here-first",
                None,
            )
        })
        .expect("the file admission must succeed");
    }

    fn action_at(db: &Arc<SyncDatabase>, at_unix_nanos: i64, path: &str) -> RewindPathAction {
        db.read::<_, SyncSqliteError>(|conn| compute_rewind_plan(conn, GROUP, at_unix_nanos))
            .unwrap()
            .entries
            .into_iter()
            .find(|entry| entry.path == path)
            .unwrap_or_else(|| panic!("{path} must appear in the plan"))
            .action
    }

    fn recorded_floor(db: &Arc<SyncDatabase>) -> Option<i64> {
        db.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT floor_unix_nanos FROM group_local_history_floor WHERE group_id = ?1",
                    [GROUP],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .unwrap()
    }

    /// The headline case. A file the group already held when this device
    /// joined must not be reported as something a rewind would delete.
    #[test]
    fn a_file_inherited_at_a_join_is_unavailable_before_the_join_not_delete() {
        let db = open_full_test_db();
        let before_join = crate::file_index::now_unix_nanos_checked().unwrap();
        commit_link_through_enrollment(&db, EnrollmentKind::Join);
        // Everything the group already held syncs in after the join.
        for path in ["notes.txt", "photos/trip.jpg", "budget.csv"] {
            admit_file(&db, path, 10);
        }

        // The observable verdict first, so a regression reports what the
        // user would actually be shown rather than a missing table row.
        let a_month_ago = before_join - THIRTY_DAYS_NANOS;
        let plan = db
            .read::<_, SyncSqliteError>(|conn| compute_rewind_plan(conn, GROUP, a_month_ago))
            .unwrap();
        let counts = plan.action_counts();
        assert_eq!(
            counts.delete, 0,
            "a folder this device inherited was not created since the target, so a preview must \
             not offer to delete it: {counts:?}"
        );
        assert_eq!(
            counts.unavailable, 3,
            "every inherited path is unanswerable this far back, and `unavailable = 0` is what \
             suppresses a renderer's own hedge: {counts:?}"
        );

        match action_at(&db, a_month_ago, "notes.txt") {
            RewindPathAction::Unavailable { reason } => {
                assert!(
                    reason.contains("joined the group"),
                    "the reason must name the join as a possible cause: {reason}"
                );
                assert!(
                    !reason.contains("retention"),
                    "retention cannot be the cause below the floor, and naming it would be a \
                     confident wrong explanation: {reason}"
                );
            }
            other => panic!("expected Unavailable before the join, got {other:?}"),
        }

        let floor = recorded_floor(&db).expect("a join must record this group's history floor");
        assert!(floor >= before_join, "the floor must be the join instant, not something earlier");
    }

    /// The other half of the same boundary: the floor must not turn a
    /// joined device into one that can never answer anything. At the floor
    /// itself, and above it, ordinary classification resumes -- including
    /// the `version_seq = 1` reading the floor suspends below itself.
    #[test]
    fn at_or_after_the_join_floor_paths_are_classified_normally() {
        let db = open_full_test_db();
        commit_link_through_enrollment(&db, EnrollmentKind::Join);
        admit_file(&db, "notes.txt", 10);
        let floor = recorded_floor(&db).expect("a join must record this group's history floor");

        assert_eq!(
            action_at(&db, floor, "notes.txt"),
            RewindPathAction::Delete,
            "at the floor the group's history is this device's own again, and this row really \
             was admitted after the target"
        );
        assert_eq!(
            action_at(&db, i64::MAX, "notes.txt"),
            RewindPathAction::Unchanged,
            "a target after the row's own admission is answered from the row itself"
        );
    }

    /// The `Create` path must keep behaving exactly as it did. A folder
    /// this device originated locally has no inherited history to guard
    /// against: its `version_seq = 1` rows really are its own first
    /// admissions, so a target before the folder existed is honestly
    /// `Delete`, not `Unavailable`. This is the regression guard on the
    /// fix's own blast radius.
    #[test]
    fn a_locally_created_folder_still_reports_delete_before_it_existed() {
        let db = open_full_test_db();
        let before_create = crate::file_index::now_unix_nanos_checked().unwrap();
        commit_link_through_enrollment(&db, EnrollmentKind::Create);
        admit_file(&db, "notes.txt", 10);

        assert_eq!(
            recorded_floor(&db),
            None,
            "creating a folder locally must record no history floor -- there is no inherited \
             history to bound"
        );
        assert_eq!(
            action_at(&db, before_create - THIRTY_DAYS_NANOS, "notes.txt"),
            RewindPathAction::Delete,
            "before this device created the folder, its files genuinely did not exist"
        );
    }

    /// The floor is per group. One device's join of one group must not make
    /// another group -- one it created itself -- unanswerable.
    #[test]
    fn a_join_floor_is_scoped_to_the_group_that_was_joined() {
        let db = open_full_test_db();
        let before_join = crate::file_index::now_unix_nanos_checked().unwrap();
        commit_link_through_enrollment(&db, EnrollmentKind::Join);
        admit_file(&db, "inherited.txt", 10);
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::file_index::upsert_file_in_tx(
                tx,
                "another-group",
                &FileRecord {
                    path: "mine.txt".to_string(),
                    size: 10,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: false,
                },
                DEVICE,
                None,
            )
        })
        .unwrap();

        let a_month_ago = before_join - THIRTY_DAYS_NANOS;
        assert!(matches!(
            action_at(&db, a_month_ago, "inherited.txt"),
            RewindPathAction::Unavailable { .. }
        ));
        let other = db
            .read::<_, SyncSqliteError>(|conn| {
                compute_rewind_plan(conn, "another-group", a_month_ago)
            })
            .unwrap();
        assert_eq!(
            other.entries.iter().find(|e| e.path == "mine.txt").unwrap().action,
            RewindPathAction::Delete,
            "a group with no floor of its own keeps the ordinary inference"
        );
    }
}
