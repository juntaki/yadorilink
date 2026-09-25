use yadorilink_peer_session::PeerSessionError;

use super::super::types::*;
use super::MaterializationPlan;

impl super::super::LocalConvergenceExecutor {
    /// The on-demand lane of [`Self::materialize_local`]: an OnDemand,
    /// not-pinned record gets a placeholder and no block fetch at all.
    pub(super) fn materialize_on_demand_lane(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        // OnDemand/not-pinned is the
        // placeholder path — but a placeholder is still a real
        // on-disk artifact created *under this path's exact name*, so
        // a hazardous record must not get one either (held
        // means no on-disk artifact under this name at all, full
        // content or placeholder alike; never any alternate name).
        if let Some(reason) = &plan.hazard_reason {
            return self.hold_for_hazard(plan, reason);
        }
        // A placeholder replaces whatever is at the path with a sparse
        // file of the record's size, so it destroys a local edit exactly
        // as a content write would. The pre-materialize flush guard is
        // scheduling-dependent -- a write can land after it -- so the
        // eager lane's last-line disk check stands here too, before the
        // row is persisted or an intent opened, so a decline leaves
        // nothing behind.
        let out_path = self.local_file_path(group_id, &record.path)?;
        if self.disk_holds_uncaptured_local_bytes(
            group_id,
            &record.path,
            &out_path,
            Some(&record.blocks),
        )? {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining an on-demand placeholder write whose target no longer matches this \
                 device's indexed content; an unauthored local edit is on disk and a \
                 placeholder would destroy it silently"
            );
            yadorilink_peer_session::dst_trace(&record.path, || {
                format!(
                    "on-demand placeholder DECLINED on {}: on-disk bytes diverge from indexed \
                     content -- unauthored local edit protected",
                    self.local_device_id
                )
            });
            return Ok(MaterializeResult::RetryRequired.into());
        }
        // OnDemand and not pinned: no block fetch at all — the whole
        // point of a placeholder is deferring that until access.
        //
        // Same journaled-write seam the eager/pinned branches above use
        // (exercised by a restart-mid-relay-sync integration test): this
        // is the actual ORDINARY on-demand-receive path -- the one a plain
        // On-Demand device takes for every normal incoming file. Without
        // it, the fresh (briefly-`Hydrated`-by-default, per
        // `persist_row_under_fresh_operation`'s own doc comment) index row
        // would be committed with NO protecting intent, before either the explicit
        // demotion to `Placeholder` or the actual on-disk placeholder
        // write, and a crash/restart in either window would leave an indexed,
        // not-deleted row with no local file and no intent -- exactly
        // what the startup "full reconciliation" scan
        // (`local_change.rs`'s `reconcile_disk_with_ignore`) reads as
        // an offline deletion, silently tombstoning a file this device
        // never actually lost.
        let intent_guard = self.state.open_placeholder_write(
            group_id,
            record,
            plan.origin_device_id,
            plan.authoring_change_hash,
            &|| self.root_lease_for(group_id),
            root_commit_permit,
        )?;
        // defense-in-depth — see the comment above.
        // A placeholder is a real on-disk write -- bump before it,
        // same as the eager/pinned placeholder
        // branches above. The evidence this settles as
        // (`PolicyPlaceholder`) carries no fence value of its own (it
        // is never CAS-published), but the bump itself still must
        // land, to invalidate any stale exact-object proof this path
        // may already carry.
        let placeholder_deferred =
            self.write_placeholder(plan, &out_path, "ondemand_placeholder_write")?;
        if placeholder_deferred {
            // Windows: `create_or_defer_placeholder` wrote nothing --
            // the real reparse-point placeholder is created later by
            // `cfapi-host.exe`'s own poll, not by this call. This is
            // NOT a settled outcome the way the non-deferred case
            // below is: settling `PolicyPlaceholder` completes this
            // path's projection obligation, and clearing the intent
            // removes the last thing protecting a path that genuinely
            // has nothing under its own name yet. Both would leave
            // this row with none of the tombstone loop's three
            // vetoes, on the ordinary on-demand-receive path every
            // Windows OnDemand-policy device takes for every normal
            // incoming file -- not a rare or dormant shape. Left open
            // deliberately (no mechanism in this codebase yet
            // observes `cfapi-host.exe`'s own confirmation), and
            // retried: a fresh `materialize` call for this path is
            // idempotent here (`RecordIfAbsent`'s own persist
            // discipline never overwrites a generation already
            // in use). Deliberately returns BEFORE `apply_unix_mode`/
            // `apply_xattrs` below too: those are real syscalls
            // against a path nothing has actually created yet.
            return Ok(MaterializeResult::RetryRequired.into());
        }
        // This IS a settled outcome (unlike the eager/pinned
        // placeholder above, and unlike the deferred case just
        // above): on-demand policy deliberately defers content until
        // access, it did not want the blocks now and fail to get
        // them, and the real placeholder write above just durably
        // completed synchronously.
        //
        // Clear the intent right after that write is confirmed,
        // BEFORE `apply_unix_mode`/`apply_xattrs` below -- correcting
        // an earlier version of this fix that cleared BEFORE `create_
        // or_defer_placeholder` instead, trading a benign outcome (a
        // stale intent left open past a later failure --
        // `materialization_repair.rs`'s own doc says repair treats an
        // open intent as safe, deferring rather than tombstoning) for
        // a harmful one (row committed as non-deleted Placeholder, no
        // file on disk, no intent -- exactly what the startup
        // reconciliation scan reads as an offline deletion). Clearing
        // only AFTER `apply_unix_mode`/`apply_xattrs` has the same
        // harmful shape from the other direction: a repeatable chmod
        // EPERM or xattr EOPNOTSUPP there would leak this guard
        // permanently -- the placeholder is already durably on disk
        // by this point (this device's own write, not a peer's
        // content), so nothing would ever re-drive materialization
        // for this exact path again to clean the intent up. This is
        // the ordinary on-demand-receive path, so the window's
        // frequency is far higher than on the eager/pinned branches
        // this pattern was copied from. An early `?` return on any
        // step above still drops the guard without clearing, which is
        // the safe (defer-the-delete) failure mode, matching the
        // eager/pinned `Hydrated` branch's own established ordering.
        intent_guard.clear()?;
        let settled = MaterializeResult::Settled(SettlementEvidence::PolicyPlaceholder);
        // A placeholder still gets the recorded exec bit
        // applied now — `hydrate_file_with_timeout` re-applies it
        // again once real content lands, so this is never lost
        // across the placeholder → hydrated transition either. Best-
        // effort relative to the settlement above, not a precondition
        // of it: a failure here still returns `Err` to the caller,
        // but the row and intent are already correctly settled --
        // only the exec-bit/xattrs may be stale, a separate, lower-
        // severity gap, not the tombstone-safety shape this ordering
        // exists to close.
        //
        // From the payload like every other lane. A placeholder
        // publishes no `ExactObject`, so this one is consistency, not
        // soundness -- but "what this materialization applies is
        // decided by its payload alone" is only a real invariant if
        // it holds everywhere, including where the stakes are low.
        plan.apply_payload_metadata(&out_path)?;
        Ok(settled.into())
    }
}
