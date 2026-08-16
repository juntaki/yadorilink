//! `MaterializationRepairJob` -- relocated byte-identically from this
//! crate's former `daemon_state::spawn_materialization_repair_scheduler`.
//! Periodic, daemon-wide live repair pass: for every non-orphaned link's
//! group, backfills any change history a policy-withheld initial import
//! omitted, then asks one connected peer (round-robin across
//! `materialization_repair_cursors`, so a slow/incomplete peer is never
//! selected forever) to reconcile this device's local materialization
//! audit against its own. Interval-only -- no startup-immediate run
//! (see the inventory's own "no new startup runs" constraint); this
//! job's sweep never ran at startup before this reorganization, and
//! still doesn't.
//!
//! Holds a full `Arc<DaemonState>` rather than a narrower bundle: its
//! real dependencies (`sync_state`, `peers`, `materialization_repair_
//! cursors`, `backfill_missing_change_history`) span daemon-wide
//! coordination state broader than any existing narrow port, and
//! inventing a new bespoke port for one job's sake would be exactly the
//! kind of speculative abstraction this pass is meant to avoid --
//! mirrors `LinkRuntimeController::start_inner`'s own periodic
//! materialization-repair task, which for the identical reason
//! (`DaemonState::root_lease_for`) also keeps a full `Arc<DaemonState>`
//! instead of the narrower `LinkRuntimeDependencies` bundle the rest of
//! that module tree uses.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::daemon_state::DaemonState;
use crate::maintenance::MaintenanceTrigger;

pub(crate) struct MaterializationRepairJob {
    state: Arc<DaemonState>,
}

impl MaterializationRepairJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    /// Read fresh on every call (mirrors `PeerSyncSession`'s own
    /// `resync_handle` loop reading `full_index_resync_interval()` fresh
    /// each time) rather than a `tokio::time::interval` fixed once at
    /// spawn time, so `set_materialization_repair_sweep_interval` takes
    /// effect on the very next sleep -- see
    /// `DaemonState::materialization_repair_sweep_interval`'s own doc for
    /// why a fixed-period interval would make that setter silently inert
    /// for an already-running daemon (every test call site).
    pub(crate) fn sweep_interval(&self) -> Duration {
        self.state.materialization_repair_sweep_interval()
    }

    pub(crate) async fn run_once(&self, _trigger: MaintenanceTrigger) {
        let state = &self.state;
        let groups: HashSet<String> = match state.replica_coordinator.link_repository().list_links()
        {
            // An orphaned link's coordination-side authorization is
            // confirmed gone, so there is no valid peer edge left to
            // request a repair from -- skip it the same way a paused
            // link's watcher already keeps it out of this set in
            // practice (no `LinkFlushHandle` to drive repair against).
            Ok(links) => {
                links.into_iter().filter(|link| !link.orphaned).map(|link| link.group_id).collect()
            }
            Err(e) => {
                tracing::warn!(error = %e, "materialization repair failed to list links");
                return;
            }
        };
        for group_id in groups {
            state.backfill_missing_change_history(&group_id).await;
            let candidates = state.peers.sessions_for_group(&group_id);
            if candidates.is_empty() {
                tracing::debug!(
                    local_device_id = %state.device_id,
                    group_id,
                    "materialization repair: no live peer sessions for this group this sweep"
                );
                continue;
            }
            let start = {
                let mut cursors =
                    state.materialization_repair_cursors.lock().unwrap_or_else(|p| p.into_inner());
                let cursor = cursors.entry(group_id.clone()).or_insert(0);
                let start = *cursor % candidates.len();
                *cursor = (start + 1) % candidates.len();
                start
            };
            // M5-A soak-closure durability investigation: full per-sweep
            // trace (ordered candidate list, cursor start, which peer got
            // asked, and that peer's own result) to distinguish real
            // round-robin starvation from genuinely unrepairable content --
            // see the tracked comment on `randomized_soak_converges_with_
            // no_leaks_or_stuck_state` in `topology_soak_lane.rs`.
            let ordered_candidates: Vec<&str> =
                candidates.iter().map(|(id, _)| id.as_str()).collect();
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id,
                ?ordered_candidates,
                start,
                "materialization repair: sweep starting"
            );
            // M5-A soak-closure durability investigation: stopping at the
            // first `Ok(_)` was a real starvation bug, not just an
            // efficiency choice -- `reconcile_local_materialization_audit`
            // returns `Ok(true)` for "the audit ran without an outer I/O
            // error", not "this device's materialization is now complete"
            // (a per-file `RetryRequired` is intentionally folded into
            // `Ok(())` inside `rematerialize_one_record`, since
            // re-candidacy is driven by `list_materialization_repair_
            // candidates`'s own DB state, not this return value). Soak
            // logs (seed 12552500466593081697) showed a full-replica
            // device asking the same first-in-list peer every sweep for
            // the entire run and never once trying its other two live
            // peers, because that first peer's audit reliably returned
            // `Ok(_)` (itself only partially materialized, so it had
            // nothing to contribute) and the loop broke immediately. Every
            // live candidate is now asked every sweep -- bounded by this
            // group's live session count, same as before -- so a peer that
            // actually holds the missing content is never starved out by
            // an earlier peer's no-op success.
            let mut any_ok = false;
            let mut last_error = None;
            for offset in 0..candidates.len() {
                let (peer_id, session) = &candidates[(start + offset) % candidates.len()];
                let result = session.clone().reconcile_local_materialization_audit(&group_id).await;
                tracing::debug!(
                    local_device_id = %state.device_id,
                    group_id,
                    peer = %peer_id,
                    offset,
                    ok = result.is_ok(),
                    "materialization repair: peer attempt finished"
                );
                match result {
                    Ok(_) => any_ok = true,
                    Err(e) => {
                        tracing::warn!(
                            group_id,
                            peer = %peer_id,
                            error = %e,
                            "materialization repair peer failed; trying another peer"
                        );
                        last_error = Some(e);
                    }
                }
            }
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id,
                any_ok,
                "materialization repair: sweep finished"
            );
            if !any_ok {
                if let Some(e) = last_error {
                    tracing::warn!(
                        group_id,
                        error = %e,
                        "materialization repair failed for every available peer"
                    );
                }
            }
        }
    }
}
