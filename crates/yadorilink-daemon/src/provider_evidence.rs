//! The evidence for what the OS holds of a provider root's items (design section 1).
//!
//! The OS owns the local copy, so the daemon never learns bytes or versions from it. It knows
//! three things, and only together do they say an item is PRESENT at its current version:
//!
//! 1. the LEDGER of its own verified handoffs (`provider_handoffs`): version V of the item was
//!    handed over, taking evidence sequence S. A version change that alters the content deletes
//!    the row in the same transaction as the commit (the OS drops its blocks on an update);
//! 2. MEMBERSHIP: the OS's materialized-items listing, reported by the host app. It carries item
//!    ids only (its version fields are empty), so it says whether the OS holds SOME local bytes,
//!    never which version. An item leaves it the moment an update lands;
//! 3. FRESHNESS: the report that listed the item must have begun after the handoff
//!    (`observed_after_seq >= S`), so an old snapshot is never combined with a newer handoff.
//!
//! plus: no publication of newer content is pending for the item. A missing snapshot (no host,
//! a restart, a rejected report) means nothing is present, never that something is.
//! `current_content_present` is true only when every one of them holds; a read error is false.

use std::collections::HashMap;
use std::sync::Mutex;

use yadorilink_ipc_proto::shellipc::{ProviderMaterializedReport, ProviderReportAck};
use yadorilink_sync_sqlite::provider::{ItemId, Publication};

use crate::application::ports::{LocalPresence, LocalTransition};
use crate::replica_coordinator::ReplicaCoordinator;

/// What the host last told us it holds locally, per root.
struct Snapshot {
    epoch: u64,
    last_seq: u64,
    /// The `observed_after_seq` the snapshot began with, raised by accepted deltas; a later report
    /// may never claim an earlier observation.
    observed_after: u64,
    /// False while the pages of a full snapshot are still arriving: nothing in it counts yet.
    complete: bool,
    /// When the host last sent an accepted report for this root.
    reported_at: std::time::Instant,
    /// item -> the `observed_after_seq` of the report that listed it.
    items: HashMap<ItemId, u64>,
}

#[derive(Default)]
struct Roots {
    snapshots: HashMap<String, Snapshot>,
    /// The highest epoch the host used per root, kept after a snapshot is dropped so an old
    /// epoch's full report cannot start over.
    highest_epoch: HashMap<String, u64>,
}

#[derive(Default)]
pub(crate) struct ProviderMembership {
    roots: Mutex<Roots>,
}

fn item_id(bytes: &[u8]) -> Option<ItemId> {
    ItemId::try_from(bytes).ok()
}

impl ProviderMembership {
    /// Applies one report of the attached host to the root's snapshot and answers it.
    /// `latest_issued` is the latest evidence sequence the daemon issued for the root: a report
    /// cannot claim to have observed after a sequence that does not exist.
    ///
    /// A report that breaks the protocol changes nothing and is answered `needs_full`:
    /// * a delta needs the same epoch, the very next sequence number and a complete snapshot;
    /// * a full report starts an epoch (strictly greater than any used before, sequence 1), or
    ///   continues the pages of the incomplete snapshot of its own epoch; a later full report in
    ///   an epoch, or an old epoch's, is a replay and never restores earlier membership;
    /// * `observed_after_seq` is at most `latest_issued` and never decreases within an epoch.
    pub(crate) fn apply(
        &self,
        report: &ProviderMaterializedReport,
        latest_issued: u64,
    ) -> ProviderReportAck {
        let root = hex::encode(&report.root_id);
        let mut state = self.roots.lock().unwrap_or_else(|p| p.into_inner());
        let answer = |accepted_seq: u64, needs_full: bool| ProviderReportAck {
            root_id: report.root_id.clone(),
            reporter_epoch: report.reporter_epoch,
            accepted_seq,
            needs_full,
        };
        let refused = || answer(0, true);
        if report.observed_after_seq > latest_issued {
            return refused();
        }
        let listed = || {
            report
                .upserts
                .iter()
                .filter_map(|item| item_id(&item.item_id))
                .map(|id| (id, report.observed_after_seq))
        };
        if report.full {
            // Another page of the snapshot this epoch is still building.
            if let Some(snapshot) = state.snapshots.get_mut(&root) {
                if snapshot.epoch == report.reporter_epoch
                    && !snapshot.complete
                    && report.report_seq == snapshot.last_seq + 1
                    && report.observed_after_seq == snapshot.observed_after
                {
                    snapshot.items.extend(listed());
                    snapshot.last_seq = report.report_seq;
                    snapshot.reported_at = std::time::Instant::now();
                    snapshot.complete = !report.more;
                    return answer(report.report_seq, false);
                }
            }
            let newest = state.highest_epoch.get(&root).copied().unwrap_or(0);
            if report.report_seq != 1 || report.reporter_epoch <= newest {
                return refused();
            }
            state.highest_epoch.insert(root.clone(), report.reporter_epoch);
            state.snapshots.insert(
                root,
                Snapshot {
                    epoch: report.reporter_epoch,
                    last_seq: 1,
                    observed_after: report.observed_after_seq,
                    complete: !report.more,
                    reported_at: std::time::Instant::now(),
                    items: listed().collect(),
                },
            );
            return answer(1, false);
        }
        match state.snapshots.get_mut(&root) {
            Some(snapshot)
                if snapshot.complete
                    && snapshot.epoch == report.reporter_epoch
                    && report.report_seq == snapshot.last_seq + 1
                    && report.observed_after_seq >= snapshot.observed_after =>
            {
                for id in report.removed.iter().filter_map(|b| item_id(b)) {
                    snapshot.items.remove(&id);
                }
                snapshot.items.extend(listed());
                snapshot.last_seq = report.report_seq;
                snapshot.observed_after = report.observed_after_seq;
                snapshot.reported_at = std::time::Instant::now();
                answer(report.report_seq, false)
            }
            _ => refused(),
        }
    }

    /// Forgets everything reported: with no host there is no evidence (the host connection ended
    /// or was replaced).
    pub(crate) fn clear(&self) {
        self.roots.lock().unwrap_or_else(|p| p.into_inner()).snapshots.clear();
    }

    /// Whether the root has a COMPLETE snapshot whose last accepted report is at most `max_age`
    /// old. A snapshot older than that says nothing about what the OS holds now.
    pub(crate) fn snapshot_is_fresh(&self, root_id: &str, max_age: std::time::Duration) -> bool {
        self.roots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshots
            .get(root_id)
            .is_some_and(|snapshot| snapshot.complete && snapshot.reported_at.elapsed() <= max_age)
    }

    /// The observation stamp of an item in the root's COMPLETE snapshot; `None` when it is not
    /// listed or there is no complete snapshot.
    fn stamp(&self, root_id: &str, item: &ItemId) -> Option<u64> {
        self.roots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshots
            .get(root_id)
            .filter(|snapshot| snapshot.complete)
            .and_then(|snapshot| snapshot.items.get(item).copied())
    }
}

/// Records a verified handoff and pushes the new evidence sequence to the host app, which echoes
/// it as `observed_after_seq` of the reports it begins afterwards. `None`: the handoff was not of
/// the current version (a stale claim) and nothing was recorded.
pub(crate) fn record_handoff(
    coordinator: &ReplicaCoordinator,
    host: &crate::provider_host_link::ProviderHostLink,
    root_id: &str,
    item: &ItemId,
    version: yadorilink_replica_domain::ids::VersionHash,
) -> Result<Option<u64>, crate::sync_error::SyncError> {
    let seq = coordinator.provider_repository().record_handoff(root_id, item, version)?;
    if let Some(seq) = seq {
        host.evidence_tick(root_id, seq);
    }
    Ok(seq)
}

/// What the daemon can honestly say the OS holds for an item: `object_present` is membership,
/// `current_content_present` is the full evidence rule. Any error reads as "not present".
pub(crate) fn provider_local_presence(
    coordinator: &ReplicaCoordinator,
    membership: &ProviderMembership,
    root_id: &str,
    item: &ItemId,
) -> LocalPresence {
    let none = LocalPresence {
        object_present: false,
        current_content_present: false,
        transition: LocalTransition::None,
    };
    // Membership: the OS holds some local bytes for the item.
    let Some(stamp) = membership.stamp(root_id, item) else { return none };
    let repo = coordinator.provider_repository();
    let object_only = LocalPresence { object_present: true, ..none };

    // Ledger: the daemon handed over the CURRENT version (an update that changed the content
    // already removed the row; a metadata-only update left a row naming an older version).
    let Ok(Some(handoff)) = repo.handoff(root_id, item) else { return object_only };
    match repo.current_version_hash(root_id, item) {
        Ok(Some(current)) if current == handoff.version_hash => {}
        _ => return object_only,
    }
    // Freshness: the report that listed the item began after the handoff.
    if stamp < handoff.evidence_seq {
        return object_only;
    }
    // No publication of newer content is pending.
    match repo.publication(root_id, item) {
        Ok(Some(Publication::ContentPending)) | Err(_) | Ok(None) => return object_only,
        Ok(Some(_)) => {}
    }
    LocalPresence { current_content_present: true, ..object_only }
}

#[cfg(test)]
mod tests;
