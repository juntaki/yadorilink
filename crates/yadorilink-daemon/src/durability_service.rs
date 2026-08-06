//! Owns this device's view of folder-group durability: which groups are
//! latched `DurabilityUnknown` (a `--force` override bypassed the handoff
//! gate for that group and its status must not report `Healthy` again
//! until a real whole-group handoff re-check clears it), the pure
//! precedence [`classify`] applies to derive a group's status from the
//! facts `DaemonState` gathers, and the injectable custody confirmer the
//! on-demand eviction path uses to verify a specific version's blocks are
//! durably held elsewhere before reclaiming them locally.
//!
//! `group_durability_latch`/`custody_confirmer` are private, reached only
//! through this type's own methods. `classify` itself is a free function
//! taking plain facts, not a method, so it can be table-driven-tested in
//! isolation from any real `SyncState`/atomics -- `DaemonState::
//! group_durability_status` is the one place that gathers those facts and
//! calls it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::custody::CustodyStamp;

/// This device's local, UI-facing view of one group's durability — distinct
/// from the coordination-plane member/share count (which only tracks who is
/// *configured* to sync a group, not who durably holds its data right now)
/// and distinct from `DegradedLinkInfo` (that's disk
/// pressure, an orthogonal axis). Answers "how safe is my data right now,
/// from what this daemon can currently confirm" — and must never overstate
/// safety: a group this daemon has no current basis to back up with a real
/// confirmation reports `DurabilityUnknown`, never `Healthy`.
///
/// See [`classify`] for how the unlatched default is derived, and
/// [`DurabilityService::latch_unknown`] for the one place that pins a group
/// to `DurabilityUnknown` regardless of what it would otherwise derive to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDurabilityStatus {
    /// This device or a confirmed peer is a whole-group full replica for
    /// the group's current head.
    Healthy,
    /// Configured for this group but still catching up to head (not every
    /// file materialized yet).
    Syncing,
    /// Coverage cannot currently be confirmed — most notably, right after a
    /// `--force` override bypassed the durability handoff gate for this
    /// group, until a later handoff check positively reconfirms whole-group
    /// coverage. The fail-safe default whenever this daemon has no other
    /// basis to report from either.
    DurabilityUnknown,
    /// A current file is confirmed to have no durable holder reachable
    /// anywhere — a positive negative, not merely "unconfirmed."
    KnownMissing,
}

/// Whether every current file in a group is already fully materialized
/// locally, or some are still catching up -- `DaemonState`'s reduction of
/// `SyncState::materialization_counts`' richer result down to just what
/// [`classify`] needs, so this module doesn't depend on `SyncState`'s
/// counts type directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationHealth {
    /// Every current file is `Hydrated` locally.
    FullyLocal,
    /// At least one current file is still a placeholder or hydrating.
    Partial,
}

/// The complete set of inputs [`classify`] derives a group's durability
/// status from. `latched_unknown` comes from `DurabilityService`'s own
/// latch table (so `DurabilityService::classify` fills it in); every other
/// field comes from `DaemonState`'s own atomics or `SyncState`.
pub struct DurabilityFacts {
    /// The persisted durability-latch table itself failed to load at
    /// startup -- every group is unknown until that's resolved, since this
    /// daemon cannot tell which ones were actually latched.
    pub latch_load_failed: bool,
    /// A `--force` removal proceeded with an unverified blast radius —
    /// every group is potentially at risk until that scope is resolved,
    /// since there is no per-group latch to narrow this down to.
    pub scope_unknown: bool,
    /// A membership operation reached `RecoveryBlocked` — automatic
    /// recovery was refused, and this device cannot currently confirm
    /// whether the forced groups it names are durably latched.
    pub recovery_blocked: bool,
    /// `group_id` is pinned to `DurabilityUnknown` in `DurabilityService`'s
    /// own latch table (a `--force` override bypassed the handoff gate for
    /// it), overriding whatever `materialization` would otherwise derive.
    pub latched_unknown: bool,
    /// This group's current materialization state, or `Err` if it
    /// couldn't even be read.
    pub materialization: Result<MaterializationHealth, ()>,
}

/// Derives a group's durability status from `facts` alone, in the exact
/// precedence `DaemonState::group_durability_status` always has: each of
/// the four "cannot currently confirm" facts wins outright, in the order
/// listed, and only once none of them apply does the group's own
/// materialization state decide `Healthy` vs. `Syncing`.
///
/// This precedence is deliberately load-bearing: this is a fail-*safe*
/// default (a group this daemon has no current basis to vouch for must
/// never report `Healthy`), so the ordering itself -- every "cannot
/// confirm" fact short-circuits before the optimistic materialization
/// check ever runs -- is the actual safety property, not an implementation
/// detail. If real behavior and this precedence ever disagree, real
/// behavior wins; update this function (and its table-driven tests below)
/// to match, not the other way around.
pub fn classify(facts: &DurabilityFacts) -> GroupDurabilityStatus {
    if facts.latch_load_failed {
        return GroupDurabilityStatus::DurabilityUnknown;
    }
    if facts.scope_unknown {
        return GroupDurabilityStatus::DurabilityUnknown;
    }
    if facts.recovery_blocked {
        return GroupDurabilityStatus::DurabilityUnknown;
    }
    if facts.latched_unknown {
        return GroupDurabilityStatus::DurabilityUnknown;
    }
    match facts.materialization {
        Ok(MaterializationHealth::FullyLocal) => GroupDurabilityStatus::Healthy,
        Ok(MaterializationHealth::Partial) => GroupDurabilityStatus::Syncing,
        Err(()) => GroupDurabilityStatus::DurabilityUnknown,
    }
}

/// Confirms whether a full replica durably holds an exact file version — bound
/// by its `change::VersionHash`, with the ordered block list carried alongside
/// for the responder's explicit block/size check and `get()` verification —
/// so an on-demand device may reclaim its own cached copy. Injected onto
/// [`DurabilityService`] so production performs the peer-to-peer version-present
/// query while unit tests supply a deterministic answer without a live peer.
pub trait CustodyConfirmer: Send + Sync {
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp>;

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool;
}

#[cfg(test)]
impl<F: Fn(&str, &str, &VersionHash, &[VersionBlock]) -> bool + Send + Sync> CustodyConfirmer
    for F
{
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self(group_id, path, version_hash, blocks).then(|| CustodyStamp::new("test-peer".into(), 0))
    }

    fn confirmation_still_valid(&self, _group_id: &str, _stamp: &CustodyStamp) -> bool {
        true
    }
}

pub struct DurabilityService {
    custody_confirmer: Mutex<Option<Arc<dyn CustodyConfirmer>>>,
    group_durability_latch: Mutex<HashMap<String, GroupDurabilityStatus>>,
}

impl DurabilityService {
    pub(crate) fn new(
        persisted_durability_latches: HashMap<String, GroupDurabilityStatus>,
    ) -> Self {
        Self {
            custody_confirmer: Mutex::new(None),
            group_durability_latch: Mutex::new(persisted_durability_latches),
        }
    }

    /// Pins `group_id` to [`GroupDurabilityStatus::DurabilityUnknown`],
    /// overriding whatever [`classify_unlatched`] would otherwise derive.
    /// Idempotent — latching an already-latched group is a no-op.
    pub fn latch_unknown(&self, group_id: &str) {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), GroupDurabilityStatus::DurabilityUnknown);
    }

    /// Clears a previously-latched `DurabilityUnknown` override for
    /// `group_id`, if any -- a no-op if it wasn't latched.
    pub fn clear_unknown(&self, group_id: &str) {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(group_id);
    }

    pub fn is_latched_unknown(&self, group_id: &str) -> bool {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(group_id)
    }

    /// The full derivation for `group_id`: fills in `latched_unknown` from
    /// this service's own latch table, then applies [`classify`] to the
    /// complete facts. `facts.latched_unknown` is ignored (and should be
    /// left `false`) -- this method, not the caller, owns that fact.
    pub fn classify(&self, group_id: &str, mut facts: DurabilityFacts) -> GroupDurabilityStatus {
        facts.latched_unknown = self.is_latched_unknown(group_id);
        classify(&facts)
    }

    /// Installs the custody confirmer used by the on-demand reclamation
    /// gate -- production wires a peer-to-peer confirmer, tests inject a
    /// deterministic one so custody behavior can be exercised without a
    /// live peer.
    pub fn install_custody_confirmer(&self, confirmer: Arc<dyn CustodyConfirmer>) {
        *self.custody_confirmer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(confirmer);
    }

    /// Delegates to the installed [`CustodyConfirmer`]; with none installed
    /// (or none can confirm), returns `None`.
    pub fn confirm_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        let confirmer =
            self.custody_confirmer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        confirmer
            .and_then(|confirmer| confirmer.confirms_present(group_id, path, version_hash, blocks))
    }

    pub fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool {
        let confirmer =
            self.custody_confirmer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        confirmer.is_some_and(|confirmer| confirmer.confirmation_still_valid(group_id, stamp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        latch_load_failed: bool,
        scope_unknown: bool,
        recovery_blocked: bool,
        latched_unknown: bool,
        materialization: Result<MaterializationHealth, ()>,
    ) -> DurabilityFacts {
        DurabilityFacts {
            latch_load_failed,
            scope_unknown,
            recovery_blocked,
            latched_unknown,
            materialization,
        }
    }

    /// Table-driven pin of `classify`'s exact precedence, matched against
    /// `DaemonState::group_durability_status`'s real, current
    /// implementation at the time this was written -- see this module's
    /// own doc comment for why the ordering itself is the safety property
    /// being pinned, not just the individual outcomes.
    #[test]
    fn classify_matches_the_real_precedence() {
        let healthy = Ok(MaterializationHealth::FullyLocal);
        let partial = Ok(MaterializationHealth::Partial);
        let unreadable = Err(());

        let cases: &[(DurabilityFacts, GroupDurabilityStatus)] = &[
            // Every "cannot confirm" fact false, materialization decides.
            (facts(false, false, false, false, healthy), GroupDurabilityStatus::Healthy),
            (facts(false, false, false, false, partial), GroupDurabilityStatus::Syncing),
            (
                facts(false, false, false, false, unreadable),
                GroupDurabilityStatus::DurabilityUnknown,
            ),
            // latch_load_failed wins outright, regardless of the rest.
            (facts(true, false, false, false, healthy), GroupDurabilityStatus::DurabilityUnknown),
            (facts(true, true, true, true, healthy), GroupDurabilityStatus::DurabilityUnknown),
            // scope_unknown wins outright even with materialization healthy.
            (facts(false, true, false, false, healthy), GroupDurabilityStatus::DurabilityUnknown),
            // recovery_blocked wins outright even with materialization healthy.
            (facts(false, false, true, false, healthy), GroupDurabilityStatus::DurabilityUnknown),
            // latched_unknown wins outright even with materialization healthy.
            (facts(false, false, false, true, healthy), GroupDurabilityStatus::DurabilityUnknown),
        ];
        for (facts, expected) in cases {
            assert_eq!(
                classify(facts),
                *expected,
                "classify({:?}) should be {:?}",
                facts.materialization,
                expected
            );
        }
    }

    #[test]
    fn latch_overrides_classify_regardless_of_facts() {
        let service = DurabilityService::new(HashMap::new());
        service.latch_unknown("group-1");
        assert_eq!(
            service.classify(
                "group-1",
                facts(false, false, false, false, Ok(MaterializationHealth::FullyLocal))
            ),
            GroupDurabilityStatus::DurabilityUnknown,
            "a latched group must report DurabilityUnknown even when every fact looks healthy"
        );
        service.clear_unknown("group-1");
        assert_eq!(
            service.classify(
                "group-1",
                facts(false, false, false, false, Ok(MaterializationHealth::FullyLocal))
            ),
            GroupDurabilityStatus::Healthy,
            "clearing the latch must let the unlatched derivation decide again"
        );
    }
}
