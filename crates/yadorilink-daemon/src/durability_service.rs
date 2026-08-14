//! Owns this device's view of folder-group durability: which groups are
//! latched `Unknown` (a `--force` override bypassed the handoff
//! gate for that group and its status must not report `Protected` again
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
//!
//! # M4 canonical durability model
//!
//! `GroupDurabilityStatus` is this daemon's one authoritative "is this
//! group's data protected" derivation — every other surface (IPC/wire
//! DTOs, CLI, desktop app) must project from it rather than reconstructing
//! an equivalent judgment from lower-level booleans. Core invariant:
//! **Durability != Connectivity.** This module never reads
//! `PeerReachability`, relay route state, or any other connectivity
//! signal, and must never be changed to. A group being `Protected` says
//! nothing about whether it can be fetched *right now*; a peer being
//! online/reachable/relay-capable says nothing about whether this group is
//! `Protected`. See `crate::route::RelayCapability`'s own doc comment for the
//! parallel invariant on the connectivity side.
//!
//! `Protected` requires real peer-confirmed evidence
//! (`DaemonState::full_replica_handoff_ready`, an exact-version-hash,
//! generation-stability-checked round-trip -- this is ALSO how a
//! genuinely-empty group reaches `Protected`, since that function's own real
//! durability-root enumeration confirms a vacuous root set exactly like a
//! non-empty one; there is deliberately no separate "does this device's
//! local file count look like zero" shortcut, since that would miss
//! retained/trash-restorable durability roots). The evidence is cached
//! with a staleness bound (monotonic clock) AND a membership-generation
//! binding by `DurabilityConfirmationJob`'s periodic sweep -- either aging
//! out or any peer netmap change since the confirmation invalidates it.
//! This device's own local materialization completeness is never
//! sufficient on its own — that was the M4 audit's central finding: a
//! device with a fully materialized local copy and zero peer confirmation
//! used to report `Protected` regardless of whether any peer held the group
//! at all.

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
/// confirmation reports `Unknown`, never `Protected`.
///
/// See [`classify`] for how the unlatched default is derived, and
/// [`DurabilityService::latch_unknown`] for the one place that pins a group
/// to `Unknown` regardless of what it would otherwise derive to.
/// M4 canonical durability model: `Protected` (positively verified),
/// `Protecting` (verification work in progress), `Unknown` (cannot
/// currently prove either way), `AtRisk` (positively known insufficient).
/// Originally shipped under the names Healthy/Syncing/DurabilityUnknown/
/// KnownMissing (M4 Pass 1) and renamed to this vocabulary in M4 Pass 7,
/// once every call site (including the wire proto mirror) could be swept
/// in one pass rather than piecemeal.
///
/// Critical invariant, load-bearing across every derivation in this file:
/// `Protected`/`AtRisk` must be earned by *peer-confirmed* evidence or
/// a positively-known structural fact — never by this device's own local
/// state alone. "Durability != Connectivity": nothing here ever reads
/// `PeerReachability`/relay route state, and this device being reachable
/// or a peer being online never upgrades a group's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDurabilityStatus {
    /// Positively verified: the group has no current files at all (nothing
    /// to protect), or a confirmed peer full replica recently proved (via
    /// `DaemonState::full_replica_handoff_ready`, an exact-version-hash,
    /// generation-stability-checked peer round-trip) that it holds the
    /// group's entire current durability-root set. Never derived from this
    /// device's own local materialization state alone.
    Protected,
    /// This device is itself a full replica for this group and is still
    /// catching up to head (not every file materialized yet) — durability
    /// work in progress, not yet confirmed, not yet known insufficient.
    Protecting,
    /// Coverage cannot currently be confirmed — either a daemon-wide
    /// "cannot currently confirm" condition applies (latch-table load
    /// failure, unresolved unknown-scope removal, recovery-blocked
    /// membership operation, a `--force`-induced per-group latch), or no
    /// peer full replica is configured to have failed the structural
    /// `AtRisk` check but no fresh peer confirmation exists either
    /// (e.g. an On-Demand device whose only full-replica peer hasn't been
    /// reconfirmed since the last sweep). The fail-safe default whenever
    /// this daemon has no other basis to report from.
    Unknown,
    /// Positively known insufficient: no device other than this one is
    /// currently configured (netmap-derived) as an authorized-writer full
    /// replica for this group. Not "unconfirmed" — a structural fact that
    /// no amount of waiting for a peer round-trip will resolve on its own.
    AtRisk,
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
    /// `group_id` is pinned to `Unknown` in `DurabilityService`'s
    /// own latch table (a `--force` override bypassed the handoff gate for
    /// it), overriding whatever `materialization` would otherwise derive.
    pub latched_unknown: bool,
    /// This group's policy/membership snapshot is marked stale
    /// (`DaemonState::is_group_policy_stale`) -- the daemon has explicitly
    /// flagged that it cannot currently trust who is authorized to write
    /// or hold this group, so any cached peer confirmation may rest on an
    /// authorization this daemon no longer believes. Treated exactly like
    /// the other daemon-wide "cannot currently confirm" facts (M4 Codex
    /// review #1 finding #4).
    pub group_policy_stale: bool,
    /// This group's current materialization state, or `Err` if it
    /// couldn't even be read.
    pub materialization: Result<MaterializationHealth, ()>,
    /// This device's own storage mode for this group is a full replica
    /// (eager/"store everything") — the only case where local
    /// materialization state (`materialization`) is allowed to influence
    /// the result at all, and even then only to decide `Protecting`, never
    /// `Protected`.
    pub is_local_full_replica: bool,
    /// Netmap-derived, content-blind: at least one device other than this
    /// one is currently configured as an authorized-writer full replica
    /// for this group. `false` makes `AtRisk` a positively-known
    /// conclusion, not merely "not yet confirmed" -- but only once
    /// `ever_confirmation_swept` is also true (see that field's own doc
    /// comment for why).
    pub any_other_full_replica_peer_configured: bool,
    /// A whole-group peer-confirmed custody check
    /// (`full_replica_handoff_ready`) succeeded within this daemon's
    /// staleness bound and under the current membership generation. The
    /// ONLY source of `Protected` — see this module's doc comment for why
    /// local materialization state must never substitute for it. This is
    /// ALSO how a genuinely-empty group (nothing to protect) reaches
    /// `Protected`: `full_replica_handoff_ready`'s own real durability-root
    /// enumeration confirms a vacuous case exactly like a non-empty one,
    /// so there is no separate "group is empty" fact here — deriving
    /// emptiness from this device's own locally-visible file count would
    /// miss retained/trash-restorable durability roots (M4 Codex review #1
    /// finding #1).
    pub peer_confirmed_custody: bool,
    /// At least one `DurabilityConfirmationJob` sweep round has ever run
    /// for this group (regardless of whether it confirmed anything).
    /// `false` means this daemon hasn't checked yet at all -- distinct
    /// from "checked and found no confirming peer" -- so `classify` must
    /// not jump straight to the structural `AtRisk` conclusion
    /// before the very first sweep has even had a chance to run (M4 Codex
    /// review #1 findings #1/#2, most visible right after daemon startup).
    pub ever_confirmation_swept: bool,
}

/// Derives a group's durability status from `facts` alone, in the exact
/// precedence `DaemonState::group_durability_status` always has.
///
/// Precedence, in order — deliberately load-bearing, the actual
/// fail-*safe* property, not an implementation detail:
/// 1. Any daemon-wide/latched "cannot currently confirm" fact
///    (including `group_policy_stale`), or an unreadable materialization
///    read, wins outright -> `Unknown`.
/// 2. `peer_confirmed_custody` -> `Protected` (the ONLY path to `Protected`;
///    never local materialization alone, never merely "the group looks
///    empty locally").
/// 3. Not yet `ever_confirmation_swept` -> `Unknown` (haven't
///    checked at all yet — could still turn out empty or protected once
///    the first sweep runs; must not be reported as known-insufficient).
/// 4. No other full-replica peer configured -> `AtRisk` (positively
///    known insufficient, checked before falling back to "still catching
///    up" so a lone full replica with no peer never reports `Protecting` as
///    if a peer confirmation were merely pending).
/// 5. This device is itself a full replica still catching up locally ->
///    `Protecting`.
/// 6. Otherwise -> `Unknown` (a peer full replica is configured
///    but no fresh confirmation exists yet — e.g. an On-Demand device
///    waiting on the next confirmation sweep).
///
/// If real behavior and this precedence ever disagree, real behavior wins;
/// update this function (and its table-driven tests below) to match, not
/// the other way around.
pub fn classify(facts: &DurabilityFacts) -> GroupDurabilityStatus {
    if facts.latch_load_failed
        || facts.scope_unknown
        || facts.recovery_blocked
        || facts.latched_unknown
        || facts.group_policy_stale
        || facts.materialization.is_err()
    {
        return GroupDurabilityStatus::Unknown;
    }
    if facts.peer_confirmed_custody {
        return GroupDurabilityStatus::Protected;
    }
    if !facts.ever_confirmation_swept {
        return GroupDurabilityStatus::Unknown;
    }
    if !facts.any_other_full_replica_peer_configured {
        return GroupDurabilityStatus::AtRisk;
    }
    if facts.is_local_full_replica
        && matches!(facts.materialization, Ok(MaterializationHealth::Partial))
    {
        return GroupDurabilityStatus::Protecting;
    }
    GroupDurabilityStatus::Unknown
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

    /// Pins `group_id` to [`GroupDurabilityStatus::Unknown`],
    /// overriding whatever [`classify_unlatched`] would otherwise derive.
    /// Idempotent — latching an already-latched group is a no-op.
    pub fn latch_unknown(&self, group_id: &str) {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), GroupDurabilityStatus::Unknown);
    }

    /// Clears a previously-latched `Unknown` override for
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

    #[allow(clippy::too_many_arguments)]
    fn facts(
        latch_load_failed: bool,
        scope_unknown: bool,
        recovery_blocked: bool,
        latched_unknown: bool,
        group_policy_stale: bool,
        materialization: Result<MaterializationHealth, ()>,
        is_local_full_replica: bool,
        any_other_full_replica_peer_configured: bool,
        peer_confirmed_custody: bool,
        ever_confirmation_swept: bool,
    ) -> DurabilityFacts {
        DurabilityFacts {
            latch_load_failed,
            scope_unknown,
            recovery_blocked,
            latched_unknown,
            group_policy_stale,
            materialization,
            is_local_full_replica,
            any_other_full_replica_peer_configured,
            peer_confirmed_custody,
            ever_confirmation_swept,
        }
    }

    /// A full replica, fully caught up locally, with a peer confirmed and
    /// fresh, and at least one sweep round already run -- the base
    /// "everything checks out" case other cases tweak one field away from.
    fn protected_full_replica_facts() -> DurabilityFacts {
        facts(
            false,
            false,
            false,
            false,
            false,
            Ok(MaterializationHealth::FullyLocal),
            true,
            true,
            true,
            true,
        )
    }

    /// Table-driven pin of `classify`'s exact precedence, matched against
    /// `DaemonState::group_durability_status`'s real, current
    /// implementation at the time this was written -- see this module's
    /// own doc comment for why the ordering itself is the safety property
    /// being pinned, not just the individual outcomes.
    #[test]
    fn classify_matches_the_real_precedence() {
        let partial = Ok(MaterializationHealth::Partial);
        let unreadable = Err(());

        // latch_load_failed / scope_unknown / recovery_blocked / latched_unknown
        // each win outright, regardless of every other fact.
        assert_eq!(
            classify(&DurabilityFacts { latch_load_failed: true, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );
        assert_eq!(
            classify(&DurabilityFacts { scope_unknown: true, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );
        assert_eq!(
            classify(&DurabilityFacts { recovery_blocked: true, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );
        assert_eq!(
            classify(&DurabilityFacts { latched_unknown: true, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );
        // group_policy_stale wins outright too, even with an otherwise
        // fresh, current-generation peer confirmation -- an untrusted
        // authorization snapshot invalidates any confirmation it produced.
        assert_eq!(
            classify(&DurabilityFacts { group_policy_stale: true, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );
        // Unreadable materialization wins outright too, even with an
        // otherwise-confirmed peer.
        assert_eq!(
            classify(&DurabilityFacts { materialization: unreadable, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );

        // Fresh peer confirmation is Protected -- the ONLY path (whether it
        // came from a real full replica or a vacuous "group is empty"
        // confirmation is invisible at this layer; both set
        // peer_confirmed_custody the same way).
        assert_eq!(classify(&protected_full_replica_facts()), GroupDurabilityStatus::Protected);

        // Never swept yet (daemon just started, no round has run) must NOT
        // jump to AtRisk even with zero peers configured -- it
        // hasn't been checked, so it might turn out empty or protected.
        assert_eq!(
            classify(&DurabilityFacts {
                peer_confirmed_custody: false,
                any_other_full_replica_peer_configured: false,
                ever_confirmation_swept: false,
                ..protected_full_replica_facts()
            }),
            GroupDurabilityStatus::Unknown
        );

        // Local materialization alone, with NO peer confirmation, NO other
        // full-replica peer configured, but AT LEAST ONE sweep round
        // already run, must NOT be Protected -- this is the exact conflation
        // the M4 audit found and this derivation fixes. It's AtRisk:
        // structurally no peer can ever confirm it.
        assert_eq!(
            classify(&DurabilityFacts {
                peer_confirmed_custody: false,
                any_other_full_replica_peer_configured: false,
                ever_confirmation_swept: true,
                ..protected_full_replica_facts()
            }),
            GroupDurabilityStatus::AtRisk
        );

        // A peer IS configured but hasn't confirmed yet: Unknown for an
        // On-Demand device (materialization irrelevant to it)...
        assert_eq!(
            classify(&DurabilityFacts {
                peer_confirmed_custody: false,
                is_local_full_replica: false,
                materialization: partial,
                ..protected_full_replica_facts()
            }),
            GroupDurabilityStatus::Unknown
        );
        // ...but Protecting for a full-replica device still catching up
        // locally.
        assert_eq!(
            classify(&DurabilityFacts {
                peer_confirmed_custody: false,
                is_local_full_replica: true,
                materialization: partial,
                ..protected_full_replica_facts()
            }),
            GroupDurabilityStatus::Protecting
        );
        // A full-replica device that's ALREADY fully caught up locally but
        // has no fresh peer confirmation is Unknown, not Protected -- local
        // completeness alone never proves group-wide coverage.
        assert_eq!(
            classify(&DurabilityFacts { peer_confirmed_custody: false, ..protected_full_replica_facts() }),
            GroupDurabilityStatus::Unknown
        );
    }

    /// M4 acceptance requirement: an On-Demand client (not itself a full
    /// replica) whose group has a fresh peer-confirmed full replica must
    /// report `Protected` ("Protected") -- durability is a group-wide fact,
    /// never gated on THIS device's own local storage mode.
    #[test]
    fn on_demand_device_with_confirmed_peer_replica_is_protected() {
        let facts = DurabilityFacts {
            latch_load_failed: false,
            scope_unknown: false,
            recovery_blocked: false,
            latched_unknown: false,
            group_policy_stale: false,
            materialization: Ok(MaterializationHealth::Partial),
            is_local_full_replica: false,
            any_other_full_replica_peer_configured: true,
            peer_confirmed_custody: true,
            ever_confirmation_swept: true,
        };
        assert_eq!(
            classify(&facts),
            GroupDurabilityStatus::Protected,
            "an On-Demand device's own permanently-partial local materialization must never \
             prevent Protected once a peer positively confirms whole-group coverage"
        );
    }

    /// M4 acceptance requirement: a relay-reachable peer with no verified
    /// custody must never read as `Protected` -- this module has no way to
    /// even express "reachable" (no `DurabilityFacts` field for it), so
    /// this pins that a peer being configured/reachable is never, on its
    /// own, sufficient without `peer_confirmed_custody`.
    #[test]
    fn configured_peer_without_confirmation_is_not_protected() {
        let facts = DurabilityFacts {
            peer_confirmed_custody: false,
            any_other_full_replica_peer_configured: true,
            ..protected_full_replica_facts()
        };
        assert_ne!(
            classify(&facts),
            GroupDurabilityStatus::Protected,
            "a configured/reachable peer must never substitute for a real custody confirmation"
        );
    }

    #[test]
    fn latch_overrides_classify_regardless_of_facts() {
        let service = DurabilityService::new(HashMap::new());
        service.latch_unknown("group-1");
        assert_eq!(
            service.classify("group-1", protected_full_replica_facts()),
            GroupDurabilityStatus::Unknown,
            "a latched group must report Unknown even when every fact looks healthy"
        );
        service.clear_unknown("group-1");
        assert_eq!(
            service.classify("group-1", protected_full_replica_facts()),
            GroupDurabilityStatus::Protected,
            "clearing the latch must let the unlatched derivation decide again"
        );
    }
}
