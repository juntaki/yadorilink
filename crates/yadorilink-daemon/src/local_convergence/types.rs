//! The vocabulary of local convergence: what a record turns into, what a
//! materialization decided, and the batching state a receive pass carries.
//!
//! These lived in `yadorilink-peer-session` because the code that used
//! them did. None of them describe a peer.

use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use yadorilink_local_storage::{reconstruct_file, verify_write_target_within_root};
use yadorilink_peer_session::hazard;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_root_authority::root_commit::RootCommitPermit;

/// Offloads a blocking call, and the handle it returns.
///
/// A three-line idiom, not a shared concept: kept here rather than
/// reaching across a crate boundary for `tokio::task::spawn_blocking`
/// with a different name.
pub(crate) type BlockingHandle<R> = tokio::task::JoinHandle<R>;

pub(crate) fn spawn_blocking<F, R>(f: F) -> BlockingHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

pub(crate) fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// The tuning the receive path used to read off `PeerSyncSession`.
pub(crate) struct Tuning;

impl Tuning {
    const BULK_ATTEMPT_WORST_CASE_SLOW_BLOCKS: u64 = 8;

    pub(crate) const BULK_FETCH_RESPONSE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(yadorilink_transport::PEER_IDLE_TIMEOUT.as_secs() + 10);
    pub(crate) const BULK_MATERIALIZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(
        Self::BULK_FETCH_RESPONSE_TIMEOUT.as_secs() * Self::BULK_ATTEMPT_WORST_CASE_SLOW_BLOCKS,
    );
    pub(crate) const FETCH_RESPONSE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(5);
    pub(crate) const MAX_COMMITS_IN_FLIGHT: usize = 2;
    pub(crate) const RECEIVE_COMMIT_BATCH_BLOCKS: usize = 256;
    pub(crate) const RECEIVE_COMMIT_BATCH_BYTES: u64 = 16 * 1024 * 1024;
}

/// a per-(session, group) ceiling on how many blocks this
/// session will *eagerly* fetch and write for one folder group over its
/// lifetime — independent of, and in addition to, the per-message caps
/// above (those bound one large message; this bounds cumulative eager
/// admission across many smaller messages from the same connected peer,
/// e.g. a burst of change batches each just under the per-message cap).
/// Once exhausted, further records that would otherwise be eagerly
/// fetched fall back to writing a placeholder instead (the same behavior
/// as an `OnDemand` group) — content is not lost or refused forever, it's
/// simply not eagerly pulled beyond the budget; an explicit pin still
/// always fetches (a deliberate, user-initiated request bypasses this
/// admission budget, same as it already bypasses the materialization
/// policy check below). Resets when this session ends (a new connection
/// starts a fresh budget) — bounding how much any *one* session can push
/// onto local disk eagerly, not a permanent per-group ceiling (that's
/// `max_local_size_bytes`, reactive eviction, and (out of scope here)
/// the separate free-space headroom mechanism).
pub(crate) const MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION: u64 = 200_000;

/// the actual admission bookkeeping behind
/// `PeerSyncSession::admit_eager_blocks`, factored out as a free function
/// over an explicit `admission` map and `max_per_group` ceiling so it's
/// unit-testable (`eager_admission_tests` below) without constructing a
/// full `PeerSyncSession` (channel, state, store,...) just to exercise
/// pure counter bookkeeping that never touches any of those. Attempts to
/// admit `block_count` more blocks for `group_id`; on success the group's
/// cumulative counter is incremented by `block_count` and `true` is
/// returned, on failure (would exceed `max_per_group`) the counter is left
/// unchanged and `false` is returned — the caller falls back to a
/// placeholder instead of eagerly fetching.
pub(crate) fn admit_eager_blocks_impl(
    admission: &mut HashMap<String, u64>,
    group_id: &str,
    block_count: u64,
    max_per_group: u64,
) -> bool {
    let used = admission.entry(group_id.to_string()).or_insert(0);
    match used.saturating_add(block_count) {
        new_total if new_total <= max_per_group => {
            *used = new_total;
            true
        }
        _ => false,
    }
}

/// Cap on how many materialization-audit records are re-driven concurrently.
/// Bounded (not "spawn one task per record
/// unconditionally") for the same reason `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
/// bounds concurrently-spawned message handlers: a large audit shouldn't spawn
/// thousands of tasks — many of them concurrently awaiting a block-fetch
/// round trip from this same peer connection — all at once.
pub(crate) const MAX_CONCURRENT_RECONCILES: usize = 16;

/// How long a cached entry in `ignore_sets` is trusted before
/// `effective_ignore_set` reloads it from the group's live sync root — see
/// that field's own doc comment for the liveness gap this bounds.
pub(crate) const IGNORE_SET_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);

/// What [`super::LocalConvergenceExecutor::remove_for_tombstone`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TombstoneRemoval {
    /// Nothing is at the path any more (or nothing was).
    Removed,
    /// A directory stays at the path because it is not empty; `reason`
    /// says why, for status. `removable` is the identity of the directory
    /// when the delete was aimed at it -- that object goes once it is
    /// empty -- and `None` when no delete aimed at it (a directory where
    /// the index holds a file), which is kept for good.
    Retained {
        reason: &'static str,
        removable: Option<Box<yadorilink_root_authority::fs_identity::FileIdentity>>,
    },
}

/// `fetch_block_over_stream` already
/// knows, in the moment, whether a peer's response was an explicit
/// `dont_have` versus received-but-rejected (decompression failure, a
/// decompression-bomb bound exceeded) — this preserves that distinction
/// through to `fetch_block_raw`'s callers instead of collapsing both into
/// the same `None`, specifically so `ensure_blocks_present` can retry the
/// former (a transient race — the peer may simply not have finished
/// indexing/materializing this content yet) without also retrying the
/// latter (a bad/oversized/corrupt payload that won't become valid by
/// asking again — retrying it would only give a slow or malicious peer a
/// second, third, fourth chance to waste this device's time). `fetch_block`
/// (the existing public API, still used by `yadorilink-daemon`'s multi-peer
/// hydration dispatcher, which already has its own faster "try a different
/// peer" fallback for either case and doesn't need this distinction) keeps
/// collapsing both into `None`, unchanged.
/// Whether one `materialize` (or `materialize_dag_content_head`) call
/// actually settled its path, or merely deferred it. If `materialize`
/// returned plain `Ok(())` for BOTH "fully materialized" AND "wrote a
/// retriable Placeholder because an eager fetch could not get every block",
/// a caller treating any `Ok(())` as success (as the Convergence
/// Engine's per-job completion check does, one layer up) could
/// mark a job done while the actual content was never verified to match
/// the resolved winner. This distinction exists so a caller can tell the
/// two apart and never treat the latter as done.
/// Per-path settlement evidence: WHAT a path settled AS, not merely THAT
/// it settled. Threaded through `MaterializeResult::Settled` and
/// `ProjectionAttempt::settled` so the publication boundary
/// (`process_group`'s stable-frontier arm) can tell an exact physical
/// proof from a scheduler-level settlement -- only the former may ever
/// write `path_materialized_generations`
/// (`ReplicaCoordinator::dag_publish_materialized_generation_if_fence_
/// current`). `identity` is `Option`, not mandatory, matching the
/// persistence layer's own `Option<&FileIdentity>` (a real identity is
/// attached wherever cheaply available at the write site; its absence
/// never blocks a publication, since the CAS in `mutation_generation`
/// alone is what fences the evidence).
///
/// **What `ExactObject` actually claims (the target projection
/// contract)**: it does NOT mean "every field `FileVersion` carries is
/// byte-for-byte reproduced on disk." A `FileVersion`'s `version_hash`
/// is an authoritative LOGICAL identity -- `mtime_unix_nanos`,
/// `unix_mode`, and `xattrs` all participate in it regardless of which
/// device authored the version or which device eventually receives it,
/// precisely so a mtime-only edit is a distinct version, a `Some(0o755)`
/// mode survives a hop through a Windows peer with no Unix mode model of
/// its own, and the DAG's notion of "which version is this" never
/// changes depending on which platform happens to be looking at it.
/// Separately, each RECEIVING target has its own capability to
/// physically reproduce any one of those fields, and that capability is
/// what `ExactObject` is actually scoped to: it means "every field this
/// target is capable of representing physically matches disk, and every
/// field it is not capable of representing is still held, unmodified,
/// in the logical version this evidence's `version` hash names" -- never
/// silently dropped or replaced by an approximation, just not asserted
/// as physically present here. Three shapes recur per field, matching
/// the same "target-capability-aware, revalidated live rather than
/// cached forever" philosophy `yadorilink-root-authority::
/// fs_capabilities`'s own `CapabilityCache` already established for
/// filesystem capabilities generally:
/// - **Exact-required**: this target claims to support the field, so it
///   must be verified to physically match before this evidence may ever
///   be constructed. Content bytes and object kind are exact-required on
///   every target. Replicated xattrs are exact-required on Linux (the
///   one backend that actually attempts to apply them at all) --
///   `verify_replicated_xattrs_exact`'s Linux arm strictly re-reads disk
///   after every apply for exactly this reason, closing a real gap
///   `apply_xattrs`'s own best-effort syscalls left open (see its own
///   doc comment).
/// - **Not-applicable**: the field has no meaning for this receiving
///   platform's own model at all (`unix_mode: None` on the authoring
///   side, or Unix permission bits received by a platform with no
///   permission-bit model) -- there was never anything to compare.
/// - **Retained-only**: the field is part of the logical version and
///   this target is NOT expected to physically reproduce it, so its
///   physical state is simply never checked and never blocks
///   completion. `unix_mode` on a non-Unix target (`unix_mode_already_
///   matches_disk`'s own non-Unix arm) and replicated xattrs on any
///   non-Linux target (`verify_replicated_xattrs_exact`'s own non-Linux
///   arm) are both retained-only today -- a device that later syncs the
///   same version to a capable target can still reproduce the field
///   exactly, because the logical version itself never lost it.
///
/// `mtime` is intentionally NOT yet slotted into exact-required/
/// retained-only above: `stamp_mtime` already best-effort-applies it (a
/// `set_times` failure is not fatal to the write), but nothing currently
/// strict-verifies disk mtime the way xattrs now are, and a naive
/// nanosecond-equality check would be its own new bug -- filesystem
/// timestamp rounding/granularity is a real, separate problem (see
/// `yadorilink-root-authority::fs_identity::TimestampGranularity`, which
/// exists for the UNRELATED purpose of judging whether a birth-time can
/// discriminate a reused inode from a genuinely new one, and must never
/// be repurposed as an mtime tolerance window). Per-target mtime
/// fidelity (does this filesystem preserve nanosecond mtime exactly, or
/// quantize it, or not support setting it at all) is deferred to its own
/// follow-up design rather than folded in here; until then, mtime stays
/// authoritative in `version_hash` but is never itself a blocking
/// completion condition -- effectively retained-only everywhere, the
/// same safe default every other field starts from before a target
/// earns an exact-required upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementEvidence {
    /// Disk holds the exact DAG-desired object at the exact desired
    /// version, verified -- a real write, or the content-identical fast
    /// path's own verification. `mutation_generation` is the fence value
    /// this evidence is valid under: the bump's own return for a real
    /// write, or a content-identical verification's *snapshot* (never a
    /// bump, decision 3d) -- what the eventual publication CASes on.
    ExactObject {
        kind: RecordKind,
        version: VersionHash,
        // Boxed to keep this variant's size close to the other arms'
        // (clippy large_enum_variant): `FileIdentity` is comparatively
        // large and only this arm carries it.
        identity: Box<Option<yadorilink_root_authority::fs_identity::FileIdentity>>,
        mutation_generation: i64,
    },
    /// Disk holds the exact desired absence: a tombstone deletion
    /// completed, or verified already absent. Same `mutation_generation`
    /// contract as `ExactObject`.
    ExactAbsent { mutation_generation: i64 },
    /// Disk holds the directory the namespace requires at a path with no
    /// explicit entry of its own: live descendants need it as their
    /// container (and a File or Symlink the path's own heads name has been
    /// relocated beside it). Same `mutation_generation` contract as
    /// `ExactObject`.
    StructuralDirectory {
        identity: Box<Option<yadorilink_root_authority::fs_identity::FileIdentity>>,
        mutation_generation: i64,
    },
    /// A policy-authorized deferral: an on-demand placeholder was
    /// intentionally written. Closes the obligation via the EXISTING
    /// `MaterializationState::Placeholder`, never an exact record.
    PolicyPlaceholder,
    /// A hazard moved the record to `hold`; nothing was written. Closes
    /// via the EXISTING held-reason mechanism, never an exact record.
    HazardHeld { reason: String },
    /// An ignore-policy decision: this path is deliberately not projected.
    IgnoreExcluded,
    /// The path's entry is settled as deleted, but the directory at it
    /// stays on disk because it is not empty: it holds something this
    /// device does not replicate, or live descendants. Nothing in it was
    /// removed. Closes via the path's retained-directory record, never an
    /// exact record; `reason` is what that record says, for status.
    Retained { reason: String },
}

impl SettlementEvidence {
    /// The checked, publishable half of this evidence, if any -- `None`
    /// for every scheduler-level settlement
    /// (`PolicyPlaceholder`/`HazardHeld`/`IgnoreExcluded`), which has no
    /// `ExactActualState` to convert to at all. Also returns the
    /// `mutation_generation` a publication CASes on, since a caller always
    /// needs both together.
    pub fn as_exact_actual_state(
        &self,
    ) -> Option<(yadorilink_peer_session::ports::ExactActualState, i64)> {
        match self {
            SettlementEvidence::ExactObject { kind, version, identity, mutation_generation } => {
                Some((
                    yadorilink_peer_session::ports::ExactActualState::Object {
                        kind: *kind,
                        version: *version,
                        identity: identity.clone(),
                    },
                    *mutation_generation,
                ))
            }
            SettlementEvidence::ExactAbsent { mutation_generation } => Some((
                yadorilink_peer_session::ports::ExactActualState::Absent,
                *mutation_generation,
            )),
            SettlementEvidence::StructuralDirectory { identity, mutation_generation } => Some((
                yadorilink_peer_session::ports::ExactActualState::StructuralDirectory {
                    identity: identity.clone(),
                },
                *mutation_generation,
            )),
            SettlementEvidence::PolicyPlaceholder
            | SettlementEvidence::HazardHeld { .. }
            | SettlementEvidence::IgnoreExcluded
            | SettlementEvidence::Retained { .. } => None,
        }
    }

    /// The inverse of [`Self::as_exact_actual_state`]: builds the exact-
    /// outcome evidence an already-confirmed [`yadorilink_peer_session::ports::
    /// ExactActualState`] describes, for a caller (the zero-work-close
    /// pre-check) that obtained one WITHOUT going through an ordinary
    /// `materialize` attempt.
    pub fn from_exact_actual_state(
        state: yadorilink_peer_session::ports::ExactActualState,
        mutation_generation: i64,
    ) -> Self {
        match state {
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind,
                version,
                identity,
            } => SettlementEvidence::ExactObject { kind, version, identity, mutation_generation },
            yadorilink_peer_session::ports::ExactActualState::Absent => {
                SettlementEvidence::ExactAbsent { mutation_generation }
            }
            yadorilink_peer_session::ports::ExactActualState::StructuralDirectory { identity } => {
                SettlementEvidence::StructuralDirectory { identity, mutation_generation }
            }
        }
    }
}

/// Whether one `materialize` (or `materialize_dag_content_head`) call
/// actually settled its path, or merely deferred it. If `materialize`
/// returned plain `Ok(())` for BOTH "fully materialized" AND "wrote a
/// retriable Placeholder because an eager fetch could not get every block",
/// a caller treating any `Ok(())` as success (as the Convergence
/// Engine's per-job completion check does, one layer up) could
/// mark a job done while the actual content was never verified to match
/// the resolved winner. This distinction exists so a caller can tell the
/// two apart and never treat the latter as done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaterializeResult {
    /// This path's outcome is final for this attempt. See
    /// [`SettlementEvidence`] for what it settled AS -- `Settled` alone no
    /// longer says: a
    /// `PolicyPlaceholder`/`HazardHeld`/ `IgnoreExcluded` evidence is
    /// exactly the case this doc comment used to warn callers NOT to
    /// conflate with "content fully materialized and disk-verified", now
    /// made structurally impossible to conflate by carrying the
    /// distinction as data instead of as a comment.
    Settled(SettlementEvidence),
    /// This path is NOT done: an eager/pinned fetch could not obtain every
    /// block (a retriable `Placeholder` was written instead), a local
    /// reconstruct failed even after its own retries, the resolved
    /// version's blocks were not locally available to plan against at
    /// all, or a hazardous tombstone held/dropped without ever recording
    /// the pending deletion durably (see `Settled`'s own doc comment). A
    /// caller must retry, never treat this as success.
    RetryRequired,
}

/// What this path's on-disk state looked like when the local core decided it
/// could not finish without blocks.
///
/// This is a staleness signal and nothing else. It is deliberately not a
/// resumption point: it says only that the file this materialization is about
/// to write has not been touched since the request was raised, and it proves
/// nothing about hazards, containment, the index row, or any mutation fence.
/// Every one of those is read again from current state when the core is
/// re-entered. A fence that matches buys an early exit from an obviously
/// stale request; it never buys skipping a guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequirement {
    /// The path whose content is wanted.
    pub(crate) path: String,
    /// The path whose resolution DEMANDS this content.
    ///
    /// Equal to `path` for an ordinary record. For a conflict copy it is the
    /// SOURCE path the copy was derived from, because a copy is never
    /// something a user asked for by name -- it exists only because
    /// resolving the source produced it, and it inherits the source's demand
    /// rather than carrying one of its own.
    ///
    /// Carried explicitly rather than re-derived from `path`: a conflict
    /// copy's name encodes its origin, and parsing it back out would make a
    /// correctness decision depend on a display format.
    pub(crate) demand_path: String,
    /// The record naming the blocks to obtain. Carried so whoever satisfies
    /// this request needs nothing from the pass that raised it.
    pub(crate) record: FileRecord,
    /// The version `record` is, from the payload that raised this
    /// request. Carried for the same reason as `record`, and because a
    /// refusal recorded while trying to obtain this content has to be
    /// about the version that was being obtained -- recomputing it from
    /// the index row later asks a different question at a different
    /// moment.
    pub(crate) version_hash: VersionHash,
    /// `disk_race_fingerprint` for this record's target path, sampled before
    /// the request was handed out.
    pub(crate) observed_disk: Option<(u64, Option<std::time::SystemTime>, i64, i64)>,
}

/// What the local half of materialization concluded on its own.
///
/// The local core reaches exactly one of two ends: it finished, or this
/// record names content this device does not hold. It never chooses a peer,
/// never decides how hard to try, and never sees a transport error --
/// obtaining blocks is the session's half, and the core is re-entered from
/// the top afterwards rather than resumed.
#[derive(Debug)]
pub enum LocalMaterializeOutcome {
    /// Nothing further is needed from any peer.
    Concluded(MaterializeResult),
    /// This record names content this device does not hold. The session
    /// satisfies this over the block lane and calls the core again.
    NeedBlocks(BlockRequirement),
}

impl From<MaterializeResult> for LocalMaterializeOutcome {
    fn from(result: MaterializeResult) -> Self {
        Self::Concluded(result)
    }
}

/// Outcome of one `retire_conflict_copies_only` attempt for a group.
/// Exists so a generation-tracked caller (`engine_wrapper.rs`'s
/// `RetirementWake`) can tell "this pass genuinely verified the frontier
/// generation it targeted" from every way it might not have -- a plain
/// `bool`/`Result<(), _>` return collapsed all three into "ran" vs
/// "errored", which is exactly the shape that let a guard-busy skip get
/// treated as a completed pass (see `RetirementWake`'s own doc comment for
/// the resulting lost-wakeup bug this type closes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementAttempt {
    /// Every copy-shaped file this pass examined was either justified by
    /// the current frontier or successfully retired. Only this variant
    /// means the caller may call `RetirementWake::complete` for the
    /// generation this pass targeted. `retired` counts how many copies
    /// were actually removed (informational only, not part of the
    /// completion contract).
    Settled { retired: usize },
    /// `RetirementAuditGuard` contention: another retirement pass for this
    /// same group already holds it, so this pass did not run at all. Not
    /// an error -- that other pass's own retire step covers SOME
    /// evaluation of this group, but not necessarily the frontier
    /// generation this pass was asked to verify.
    Busy,
    /// The pass ran, but at least one copy's tombstone `materialize`
    /// returned `MaterializeResult::RetryRequired` or errored -- that
    /// copy's justification was never actually re-verified against the
    /// targeted frontier, so the pass as a whole did not settle it.
    RetryRequired,
    /// The pass ran and every copy it examined resolved cleanly, but this
    /// device's own admitted DAG frontier for the group was different
    /// after the pass than before it started -- see
    /// `retire_conflict_copies_only`'s own doc comment for exactly what is
    /// compared and why. Every decision this pass made (justified/
    /// unjustified, retire/retain) was made against SOME frontier that
    /// existed during the pass, but not provably the one the caller's
    /// generation was meant to verify, so it must not be treated as a
    /// completion of that generation -- not "undo what this pass did"
    /// (already-correct-for-some-real-frontier mutations are left as they
    /// are), but "do not trust this pass's verdict as final; run again
    /// against the CURRENT frontier."
    FrontierChanged,
}

/// The outcome of one `reconcile_group_paths` call, split into two
/// explicit, disjoint sets rather than a single "failed" set, so one
/// failure mode is structurally impossible: a path absent from
/// a single "failed" set reads as "succeeded", which is true only if every
/// branch that *doesn't* explicitly fail also explicitly records success. A
/// path this call never actually examined (an early-return branch nobody
/// remembered to record) would silently inherit "succeeded" for free. With two
/// explicit sets, a path in neither is a visible bug (see
/// `reconcile_paths_directly`'s caller-side handling), never a silent,
/// accidental success.
///
/// `settled`: this path's outcome is final for this attempt — content
/// verified to match the current resolution, a tombstone deletion completed
/// (or was already reflected), an ignore-policy decision, or a hazard/
/// on-demand placeholder correctly recorded as such. Keyed by path to a
/// [`SettlementEvidence`] rather than a bare
/// `BTreeSet<String>`, so a caller can tell WHAT a path settled as, not
/// merely that it did — strictly additive over the key set:
/// `is_settled`/`needs_retry`/`path_fully_resolved`/`merge` keep their
/// prior semantics over the same keys. Where an attempt acts on the same
/// path more than once (the fixpoint can revisit a path), inserting again
/// overwrites the earlier evidence — the LAST bump's evidence is the one
/// that survives, and an earlier one is never the one the
/// publication step CASes against.
///
/// `retry`: this path is NOT done and must be tried again — a real error,
/// an eager/pinned fetch that could not obtain every block, or this call
/// read a state (no live heads at all for a path it was asked to resolve)
/// it cannot currently make a positive claim about.
///
/// Every path this call is asked to resolve (`seed_paths`, plus every
/// conflict-copy/tombstone path the fixpoint derives from them) ends up in
/// EXACTLY one of these two sets — never both, never neither.
#[derive(Debug, Default, Clone)]
pub struct ProjectionAttempt {
    pub(crate) settled: std::collections::BTreeMap<String, SettlementEvidence>,
    pub(crate) retry: std::collections::BTreeSet<String>,
}

impl ProjectionAttempt {
    /// Whether `path` is in `settled` — the ONLY way a caller should ever
    /// decide a path succeeded. Never infer success from `path` simply not
    /// being in `retry`.
    pub fn is_settled(&self, path: &str) -> bool {
        self.settled.contains_key(path)
    }

    /// The settlement evidence recorded for `path`, if any — the
    /// publication boundary reads this to decide WHAT (if anything) to
    /// publish to `path_materialized_generations` for a settled path.
    pub fn evidence_for(&self, path: &str) -> Option<&SettlementEvidence> {
        self.settled.get(path)
    }

    /// Every settled path this attempt recorded, with its evidence — Stage
    /// 3's publication boundary (`process_group`'s stable-frontier arm)
    /// iterates this to decide, per path, what (if anything) to publish.
    pub fn settled_with_evidence(&self) -> impl Iterator<Item = (&str, &SettlementEvidence)> {
        self.settled.iter().map(|(path, evidence)| (path.as_str(), evidence))
    }

    /// Whether `path` is in `retry`.
    pub fn needs_retry(&self, path: &str) -> bool {
        self.retry.contains(path)
    }

    /// Whether any path in `retry` is a conflict copy derived from `path`
    /// -- a direct path is not itself done if the losing content it
    /// produced as a conflict copy still needs another attempt.
    fn any_retry_path_is_conflict_copy_of(&self, path: &str) -> bool {
        self.retry.iter().any(|p| yadorilink_replica_domain::conflict::is_conflict_copy_of(p, path))
    }

    /// Whether `path` is fully resolved by this attempt: settled AND no
    /// conflict copy derived from it is still outstanding in `retry`. This
    /// is the one predicate any caller (including `yadorilink-daemon`'s
    /// Convergence Engine) should use to decide a job for `path` is done —
    /// `is_settled` alone is not enough, since a seed path can settle while
    /// the losing content it produced at a derived conflict-copy path still
    /// needs another attempt (retiring a job on `is_settled` alone would
    /// silently drop the still-outstanding conflict-copy obligation).
    pub fn path_fully_resolved(&self, path: &str) -> bool {
        self.is_settled(path) && !self.any_retry_path_is_conflict_copy_of(path)
    }
}

/// One `put_prepared_batch` call's result: which requested hashes are now
/// durable, which arrived as bytes that did not hash to the key they were
/// requested under, and whether the commit itself failed.
///
/// `hashes` is the only source of provenance-eligible hashes on the
/// receive path. It is populated by the committing task itself, so a hash
/// cannot reach it without that task having returned from the store call
/// that made it durable.
pub(crate) struct CommittedBatch {
    pub(crate) hashes: Vec<Vec<u8>>,
    pub(crate) rejected: Vec<Vec<u8>>,
    pub(crate) error: Option<yadorilink_local_storage::StorageError>,
    /// `None` when no `ReconcileCallTimer` was attached to this call --
    /// the commit still happens, it just isn't attributed.
    pub(crate) elapsed: Option<std::time::Duration>,
}

/// One fetched, verified, not-yet-durable block, and which file asked for
/// it.
///
/// The `path`/`version_hex` ride along because a batch spans files: the
/// stale-refusal clear is keyed by `(group, path, version, peer)`, so a
/// batch that mixes three files' blocks has three refusals to clear, not
/// one. Carrying the key per block and deduplicating at commit time is
/// what keeps that correct without reintroducing a per-file barrier.
pub(crate) struct PendingBlock {
    pub(crate) hash: Vec<u8>,
    pub(crate) data: Bytes,
    pub(crate) path: String,
    pub(crate) version_hex: String,
}

/// Fetched blocks waiting to be made durable, and the commits carrying
/// them, pooled ACROSS the files of one reconciliation pass.
///
/// Pooling across files rather than within one is the whole point. A
/// tiny-file workload is exactly one block per file, so a pool scoped to a
/// single file can never batch anything: 2000 files of one block each
/// produced 2000 batches of one and therefore 2000 durability barriers,
/// measured end to end on two real daemons. The block store's group commit
/// cannot help a caller that hands it one block at a time, and the local
/// capture path had already learned this -- `ScanBlockStaging` pools across
/// files for the same reason.
pub(crate) struct ReceiveCommitPool {
    /// The group every block in this pool belongs to. A pool spans files,
    /// never groups: the refusal key and the provenance write are both
    /// group-scoped, and mixing groups would make one batch's success
    /// attest to the wrong one.
    pub(crate) group_id: String,
    /// The pass's cross-file dedup set, recorded into at COMMIT time.
    ///
    /// It has to be here rather than borrowed per file, because the file
    /// that fetched a block is usually not the one whose batch commits it.
    /// Recording at fetch time instead would be wrong in the unsafe
    /// direction: a second file would skip re-fetching a block that is
    /// still only pending, and a failed batch would leave it believing it
    /// holds content that was never written.
    pub(crate) reconcile_batch: Option<Arc<ReconcileProvenanceBatch>>,
    /// Hashes this pass has already fetched, whether or not their batch
    /// has committed yet.
    ///
    /// Deferring the commit must not also defer the dedup. Two files
    /// sharing a block are usually fetched before either one's batch
    /// lands, so a dedup that consulted only committed state would fetch
    /// the same block over the network twice. Skipping the second fetch is
    /// safe because it grants nothing: provenance still comes only from
    /// `durable`, so if the batch fails neither file is publishable and
    /// both are re-fetched on a later pass.
    pub(crate) fetched: std::collections::HashSet<Vec<u8>>,
    pub(crate) pending: Vec<PendingBlock>,
    pub(crate) pending_bytes: u64,
    pub(crate) commits: FuturesUnordered<BlockingHandle<CommittedBatch>>,
    /// Hashes from batches that have already returned `Ok`. This is the
    /// only source of provenance-eligible hashes: a hash reaches it after
    /// the write it attests to is durable, never before.
    pub(crate) durable: Vec<Vec<u8>>,
    /// First fatal error across every commit in this pass.
    pub(crate) fatal: Option<PeerSessionError>,
    /// A peer returned bytes that did not hash to the key they were asked
    /// for, or a commit failed. Either way this pass cannot claim every
    /// block it fetched is now held.
    pub(crate) lost_content: bool,
}

impl ReceiveCommitPool {
    pub(crate) fn new(
        group_id: &str,
        reconcile_batch: Option<Arc<ReconcileProvenanceBatch>>,
    ) -> Self {
        Self {
            group_id: group_id.to_string(),
            reconcile_batch,
            fetched: std::collections::HashSet::new(),
            pending: Vec::new(),
            pending_bytes: 0,
            commits: FuturesUnordered::new(),
            durable: Vec::new(),
            fatal: None,
            lost_content: false,
        }
    }
}

/// Materializes a non-deleted symlink
/// record at `group_id`/`record.path` under `root`. Factored out as a
/// free function (explicit `state`/`root`/`group_id`/`record` rather than
/// a `PeerSyncSession` receiver) purely for direct unit-testability — the
/// same reason `index_message_exceeds_cardinality_cap`/
/// `admit_eager_blocks_impl` above are free functions: a symlink record
/// carries no blocks at all, so materializing one needs no
/// peer/channel access whatsoever, unlike ordinary file
/// materialization/hydration.
///
/// **Wire schema**: `proto::FileInfo` (`yadorilink-ipc-proto`) carries
/// no `record_kind`/`symlink_target` field,
/// so a peer's incoming index message cannot yet actually tell this
/// device "this path is a symlink". Routing is therefore decided by the
/// *payload's* `record_kind` (`payload.version().meta.record_kind`),
/// which for a wire-sourced payload is this device's own already-recorded
/// classification, folded into the payload once at its construction
/// (`MaterializationPayload::from_wire`) rather than re-read from the row
/// at each decision point. That distinction is the whole point: the row
/// can move between the dispatch, the write and the proof; the payload
/// cannot. Wiring a peer's advertised kind through to that construction
/// is the natural extension seam; until then, this function is real,
/// tested, and ready, but a symlink genuinely cannot cross the wire from
/// a peer that classified it during section 2's scan/watch path on a
/// *different* device.
pub(crate) struct SymlinkMaterialization<'a> {
    pub(crate) state: &'a crate::replica_coordinator::ReplicaCoordinator,
    pub(crate) root: &'a Path,
    pub(crate) group_id: &'a str,
    pub(crate) windows_opt_in: bool,
    pub(crate) origin_device_id: &'a str,
    pub(crate) authoring_change_hash: Option<&'a ChangeHash>,
    pub(crate) permit: &'a RootCommitPermit<'a>,
}

/// What `materialize_symlink_at` actually accomplished on disk. A bare
/// `Ok(())` cannot mean "a physical symlink now exists matching the
/// desired version": three of this function's own branches (no target
/// recorded; a Windows peer that has not opted in; no symlink model on
/// this platform at all) write nothing whatsoever, and treating them as
/// success would promote a policy skip or a locally-known data gap to a
/// claimed exact physical write. Only [`Self::WrittenExact`] may ever be used to
/// construct `SettlementEvidence::ExactObject`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SymlinkMaterializeOutcome {
    /// A real, physical symlink now exists at `out_path`, matching the
    /// desired version's recorded target -- `mutation_generation` is the
    /// fence value this function's own bump (immediately before the
    /// symlink-creation syscall) produced, for the caller to publish
    /// `ExactObject` evidence under. Deliberately owned by this function,
    /// not the caller: a caller bumping the fence UNCONDITIONALLY before
    /// calling this function would, on a `PolicySkipped` outcome (a
    /// durable, permanently-retried condition), bump the generation again
    /// on every single retry forever, with no mutation ever actually
    /// occurring -- perpetual, pointless generation churn. Bumping only on
    /// the branch that actually mutates something prevents that.
    /// `written` is the version this write put on disk, read before the
    /// syscall so the caller never has to infer it from a row that may
    /// have moved since.
    WrittenExact { mutation_generation: i64, written: Box<FileVersion> },
    /// The index row was updated, but nothing was written to disk by
    /// policy (no target recorded for a symlink-classified record, a
    /// Windows peer that has not opted in to real symlink
    /// materialization, or a platform with no symlink model at all).
    /// Never eligible for `ExactObject`. The caller (see its own call site's
    /// doc comment) maps this to `MaterializeResult::RetryRequired`, which
    /// leaves the obligation row outstanding under the SAME ordinary,
    /// capped-backoff retry mechanism a transient failure gets -- not a
    /// dedicated liveness sweep the way `HazardHeld`/`IgnoreExcluded` have.
    /// That capped backoff (currently 30s) is what actually re-examines this
    /// condition once its blocking cause (no Windows opt-in, no recorded
    /// target) changes; there is no other re-arm path for it.
    PolicySkipped,
    /// The symlink was written, but the commit recording it was refused,
    /// so nothing was committed: no proof, no `Hydrated`, and the
    /// materialization intent is still open.
    ///
    /// Two different refusals land here, and this outcome does not say
    /// which: another mutator advanced this path's fence after this write
    /// bumped it, or the row no longer names the version this write was
    /// built from (a supersession, which moves the version without moving
    /// the fence). Both mean the same thing to the caller.
    ///
    /// Never eligible for `ExactObject`. The bytes on disk may well be
    /// right, but this attempt can no longer prove they are what the path
    /// currently wants, and evidence published for it would settle an
    /// obligation against a claim nothing can verify. The
    /// caller maps this to the same capped-backoff retry a transient
    /// failure gets; the still-open intent is what records that a write
    /// really did happen.
    CommitRejected,
}

pub(crate) fn materialize_symlink_at(
    context: SymlinkMaterialization<'_>,
    record: &FileRecord,
    // The version these bytes are, from the payload that produced them.
    // The link target written below comes from the same version's own
    // metadata, so "target from V1, version from V2" is not expressible.
    written_version: &FileVersion,
) -> Result<SymlinkMaterializeOutcome, PeerSessionError> {
    let SymlinkMaterialization {
        state,
        root,
        group_id,
        windows_opt_in,
        origin_device_id,
        authoring_change_hash,
        permit,
    } = context;
    let out_path = root.join(&record.path);
    // A free function, not a `PeerSyncSession` method, so it cannot go
    // through `self.verify_write_target` (which already orders these
    // the same way) -- re-verify directly here for the same reason that
    // method does: a colliding long-running eager sync could see this
    // root's mountpoint unmounted and replaced between the record's own
    // admission and this write. This MUST run before
    // `verify_write_target_within_root` below, not after: that call is
    // not a pure check, it `create_dir_all`s `root` and `out_path`'s
    // parent as a side effect, so calling it first would create
    // directories on a possibly-wrong replacement volume before its
    // identity has even been confirmed.
    state.verify_root(root, group_id)?;
    // defense-in-depth, same as every other materialization
    // write path in this module — see `verify_write_target_within_root`'s
    // doc comment.
    verify_write_target_within_root(
        &out_path,
        root,
        &yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
            state, group_id,
        ),
    )?;

    // From the version being written, not from the row. This used to be
    // `state.get_symlink_target(group_id, &record.path)` directly under a
    // comment claiming the target came from the same version the proof
    // names -- the comment was the intent and the code was the bug. A
    // supersession between the caller's payload and this read would point
    // the link at V2's target and publish V1's proof, and `version_hash`
    // bakes the target in, so the proof would be false about exactly the
    // byte string this function just wrote.
    let target = written_version.meta.symlink_target.clone();
    #[cfg(unix)]
    let write_eligible = target.is_some();
    #[cfg(windows)]
    let write_eligible = target.is_some() && windows_opt_in;
    #[cfg(not(any(unix, windows)))]
    let write_eligible = false;

    // Crash-safety: committing the index row FIRST and only then
    // attempting the physical write, with no durable intent, would leave
    // (after a crash between the two) a row claiming this path is a
    // symlink with no physical symlink on disk and nothing durable to tell
    // startup/periodic repair "this was an interrupted write, not an
    // offline deletion" (`materialization_repair.rs` examines symlink rows
    // for exactly this reason). The owner operation
    // below opens the intent BEFORE the row commit, mirroring the
    // regular-file seam exactly, and bumps the mutation fence alongside
    // it; both precede the actual write below, and both are skipped
    // together when nothing will actually be written (no recorded target,
    // or a Windows peer that has not opted in): there is no crash window
    // to protect when no mutating syscall will ever occur. The CALLER
    // must not bump unconditionally before invoking this function, which
    // would keep advancing the generation on every retry of a permanently-
    // skipped symlink with no mutation ever occurring -- see
    // `SymlinkMaterializeOutcome::WrittenExact`'s own doc comment. It then
    // upserts the row unless this exact authored version is already
    // current, and marks an eligible write in flight.
    let write_target = if write_eligible { target.as_deref() } else { None };
    let (mutation_generation, intent_guard) = match state.open_symlink_write(
        group_id,
        record,
        origin_device_id,
        authoring_change_hash,
        write_target,
        permit,
    )? {
        Some((mutation_generation, intent_guard)) => {
            (Some(mutation_generation), Some(intent_guard))
        }
        None => (None, None),
    };
    // The caller's payload version. Reading it from the row -- at any
    // point, before or after the syscall -- asks about the row, and the
    // target written below came from somewhere else entirely, so the two
    // could describe different versions of this path.
    let written = written_version.clone();

    if !write_eligible {
        if target.is_none() {
            // No target recorded for a record classified as a symlink —
            // there is nothing safe to create. The index row is still
            // updated above (so a later correction still syncs
            // normally), but skip the on-disk write rather than create a
            // broken/empty link.
            tracing::warn!(
                path = %record.path,
                group_id,
                "symlink record has no recorded target; skipping on-disk materialization"
            );
        }
        // The remaining `!write_eligible` case (Windows, not opted in) is
        // a deliberate, visible policy skip -- see this struct's own
        // `windows_opt_in` field doc comment.
        return Ok(SymlinkMaterializeOutcome::PolicySkipped);
    }
    let target = target.expect("write_eligible is only true when target.is_some()");

    #[cfg(unix)]
    {
        let _ = windows_opt_in; // only meaningful on Windows
        yadorilink_local_storage::materialize_symlink(&out_path, &target)?;
    }
    #[cfg(windows)]
    yadorilink_local_storage::materialize_symlink_windows(&out_path, &target)?;

    let mutation_generation =
        mutation_generation.expect("write_eligible implies the fence was bumped above");

    // The symlink now genuinely exists on disk under this exact name.
    // Everything this write proved is recorded in ONE durable step: the
    // versioned generation under the epoch this write itself produced,
    // the `Hydrated` stamp, and the intent clear.
    //
    // This deliberately does not go through the external-adoption path
    // (`adopt_local_capture_actual_state`), which mints a fresh epoch of
    // its own -- so this writer, having just bumped the fence to `N`,
    // advanced it to `N+1` on its way to recording what it did, and the
    // caller's own `ExactObject` evidence (which CASes on the `N` returned
    // below) could then never win. It also published a versionless row,
    // and because the resolved-path-state hash encodes version presence,
    // such a proof matches no desired resolution at all. The two together
    // meant a symlink's obligation could never close: the link was correct
    // on disk and re-materialized forever.
    //
    // The intent is cleared by that same commit rather than before the
    // observation. Clearing first would leave a window where the link
    // exists, nothing records that a write was in flight, and no proof
    // has landed yet. Dropping the guard unclear is safe -- it has no
    // `Drop` behaviour of its own; the commit below owns the clear.
    let version = written.version_hash;
    let identity =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).ok();
    if !state.commit_internal_materialized_state_if_fence_current(
        group_id,
        &record.path,
        yadorilink_peer_session::ports::ExactActualState::Object {
            kind: yadorilink_replica_domain::file::RecordKind::Symlink,
            version,
            identity: Box::new(identity),
        },
        mutation_generation,
        // Guarded on the row this write was built from. The fence CAS
        // alone catches a competing physical mutator and says nothing
        // about a DAG-side supersession, which moves the version without
        // moving the fence -- so an unguarded commit could stamp
        // `Hydrated` and publish for a version this path had already
        // left, with the link on disk still pointing at the old one.
        Some(yadorilink_peer_session::ports::ExpectedAuthoring {
            state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
            authoring_change_hash,
            expected_version: Some(&version),
        }),
        permit,
    )? {
        // Refused: either the fence moved or the row names another
        // version. Nothing was written -- no proof, no `Hydrated`, and
        // the intent is still open -- so report this as a retry rather
        // than an exact write, which would settle an obligation against
        // evidence the store just refused.
        drop(intent_guard);
        return Ok(SymlinkMaterializeOutcome::CommitRejected);
    }
    drop(intent_guard);
    Ok(SymlinkMaterializeOutcome::WrittenExact { mutation_generation, written: Box::new(written) })
}

/// If `record`'s block list is byte-identical
/// to what's already indexed locally for this path (content provably
/// unchanged — the same block hashes, in the same order, describe both),
/// this applies just the owner-executable bit currently recorded in the
/// local index for the path and updates the index row's own
/// version/mtime/deleted bookkeeping — without calling
/// `ensure_blocks_present` or `reconstruct_file` at all, i.e. without any
/// network round trip or full-file rewrite. Returns whether the fast path
/// applied; `false` means the caller must fall through to ordinary
/// fetch/reconstruct handling (no local record existed yet for this path,
/// the content actually changed, or the file is unexpectedly missing from
/// disk — see the disk/index divergence note below).
///
/// See `materialize_symlink_at`'s doc comment for the same wire-schema
/// caveat: `proto::FileInfo` has no exec-bit field yet, so
/// "the bit this applies" is this device's own already-recorded value for
/// the path, not literally something read off the incoming wire message.
/// This is still exactly the mechanism the receiving side needs — once a
/// peer's advertised bit is wired through to a `set_unix_mode` call ahead
/// of reconciliation, this fast path picks it up correctly with no
/// further changes.
///
/// This fast path assumes the
/// file is still sitting on disk from whenever it was last actually
/// written (this function itself never writes content) — that assumption
/// can be false (e.g. a real local deletion raced this incoming record,
/// with the local watcher/debounce pipeline not having indexed that
/// deletion yet). The disk-existence check below runs *before* the index
/// write commits, specifically so a stale-but-plausible-looking local
/// index row can never be refreshed into a permanently wrong "hydrated
/// and present" state — falling through to the caller's ordinary
/// reconstruct path (which actually (re)writes the file) is always safe
/// here, just slower than the fast path in the common case. The previous
/// version of this function instead committed the index write first and
/// only discovered a missing file afterward, incidentally, via
/// `apply_unix_mode`'s Unix-only `fs::metadata` call — whose error was
/// silently logged and discarded by the caller (`reconcile_one_file`'s
/// own caller, a `tracing::warn!` with no rollback), and which never
/// fired at all on Windows (`apply_unix_mode` is a no-op there), making
/// the corruption completely silent on that platform.
/// Returns `Ok(None)` when this path is not eligible for the fast path at
/// all (falls through to the caller's ordinary reconstruct path); `Ok(Some(
/// mutation_generation))` when it was handled here, carrying the fence
/// value the caller's own evidence must be published under. That value is
/// a BUMP, not a snapshot, whenever applying `unix_mode`/`xattrs` would
/// genuinely change anything on disk: `chmod`/`fsetxattr`/`fremovexattr`
/// are real mutating syscalls exactly like a content write is, and the
/// physical-mutation fence must be bumped before the first one of them,
/// never after -- treating this metadata repair as a pure verification
/// (a snapshot) when it can still write real bytes to the inode would
/// leave a stale publication un-invalidated by exactly the mutation this
/// fence exists to detect. Only when metadata already, verifiably, matches
/// disk (checked read-only, before any syscall that could change it) is
/// this a true zero-mutation verification eligible for a snapshot.
/// Whether `out_path`'s TERMINAL path component is a genuine regular
/// file, checked without following it (`symlink_metadata`, not
/// `metadata`) -- `false` for a symlink, a directory, any other object
/// kind, or a path that does not exist at all.
///
/// `verify_write_target_within_root`/
/// `verify_write_target` only confirm `out_path`'s PARENT directory
/// chain resolves inside the sync root -- correct for the temp-then-
/// rename primitive every OTHER write path in this module uses (`rename`
/// replaces the terminal component itself, symlink or not), but the two
/// "content already matches, only touch metadata" fast paths that call
/// this are different: `disk_bytes_match_indexed_blocks`/`apply_xattrs`
/// both `File::open(out_path)`, and `apply_unix_mode` reads `fs::
/// metadata` then `set_permissions(out_path)` -- every one of those
/// follows a terminal symlink. If a local actor or a race replaces
/// `out_path` itself with a symlink to a file outside the sync root, and
/// that outside file's bytes happen to match the stale-but-still-indexed
/// blocks, nothing in either fast path would otherwise notice before a
/// chmod/xattr syscall lands on the OUTSIDE target. A residual TOCTOU
/// window remains between this check and the actual syscalls below it --
/// the same accepted "Low / TOCTOU" class of residual `verify_write_
/// target_within_root`'s own doc comment already documents for the
/// intermediate-component case; fully eliminating it would mean opening
/// `out_path` once with `O_NOFOLLOW` and reusing that one fd for
/// hashing/`fchmod`/`fsetxattr`, deferred as a stronger hardening pass
/// rather than folded into this fix.
pub(crate) fn terminal_object_is_a_regular_file(out_path: &Path) -> bool {
    std::fs::symlink_metadata(out_path).map(|m| m.file_type().is_file()).unwrap_or(false)
}

pub(crate) fn try_apply_metadata_only_update(
    state: &crate::replica_coordinator::ReplicaCoordinator,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    authoring_change_hash: Option<&ChangeHash>,
    // The version this update is applying, from the caller's payload. The
    // metadata written below comes from it too, so what lands on disk and
    // what the proof will name are the same decision.
    desired_version: &FileVersion,
    permit: &RootCommitPermit,
) -> Result<Option<MetadataOnlyUpdate>, PeerSessionError> {
    let Some(local) = state.get_file(group_id, &record.path)? else { return Ok(None) };
    if local.deleted || record.blocks.is_empty() || local.blocks != record.blocks {
        return Ok(None);
    }
    let out_path = root.join(&record.path);
    // Re-verify root identity before `verify_write_target_within_root`
    // below, not just once right before the chmod further down: that
    // call is not a pure check, it `create_dir_all`s `root` and
    // `out_path`'s parent as a side effect, so calling it first would
    // create directories on a possibly-wrong replacement volume before
    // its identity has even been confirmed, even though this function
    // may still return `Ok(None)` afterward without ever reaching the
    // chmod.
    state.verify_root(root, group_id)?;
    verify_write_target_within_root(
        &out_path,
        root,
        &yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
            state, group_id,
        ),
    )?;
    // See `terminal_object_is_a_regular_file`'s own doc comment for the full
    // reasoning: fail closed here instead. A terminal symlink is never
    // eligible for this fast path (falls through to the ordinary
    // reconstruct path via `Ok(None)`, which is the temp-then-rename
    // primitive and therefore safe).
    if !terminal_object_is_a_regular_file(&out_path) {
        return Ok(None);
    }
    // The index can get ahead of the disk when a prior materialization wrote
    // its row and then failed. Existence alone is also insufficient: a stale
    // or partially-written file at this path must take the normal reconstruct
    // path, not be accepted as a metadata-only update.
    //
    // A file whose mode denies its owner read access cannot have its bytes
    // verified either. It must not fall through to the ordinary path: on an
    // OnDemand group that path replaces a hydrated file with a placeholder,
    // and an owner-writable, unreadable file can hold an edit the scanner
    // never saw. Nor can its replicated metadata be read back or set. This
    // is reported before anything is mutated (no upsert, no fence bump) as
    // `MetadataUnprovable`, which the caller turns into a hold -- neither a
    // raw permission error that fails everything around it, nor a
    // replacement, nor a retry that can only fail the same way.
    match yadorilink_local_storage::disk_bytes_match_indexed_blocks(&out_path, &record.blocks) {
        Ok(true) => {}
        Ok(false) => return Ok(None),
        Err(yadorilink_local_storage::StorageError::Io(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            return Err(PeerSessionError::MetadataUnprovable(record.path.clone()));
        }
        Err(error) => return Err(error.into()),
    }
    // Re-verify here, after the hash step: `disk_bytes_match_indexed_blocks`
    // above can take real time hashing every block of a large file, and a
    // root swap, or an intermediate/terminal symlink substitution, during
    // that window must not go undetected right up to the point this
    // function mutates whatever is now at `out_path`. Mirrors the
    // equivalent re-check `materialize()`'s own metadata-only fast path
    // performs after its identical hash step (see that call site's own
    // comment): re-verify root identity and containment, then refuse the
    // fast path entirely (falling through to the safe temp-then-rename
    // reconstruct path via `Ok(None)`) if the terminal component is no
    // longer a genuine regular file -- the same fail-closed check this
    // function already ran once above, now re-run after the slow read
    // rather than trusted from before it.
    state.verify_root(root, group_id)?;
    verify_write_target_within_root(
        &out_path,
        root,
        &yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
            state, group_id,
        ),
    )?;
    if !terminal_object_is_a_regular_file(&out_path) {
        return Ok(None);
    }
    match authoring_change_hash {
        Some(hash) => state.upsert_file_with_origin_and_author(
            group_id,
            record,
            origin_device_id,
            hash,
            permit,
        )?,
        None => state.upsert_file_with_origin(group_id, record, origin_device_id, permit)?,
    }
    // From the version this update applies, not from the row it just
    // upserted. These two lines used to be `state.get_unix_mode` /
    // `state.get_xattrs`, with `let _ = desired_version;` at the bottom
    // of the function -- the parameter was plumbed in and then discarded,
    // so the doc comment above ("the metadata written below comes from
    // it too") described an intent the body did not implement. Reading
    // the row back after the upsert looks equivalent and is not: a
    // supersession landing between the two applies V2's mode and xattrs
    // while this call settles under V1's `version_hash`, which bakes both
    // in.
    let unix_mode = desired_version.meta.unix_mode;
    let xattrs = desired_version.meta.xattrs.clone();
    // A read-only comparison, before any syscall that could change either:
    // only when NEITHER would actually change anything is this genuinely a
    // zero-mutation verification.
    //
    // This fast path must not decide snapshot-vs-bump from
    // unix_mode/xattrs alone, ignoring mtime -- otherwise a same-content,
    // mtime-ONLY-changed version (an ordinary "touch") could settle as `ExactObject` under the NEW
    // version's `version_hash` (which bakes in the new mtime) without
    // ever attempting to stamp the new mtime onto disk at all. mtime
    // stays retained-only (never a completion-blocking exactness
    // requirement -- see `SettlementEvidence::ExactObject`'s own doc
    // comment), but "retained-only" was never meant to mean "never even
    // attempted on a target that can actually set it" -- that's exactly
    // the treatment `unix_mode`/`xattrs` already get here (applied when
    // possible, just not strictly blocking if the target can't). Folded
    // into the same bump-vs-snapshot decision, not a separate one: an
    // mtime-only change is still a real mutating syscall attempt and
    // must bump the fence first like any other, per the same "bump
    // before the first mutating syscall, no exceptions" invariant
    // unix_mode/xattrs already follow.
    let metadata_already_matches_disk =
        yadorilink_local_storage::unix_mode_already_matches_disk(&out_path, unix_mode)?
            && yadorilink_local_storage::xattrs_already_match_disk(&out_path, &xattrs)?
            && yadorilink_local_storage::mtime_already_matches_disk(
                &out_path,
                desired_version.meta.mtime_unix_nanos,
            )?;
    let (mutation_generation, xattr_evidence) = if metadata_already_matches_disk {
        // Nothing is written: what disk holds must be proved from disk.
        (state.dag_snapshot_mutation_fence(group_id, &record.path)?, XattrEvidence::ReproveFromDisk)
    } else {
        let fence = state.dag_bump_mutation_fence(group_id, &record.path, "metadata_repair")?;
        // The mtime stamp opens the file, so it goes before the final mode,
        // which may deny the owner read access (0o200). Neither the
        // attributes nor the mode change the mtime afterwards.
        yadorilink_local_storage::stamp_mtime_at_path(
            &out_path,
            desired_version.meta.mtime_unix_nanos,
        )?;
        let applied =
            yadorilink_local_storage::apply_file_metadata_verified(&out_path, unix_mode, &xattrs)?;
        (fence, XattrEvidence::from(applied))
    };
    require_xattr_evidence(&record.path, &out_path, &xattrs, &xattr_evidence)?;
    Ok(Some(MetadataOnlyUpdate { mutation_generation, xattrs: xattr_evidence }))
}

/// Whether the regular file already at `out_path` denies its owner read
/// access -- the one condition under which its replicated metadata can be
/// neither read back nor set (a `user.*` attribute needs the file opened
/// for reading). Asked before any mutation, never after: the answer
/// decides whether a repair may start at all. A missing file is not
/// "unreadable"; the caller's ordinary handling decides what that means.
pub(crate) fn existing_file_is_owner_unreadable(out_path: &Path) -> Result<bool, PeerSessionError> {
    match std::fs::File::open(out_path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        // A storage error, not a bare `Io`: it belongs to this path alone.
        Err(error) => Err(yadorilink_local_storage::StorageError::Io(error).into()),
    }
}

/// A metadata-only update that took effect: the fence it ran under, and the
/// xattr evidence it already checked, for a caller that builds the
/// `ExactObject` from it (so a file this update just made unreadable is not
/// re-read).
#[derive(Debug)]
pub(crate) struct MetadataOnlyUpdate {
    pub(crate) mutation_generation: i64,
    pub(crate) xattrs: XattrEvidence,
}

/// Shared with every other proof-publishing writer; see its own doc comment.
pub(crate) use yadorilink_local_storage::XattrEvidence;

/// The xattr half of the `ExactObject` gate, for either source of evidence.
/// An in-attempt confirmation counts only for the exact path and attribute
/// set it was taken for; anything else is not evidence for this claim.
pub(crate) fn require_xattr_evidence(
    path: &str,
    out_path: &Path,
    desired_xattrs: &[(String, Vec<u8>)],
    evidence: &XattrEvidence,
) -> Result<(), PeerSessionError> {
    evidence.prove(out_path, desired_xattrs).map_err(|refused| {
        tracing::debug!(
            path,
            ?refused,
            "the replicated extended attributes are not proven to match the desired version; \
             refusing to settle as exact"
        );
        PeerSessionError::ReplicatedXattrsNotExact(path.to_string())
    })
}

/// The `ExactObject` proof gate every path that constructs one after
/// applying replicated extended attributes must pass through: a strict,
/// on-disk reread (`yadorilink_local_storage::verify_replicated_xattrs_
/// exact`) of what `path` actually holds right now, compared against
/// what the desired version specifies. `FileVersion`'s content-addressed
/// identity bakes replicated xattr bytes directly into `version_hash`
/// (see `FileVersion::compute_hash`), so an `ExactObject` proof that
/// disagrees with what disk can actually be confirmed to hold would be a
/// false claim -- and `apply_xattrs` itself never surfaces a
/// `fsetxattr`/`fremovexattr` failure as an `Err` (deliberately
/// best-effort at the syscall layer), so nothing upstream of this check
/// would otherwise ever catch one.
///
/// Both of `verify_replicated_xattrs_exact`'s failure outcomes -- a
/// confirmed mismatch, and a real I/O failure enumerating or reading an
/// attribute on the Linux backend that can actually attempt the
/// comparison -- collapse to the same `ReplicatedXattrsNotExact` error
/// on purpose: both mean the same thing to every caller here, which is
/// "do not settle this as exact," never "the write itself failed." A
/// caller's own error handling maps that, like any other
/// materialize-time error, to leaving the obligation outstanding for
/// retry. A backend with no replicated-xattr support at all never
/// reaches this error path -- see `verify_replicated_xattrs_exact`'s
/// own non-Linux arm, which treats xattrs as retained-only there
/// (target projection contract, see `SettlementEvidence::ExactObject`'s
/// own doc comment) rather than blocking completion on a field this
/// target was never expected to physically reproduce.
pub(crate) fn require_replicated_xattrs_exact(
    path: &str,
    out_path: &Path,
    desired_xattrs: &[(String, Vec<u8>)],
) -> Result<(), PeerSessionError> {
    match yadorilink_local_storage::verify_replicated_xattrs_exact(out_path, desired_xattrs) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PeerSessionError::ReplicatedXattrsNotExact(path.to_string())),
        Err(e) => {
            tracing::debug!(
                path,
                error = %e,
                "could not confirm replicated extended attributes exactly match the desired \
                 version; refusing to settle as exact"
            );
            Err(PeerSessionError::ReplicatedXattrsNotExact(path.to_string()))
        }
    }
}

/// The `ExactObject` proof gate against a claimed object kind actually
/// disagreeing with what physically exists at `out_path`:
/// `FileIdentity::observe_path(...).ok()`
/// alone silently accepts `None` (no disk object at all), and nothing
/// upstream confirmed a `RegularFile`/`Symlink`/`Directory` claim against
/// what materialize's own write actually produced. Symlink metadata is
/// read (never followed) so a dangling symlink is correctly identified
/// as a symlink, not as "does not exist."
pub(crate) fn require_physical_kind_matches(
    path: &str,
    out_path: &Path,
    kind: RecordKind,
) -> Result<(), PeerSessionError> {
    let observed_kind = match std::fs::symlink_metadata(out_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Some(RecordKind::Symlink),
        Ok(metadata) if metadata.file_type().is_dir() => Some(RecordKind::Directory),
        Ok(metadata) if metadata.file_type().is_file() => Some(RecordKind::File),
        Ok(_) | Err(_) => None,
    };
    if observed_kind == Some(kind) {
        return Ok(());
    }
    tracing::warn!(
        path,
        ?kind,
        ?observed_kind,
        "the physical object kind on disk does not match the version's claimed record kind; \
         refusing to settle as exact"
    );
    Err(PeerSessionError::PhysicalKindMismatch(path.to_string()))
}

/// `reconstruct_file` does synchronous `std::fs` I/O for EVERY block
/// in `blocks` (a `store.get` read plus a `write_all`), then a final
/// `sync_all` (fsync) on the assembled temp file and again on its parent
/// directory. Every OTHER call in this file that does comparable
/// synchronous block-store I/O already routes through `spawn_blocking`
/// (`handle_block_request`'s `store.get`, `ensure_blocks_present`'s `store
/// ::put` -- see their own identical doc comments), but `reconstruct_file`
/// itself did not, until now: it ran directly on whatever tokio worker
/// thread happened to be executing the calling async task.
///
/// For a small file this is a few milliseconds, unnoticeable. For a large
/// single-file transfer this call can run long enough (confirmed: a real
/// clean-loopback `yadorilink-bench L1 --two-process` run at 4+ GiB) to
/// starve OTHER work sharing this process's fixed-size tokio worker pool --
/// including this SAME peer's own transport tasks. Observed directly on the
/// transport that preceded this one: timer-driven work silently not polled
/// for seconds at a stretch, then firing bunched together once the starved
/// tasks got a scheduling turn again -- symptoms of tasks that stopped being
/// *polled*, not of any packet actually lost on the wire (`nstat -az
/// UdpRcvbufErrors` stayed flat through the runs where this fix's absence
/// was confirmed, ruling out the kernel socket buffer as the cause).
/// Starvation long enough to exhaust the transport's own recovery forces a
/// reconnect, whose retry/materialize work can re-trigger this exact same
/// blocking call again -- a self-sustaining cycle that, left unfixed, never
/// let a large transfer's connection stay up long enough to converge.
pub(crate) async fn reconstruct_file_off_runtime(
    store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    out_path: &std::path::Path,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
    mtime_unix_nanos: i64,
) -> Result<(), PeerSessionError> {
    let out_path = out_path.to_path_buf();
    let blocks = blocks.to_vec();
    match spawn_blocking(move || {
        reconstruct_file(store.as_ref(), &out_path, &blocks, mtime_unix_nanos)
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(join_err) => Err(PeerSessionError::from(std::io::Error::other(format!(
            "reconstruct_file blocking task panicked: {join_err}"
        )))),
    }
}

/// The "assemble" half of [`reconstruct_file_off_runtime`], run off
/// the async runtime for the identical reason -- see that function's doc
/// comment. Used by `prepare_ordinary_projected_upsert` to do the slow,
/// network-fetch-bound block assembly with no path lock held at all.
pub(crate) async fn reconstruct_file_to_temp_off_runtime(
    store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    out_path: &std::path::Path,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
    mtime_unix_nanos: i64,
) -> Result<std::path::PathBuf, PeerSessionError> {
    let out_path = out_path.to_path_buf();
    let blocks = blocks.to_vec();
    match spawn_blocking(move || {
        yadorilink_local_storage::reconstruct_file_to_temp(
            store.as_ref(),
            &out_path,
            &blocks,
            mtime_unix_nanos,
        )
    })
    .await
    {
        Ok(Ok(tmp_path)) => Ok(tmp_path),
        Ok(Err(e)) => Err(e.into()),
        Err(join_err) => Err(PeerSessionError::from(std::io::Error::other(format!(
            "reconstruct_file_to_temp blocking task panicked: {join_err}"
        )))),
    }
}

/// The "publish" half -- run off the async runtime for the same
/// reason `reconstruct_file_off_runtime` is: this still does a real
/// syscall (rename + directory fsync), and `try_commit_ordinary_batch`
/// calls it while holding this batch's path locks, so it must not block
/// the runtime's worker thread any more than any other write branch does.
pub(crate) async fn persist_reconstructed_file_off_runtime(
    tmp_path: &std::path::Path,
    out_path: &std::path::Path,
) -> Result<(), PeerSessionError> {
    let tmp_path = tmp_path.to_path_buf();
    let out_path = out_path.to_path_buf();
    match spawn_blocking(move || {
        yadorilink_local_storage::persist_reconstructed_file(&tmp_path, &out_path)
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(join_err) => Err(PeerSessionError::from(std::io::Error::other(format!(
            "persist_reconstructed_file blocking task panicked: {join_err}"
        )))),
    }
}

/// Cross-file provenance batching (follow-up to the per-file
/// batching that removed the ORIGINAL one-`record_group_block_
/// provenance`-transaction-per-block amplification): dedup evidence
/// shared across every `ensure_blocks_present_collecting` call within ONE
/// `reconcile_group_paths` invocation's ordinary-reconciliation
/// preparation loop.
///
/// Holds every hash a candidate in THIS call has already durably `store.
/// put`, whether its own `record_group_block_provenance` flush has
/// actually committed yet or not. This is deliberately NOT the flush
/// mechanism itself -- the actual SQL writes happen separately, once per
/// bounded (`ORDINARY_BATCH_MAX_PATHS`-sized) commit chunk, inside `try_
/// commit_ordinary_batch`, using each `PreparedProjectedUpsert`'s own
/// attached `newly_fetched_block_hashes` -- this type exists ONLY so a
/// LATER file in the same reconciliation window that references a block
/// an EARLIER file already fetched this same window can recognize it as
/// already-held without re-fetching it over the network purely because
/// the earlier file's own flush hasn't committed to SQL yet. A hash must
/// never be recorded here before its own `store.put` has actually
/// returned success -- see `ensure_blocks_present_core`'s own call sites.
///
/// `Mutex`-guarded rather than `&mut`: `ensure_blocks_present_core` fetches
/// several blocks of ONE file concurrently via `FuturesUnordered`, so
/// concurrent inserts/reads within a single file's own call are possible,
/// even though different files' `prepare_ordinary_projected_upsert` calls
/// are always sequential (the per-path loop in `reconcile_group_paths`
/// awaits each one before starting the next).
pub(crate) struct ReconcileProvenanceBatch {
    known: std::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
}

impl ReconcileProvenanceBatch {
    pub(crate) fn new() -> Self {
        Self { known: std::sync::Mutex::new(std::collections::HashSet::new()) }
    }

    pub(crate) fn already_known(&self, hash: &[u8]) -> bool {
        self.known.lock().unwrap_or_else(|p| p.into_inner()).contains(hash)
    }

    /// Records a hash whose `store.put` has already succeeded. Idempotent.
    pub(crate) fn record(&self, hash: Vec<u8>) {
        self.known.lock().unwrap_or_else(|p| p.into_inner()).insert(hash);
    }
}

/// One item accumulated by `reconcile_group_paths`'s per-path loop
/// for a bounded, batched commit via `PeerSyncSession::
/// try_commit_ordinary_batch`, instead of the unbatched per-path
/// `materialize_dag_content_head`/`materialize` call every other path
/// still takes.
pub(crate) enum OrdinaryBatchItem<'a> {
    /// The `Box<dyn Send + 'a>` is the same block-write-activity guard
    /// `prepare_ordinary_projected_upsert` acquired before fetching this
    /// upsert's blocks -- kept alive here so it is still held when `try_
    /// commit_ordinary_batch` later commits this upsert's row, matching
    /// the unbatched `materialize_dag_content_head`'s single guard held
    /// across its whole call. Never inspected, only kept alive; dropped
    /// once this item is consumed (committed or dropped to retry).
    // `PreparedProjectedUpsert` boxed to keep this variant's size close to
    // `Delete`'s (clippy large_enum_variant).
    Upsert(Box<dyn Send + 'a>, Box<yadorilink_peer_session::ports::PreparedProjectedUpsert>),
    /// `(path, tombstone_author, derived_head)` -- mirrors the synthetic
    /// tombstone `FileRecord` reconcile_group_paths' own Absent branch
    /// builds for the unbatched case, minus the record itself (rebuilt
    /// fresh once this item is revalidated, since it never carries a
    /// payload beyond the path itself). `tombstone_author` is only a HINT
    /// from the unlocked classification pass -- `try_commit_ordinary_
    /// batch` re-derives the real one fresh under its lock (see its own
    /// Delete-handling doc comment for why the hint alone is not safe to
    /// commit on). `derived_head` must travel with this item for the same
    /// reason `PreparedProjectedUpsert` carries one: a pure conflict-copy
    /// path's fresh re-resolution under the batch's lock needs it to see
    /// any live head at all.
    Delete(String, ChangeHash, Option<PathHead>),
}

impl OrdinaryBatchItem<'_> {
    pub(crate) fn path(&self) -> &str {
        match self {
            OrdinaryBatchItem::Upsert(_, u) => &u.rel_path,
            OrdinaryBatchItem::Delete(path, ..) => path,
        }
    }
}

/// Bounded retry
/// parameters for a `reconcile_one_file` call failing transiently — see
/// its call site's doc comment (the `in_flight.spawn` dispatch loop) for
/// the specific race this is sized for. Same shape as the
/// `NOT_FOUND_RETRY_*` constants used for block-fetch retries
/// (bounded attempts, fixed delay with jitter to avoid synchronized retry
/// bursts) — free functions/constants rather than `PeerSyncSession`
/// associated items since the retry loop lives inside a `'static`
/// `tokio::spawn`'d closure, not a `&self` method.
pub(crate) const RECONCILE_RETRY_ATTEMPTS: u32 = 5;

const RECONCILE_RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

const RECONCILE_RETRY_JITTER_FRACTION: f64 = 0.25;

/// `reconcile_group_paths`'s own diagnostic threshold for "the conflict-copy
/// fixpoint derived a lot more paths than its seed window" — every caller
/// bounds its seed-path window to a small count (the Convergence Engine's
/// `MAX_PATHS_PER_RECONCILE_ATTEMPT`, currently 8), so a derived-path count
/// well past that is worth a log line even though it's not truncated (see
/// that check's own doc comment for why). Not tied to any specific caller's
/// window size — just a fixed, generous magnitude past which "the fixpoint
/// grew a lot" is worth surfacing.
pub(crate) const UNUSUALLY_LARGE_CONFLICT_COPY_FIXPOINT_THRESHOLD: usize = 32;

pub(crate) fn reconcile_retry_delay() -> std::time::Duration {
    let jitter =
        rand::random_range(-RECONCILE_RETRY_JITTER_FRACTION..=RECONCILE_RETRY_JITTER_FRACTION);
    RECONCILE_RETRY_BASE_DELAY.mul_f64(1.0 + jitter)
}

/// What the volume this path is about to land on folds together.
///
/// The two axes are probed and applied separately because they do not
/// necessarily move together -- see `hazard::is_normalization_insensitive_
/// filesystem`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VolumeFolding {
    pub case_insensitive: bool,
    pub normalization_insensitive: bool,
}

impl VolumeFolding {
    /// Whether this volume can fold two distinct names onto one file at
    /// all. When it cannot, no sibling can collide with anything, so the
    /// caller has no reason to go and read them.
    pub(crate) fn folds_anything(self) -> bool {
        self.case_insensitive || self.normalization_insensitive
    }
}

/// Whether `path` collides with something already indexed beside it, given
/// what the volume folds.
///
/// Takes the siblings and the volume's behaviour as values so the decision
/// can be exercised for a volume the machine running the test does not
/// have. Both axes are properties of the target filesystem, so a
/// state-backed version of this can only ever be tested on a host that
/// already folds the way the case under test needs -- which meant the
/// case-fold and normalization cases silently skipped on every
/// case-sensitive Linux runner, the platform they most need to keep
/// working for a peer that syncs *to* macOS.
pub(crate) fn hazard_reason_for_siblings(
    path: &str,
    volume: VolumeFolding,
    siblings: &[FileRecord],
) -> Option<String> {
    if volume.case_insensitive {
        if let Some(colliding) = hazard::case_fold_collision(path, siblings) {
            return Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_CASE_COLLISION,
                colliding.path
            ));
        }
    }
    if volume.normalization_insensitive {
        if let Some(colliding) = hazard::normalization_collision(path, siblings) {
            return Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_NORMALIZATION_COLLISION,
                colliding.path
            ));
        }
    }
    // A pair that differs on BOTH the case-fold AND normalization axes at
    // once (e.g. "Café.txt" vs "café.txt") escapes both single-axis checks
    // above independently, but collides to one physical file when the
    // volume is simultaneously case-insensitive AND
    // normalization-insensitive -- the macOS default (both HFS+ and
    // APFS). See `hazard::canonical_fold`'s doc comment for why neither
    // check above, run alone, can catch this pair.
    if volume.case_insensitive && volume.normalization_insensitive {
        if let Some(colliding) = hazard::case_and_normalization_collision(path, siblings) {
            return Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_CASE_AND_NORMALIZATION_COLLISION,
                colliding.path
            ));
        }
    }
    None
}

/// The actual hazard-detection logic
/// behind `PeerSyncSession::hazard_reason_for`, factored out as a free
/// function (explicit `state`/`root`/`group_id`/`record`/`policy` rather
/// than a `PeerSyncSession` receiver) for the same reason
/// `materialize_symlink_at`/`try_apply_metadata_only_update` above are
/// free functions: direct unit-testability with just a `SyncState` +
/// tempdir, no live `QuicPeerChannel` needed (`hazard_reason_tests` below).
///
/// Composes `hazard::invalid_name_reason`, `hazard::case_fold_collision`
/// (only even queried when `hazard::is_case_insensitive_filesystem` says
/// `root`'s filesystem actually needs the check) and `hazard::
/// normalization_collision` (independently gated on `hazard::is_
/// normalization_insensitive_filesystem` — the two probes are separate
/// axes, see that function's own doc comment for why) — `None` means safe
/// to materialize normally.
///
/// Taking an explicit `policy` (rather than hardcoding `NamePolicy::
/// local` here) is what makes a "held on a Windows-policy test
/// target, materializes normally on a POSIX-policy test target, from the
/// same index state" scenario directly testable in one process regardless
/// of which platform actually runs the test suite —
/// `PeerSyncSession::hazard_reason_for` (this function's only production
/// caller) always passes `hazard::NamePolicy::local`.
///
/// Computed fresh on every call — `is_case_insensitive_filesystem` itself
/// re-probes on every call too (see its doc comment for why it is not
/// cached) — so a record whose hazard has since resolved (the colliding
/// sibling was
/// renamed/deleted, or an invalid name was fixed at the source) is
/// correctly recognized as no-longer-hazardous the next time this path is
/// reconciled. The reconciliation substrate's periodic re-reconciliation
/// with each peer (already relied on elsewhere for eventual consistency) is
/// what actually triggers that next reconcile — this crate has no separate
/// "re-check every held file" sweep; documented as a gap, not an oversight.
pub(crate) fn hazard_reason_for_policy(
    state: &crate::replica_coordinator::ReplicaCoordinator,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    policy: hazard::NamePolicy,
) -> Result<Option<String>, PeerSessionError> {
    if let Some(reason) = hazard::invalid_name_reason(policy, &record.path) {
        return Ok(Some(reason));
    }
    // Both probes are real filesystem round trips (deliberately uncached --
    // see `is_case_insensitive_filesystem`'s doc comment), so each is taken
    // once here rather than re-probed per check.
    let volume = VolumeFolding {
        case_insensitive: hazard::is_case_insensitive_filesystem(root),
        normalization_insensitive: hazard::is_normalization_insensitive_filesystem(root),
    };
    if !volume.folds_anything() {
        // The common case on Linux, and the reason the read below is
        // guarded rather than hoisted: nothing this group holds can fold
        // onto this name, so listing the group would be a query whose
        // answer cannot change the outcome.
        return Ok(None);
    }
    Ok(hazard_reason_for_siblings(&record.path, volume, &state.list_files(group_id)?))
}

/// The actual held-state bookkeeping
/// behind `PeerSyncSession::hold`, factored out the same way as
/// `hazard_reason_for_policy` above for direct unit-testability. Adopts
/// `record` into the index (`upsert_file` — a held record keeps
/// participating in ordinary index exchange/forwarding, since
/// `reconcile_one_file`'s callers `forward` a record regardless of what
/// `materialize` itself did with it) and marks it held with `reason`
/// (`SyncState::set_held`), without ever reaching an atomic on-disk write
/// step for this path. Never renames, never writes under any alternate
/// name — the only two effects this has are an
/// index upsert and a held-state write; see
/// `no_hazard_ever_writes_under_any_alternate_name` (in
/// `tests/peer_session.rs`) for a regression test asserting exactly that
/// through the real, wire-driven `materialize` path.
pub(crate) fn hold_record(
    state: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
    record: &FileRecord,
    reason: &str,
    origin_device_id: &str,
    authoring_change_hash: Option<&ChangeHash>,
    permit: &RootCommitPermit,
) -> Result<(), PeerSessionError> {
    // Upsert, demote to `Placeholder`, mark held: see
    // `ReplicaCoordinator::hold_row_for_hazard`.
    state.hold_row_for_hazard(
        group_id,
        record,
        reason,
        origin_device_id,
        authoring_change_hash,
        permit,
    )?;
    tracing::info!(
        path = %record.path,
        group_id,
        reason,
        "holding file due to a filename hazard (case-fold collision or platform-invalid \
         name); not materialized under any name on this device"
    );
    Ok(())
}

/// The symlink/exec-bit/authoring metadata paired with an incoming peer's
/// `FileRecord` (the wire's `proto::FileInfo` fields 7-10 in
/// `ProtobufPeerWireCodec`'s decode, or the equivalent local-audit fields
/// from `file_info_for_record`) that `FileRecord` itself cannot carry (see
/// `yadorilink_local_storage::chunker::unix_mode_from_metadata`'s doc
/// comment for the owner-exec-bit half of this gap). Threaded alongside the
/// resulting `FileRecord` through
/// `reconcile_one_file`/`resolve_and_apply_conflict` so
/// `apply_incoming_wire_metadata` can persist it into `SyncState` at the
/// record's *final* path — which can differ from the wire path when a
/// concurrent-edit conflict renames it — immediately before `materialize`
/// is called, since `materialize`'s own symlink dispatch
/// (`SyncState::get_record_kind`) reads the local index, never the wire
/// message directly.
#[derive(Clone, Debug)]
pub struct IncomingWireMeta {
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub symlink_out_of_root: bool,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
    /// The device that
    /// actually produced this incoming record's content, per the sending
    /// peer's own `SyncState::get_origin_device_id` lookup (see
    /// `file_info_for_record`). `None` when absent/empty on the wire — an
    /// peer that did not record one, or a row that peer never
    /// recorded an origin for — callers fall back to `self.peer_device_id`
    /// in that case, matching the pre-this-fix assumption.
    pub origin_device_id: Option<String>,
    /// Required causal identity of the retained DAG change that authored
    /// this projection. A missing or malformed value is rejected; there is
    /// no version-vector compatibility fallback.
    pub authoring_change_hash: Option<ChangeHash>,
}

/// What the materialization audit found for one repair-candidate path.
///
/// The three non-payload arms are not errors and not the same thing, and
/// the audit logs them differently, so they are named rather than folded
/// into an `Option`.
#[derive(Debug)]
pub enum AuditCandidate {
    /// The path has no `state = 'current'` row at all — it was listed as
    /// a repair candidate and then stopped being one, which a concurrent
    /// writer can do at any time.
    NoRow,
    /// A tombstone. There is nothing to rematerialize towards.
    Deleted,
    /// A genuine current row that has no authoring identity yet.
    ///
    /// Deliberately recognised broadly (any missing identity), not
    /// narrowed to a route like `version_seq == 0`: at least two real
    /// production writers produce this shape, with different `version_seq`
    /// values. The bootstrap scaffold `apply_incoming_wire_metadata`
    /// creates before a change's real content lands starts at
    /// `version_seq == 0`. A device rebootstrapping from a checkpoint
    /// snapshot (`replace_group_files_from_snapshot`) is the other: it
    /// deliberately never trusts a snapshot's claim that a `Current`,
    /// non-deleted file's content is present locally (stamping
    /// `Placeholder`, correctly conservative) but also never carries an
    /// authoring identity across the snapshot boundary, at whatever
    /// `version_seq` the snapshot recorded — almost never `0`.
    ///
    /// Either way the row is genuinely `Placeholder` with nothing to
    /// eagerly rehydrate FROM until it is paired with real content.
    /// `list_materialization_repair_candidates` selecting it is correct
    /// (it does need materializing eventually); it is the ordinary
    /// DAG-driven obligation pipeline, not this audit, that resolves it.
    NotYetPaired,
    /// The payload: one incarnation of the row, split into the pair every
    /// materialization lane already takes.
    Payload(FileRecord, IncomingWireMeta),
}

/// The payload the local materialization audit will materialize a path
/// towards, derived from ONE incarnation of this device's current row.
///
/// This is a *producer*, and the distinction is the whole point. What it
/// returns decides what bytes, symlink target, kind, mode and xattrs land
/// on disk, and — through `MaterializationPayload::from_wire` — which
/// version the resulting proof names. So it may not stitch its answer
/// together out of several reads: a payload holding one incarnation's
/// blocks beside another's mode and authoring hash derives a version hash
/// over a column combination that was never in the index at all, and no
/// downstream guard catches it, because every guard compares against the
/// row rather than against what was written.
///
/// It takes the snapshot rather than a state handle so that it cannot
/// read at all, which is what makes the above structural instead of
/// merely tested. [`yadorilink_peer_session::ports::CurrentRowSnapshot`]
/// is one statement's result, so tearing would now require a caller to
/// hand-build an incoherent snapshot.
///
/// The row is not a guard here and is not used as one. Whether the write
/// is still admissible when it lands is decided later, under the path
/// lock, by `apply_locked_record` and by the exact-version-guarded
/// commit — against the row as it is *then*, which is exactly where a
/// supersession that raced the read is supposed to be caught.
pub(crate) fn materialization_audit_candidate(
    row: Option<yadorilink_peer_session::ports::CurrentRowSnapshot>,
) -> AuditCandidate {
    let Some(row) = row else {
        return AuditCandidate::NoRow;
    };
    if row.record.deleted {
        return AuditCandidate::Deleted;
    }
    let Some(authoring_change_hash) = row.authoring_change_hash else {
        return AuditCandidate::NotYetPaired;
    };
    AuditCandidate::Payload(
        row.record,
        IncomingWireMeta {
            record_kind: row.record_kind,
            symlink_target: row.symlink_target,
            symlink_out_of_root: row.symlink_out_of_root,
            unix_mode: row.unix_mode,
            xattrs: row.xattrs,
            // This device's own record of who actually produced this
            // path's current content — see `IncomingWireMeta`'s doc
            // comment for how the receiving side uses this.
            origin_device_id: row.origin_device_id,
            authoring_change_hash: Some(authoring_change_hash),
        },
    )
}

/// Closes a wire-serialization handoff gap (see `IncomingWireMeta`'s own doc
/// comment above for the precise gap this fills):
/// persists an incoming peer's advertised `record_kind`/`symlink_target`/
/// `symlink_out_of_root`/`unix_mode` into `SyncState` at `record.path`,
/// which must be `record`'s *final* target path (post-conflict-rename, if
/// any) — the same path `materialize` is about to be called for.
///
/// **Correctness-critical: never upserts `record`'s real content fields
/// over an existing row.** Every one of the four setters below is an
/// `UPDATE... WHERE group_id = ?, path = ?` that errors with
/// `PeerSessionError::NotFound` if no row exists yet for this path (see
/// `index.rs`'s `set_record_kind`/etc. doc comments), so *some* row must
/// exist first. The first, broken version of this function called
/// `state.upsert_file(group_id, record)` unconditionally to guarantee
/// that — which introduced a real regression, caught by this change's own
/// two-peer wire test (`tests/peer_session.rs`): `materialize`'s
/// `try_apply_metadata_only_update` fast-paths whenever the
/// path's *already-indexed* blocks equal the incoming record's blocks,
/// skipping the real fetch/write and just chmod'ing the (assumed
/// already-on-disk) file. Pre-upserting `record` here made that
/// comparison compare `record` against itself — trivially equal, every
/// time, for *every* brand-new file — so the fast path fired for a file
/// whose content was never actually written to disk, and the chmod call
/// failed with `ENOENT`. The fix: only create a row when none exists yet
/// (a path this device has genuinely never seen before), and when
/// creating one, use an **empty block list** regardless of `record`'s
/// real blocks — structurally guaranteed to differ from any real,
/// non-empty content the same message is about to deliver, so
/// `try_apply_metadata_only_update`'s comparison (or its own
/// `record.blocks.is_empty` guard, for a genuinely empty file) correctly
/// falls through to a real fetch/write. When a row *does* already exist
/// (an update to a previously-seen path), it is left completely untouched
/// here — its old content fields are exactly what `try_apply_metadata_
/// only_update` needs to compare the incoming record against.
///
/// Factored out as a free function (matching `materialize_symlink_at`/
/// `try_apply_metadata_only_update`/`hazard_reason_for_policy` before it)
/// for direct unit-testability without a live `QuicPeerChannel`.
pub fn apply_incoming_wire_metadata(
    state: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
    record: &FileRecord,
    meta: &IncomingWireMeta,
    permit: &RootCommitPermit,
) -> Result<(), PeerSessionError> {
    // This was `state.upsert_file(group_id, &FileRecord
    // { blocks: Vec::new,..record.clone })` guarded by the same
    // `is_none` check — that call now goes through the version-retaining
    // `upsert_file_in_tx` path, which would otherwise record
    // this empty bootstrap row as a genuine (if short-lived) superseded
    // version once `materialize` immediately upserts the real content
    // moments later, leaving every peer-adopted file's history with a
    // spurious empty first version. `ensure_bootstrap_row_for_metadata`
    // creates the same kind of scaffold row `SyncState`'s own
    // `files_supersede_prior_current` trigger recognizes and *deletes*
    // (rather than supersedes) on the next real upsert — see that
    // function's and the trigger's doc comments for the full mechanism.
    // One transaction, not 6 separate `state.set_*`/`ensure_bootstrap_
    // row_for_metadata` calls each taking its own `writer_gate`: this
    // unconditional-on-every-path-resolution call would otherwise dominate
    // writer_gate load under a large change burst.
    // `apply_incoming_metadata_atomic` does the same bootstrap-if-needed
    // plus all 5 field writes in ONE transaction.
    let columns = yadorilink_replica_domain::session_state::LocalFileMetaColumns {
        record_kind: meta.record_kind,
        symlink_target: meta.symlink_target.clone(),
        symlink_out_of_root: meta.symlink_out_of_root,
        unix_mode: meta.unix_mode,
        xattrs: meta.xattrs.clone(),
    };
    state.apply_incoming_metadata_atomic(group_id, &record.path, &columns, permit)?;
    Ok(())
}

static MATERIALIZATION_AUDITS_IN_FLIGHT: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();

/// Diagnostic correlation id, shared by `reconcile_local_materialization_
/// audit` and `reconcile_paths_directly`, for diagnosing intermittently
/// stalled obligations — a single global
/// counter (not per-device, not per-mechanism) so every log line from a
/// given call, from either entry point, across every device in a single
/// multi-device test process, carries one unambiguous id.
static NEXT_AUDIT_ATTEMPT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn next_audit_attempt_id() -> u64 {
    NEXT_AUDIT_ATTEMPT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `retire_conflict_copies_only`'s whole-pass frontier freshness check --
/// factored out to a pure function so its exact semantics (a plain slice
/// comparison; any number of intermediate admissions during the pass
/// collapses to the same before/after mismatch as a single one) can be
/// tested without any async execution, DAG store, or session plumbing.
/// `dag_group_heads`'s own `ORDER BY change_hash` makes two reads of an
/// unchanged frontier compare equal regardless of admission order, so this
/// never needs to sort its inputs itself.
pub(crate) fn frontier_changed_during_pass(before: &[ChangeHash], after: &[ChangeHash]) -> bool {
    before != after
}

pub(crate) struct MaterializationAuditGuard {
    key: String,
}

impl MaterializationAuditGuard {
    pub(crate) fn try_acquire(
        state: &Arc<crate::replica_coordinator::ReplicaCoordinator>,
        group_id: &str,
    ) -> Option<Self> {
        let key = format!("{:p}:{group_id}", Arc::as_ptr(state));
        let in_flight = MATERIALIZATION_AUDITS_IN_FLIGHT.get_or_init(Default::default);
        let mut in_flight = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !in_flight.insert(key.clone()) {
            return None;
        }
        Some(Self { key })
    }
}

impl Drop for MaterializationAuditGuard {
    fn drop(&mut self) {
        if let Some(in_flight) = MATERIALIZATION_AUDITS_IN_FLIGHT.get() {
            in_flight.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
        }
    }
}

static RETIREMENT_AUDITS_IN_FLIGHT: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();

/// `retire_conflict_copies_only`'s own single-flight, deliberately a
/// SEPARATE key space from `MaterializationAuditGuard` rather than sharing
/// its key. Before this, retirement contended with `reconcile_local_
/// materialization_audit`/`reconcile_paths_directly` for the exact same
/// per-group slot: a full audit or direct path reconciliation already in
/// flight for a group made every retirement pass against it report `Busy`
/// for that entire duration, even though retirement's own physical
/// mutation is already independently serialized per-path by `state.
/// path_lock` (see `retire_unjustified_ephemeral_conflict_copies`'s own
/// path-lock acquisition, and `reconcile_group_paths`'/`apply_locked_
/// record`'s matching ones) -- the group-wide guard was serializing far
/// more than the one thing (two writers racing the SAME path) that
/// actually needed serializing. Only retirement passes now contend with
/// each other; a long-running full audit no longer blocks retirement's own
/// progress, and vice versa.
pub(crate) struct RetirementAuditGuard {
    key: String,
}

impl RetirementAuditGuard {
    pub(crate) fn try_acquire(
        state: &Arc<crate::replica_coordinator::ReplicaCoordinator>,
        group_id: &str,
    ) -> Option<Self> {
        let key = format!("{:p}:{group_id}", Arc::as_ptr(state));
        let in_flight = RETIREMENT_AUDITS_IN_FLIGHT.get_or_init(Default::default);
        let mut in_flight = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !in_flight.insert(key.clone()) {
            return None;
        }
        Some(Self { key })
    }
}

impl Drop for RetirementAuditGuard {
    fn drop(&mut self) {
        if let Some(in_flight) = RETIREMENT_AUDITS_IN_FLIGHT.get() {
            in_flight.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
        }
    }
}

/// Outcome of `hydrate_file`/`hydrate_file_with_timeout`. A plain `Ok(())`
/// used to mean "bytes fetched AND written to disk under this name" in
/// every case except one: a filename hazard discovered after every block
/// was already fetched into the local block store reverts the row to
/// `Placeholder` and returns success anyway (the blocks really were
/// fetched; only the physical write was withheld) -- see the hazard
/// short-circuit inside `hydrate_file_with_timeout`. That collapsed two
/// meaningfully different outcomes into one signal: `pin_and_hydrate_file`
/// (whose own doc says "pinning forces hydration") could report success
/// while the pinned file still had no content on disk at all. This type
/// exists so a caller can tell the two apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationOutcome {
    /// Content is fully written to disk under this path's name.
    Hydrated,
    /// Every block was fetched into the local block store (so this device
    /// can still serve them onward to another peer), but a filename
    /// hazard withheld the physical write. The row is back at
    /// `Placeholder`, held, exactly as if hydration had never been
    /// attempted -- a caller relying on "hydration means the file is now
    /// on disk" must not treat this the same as `Hydrated`.
    Held { reason: String },
}

/// Outcome of `apply_locked_record`: the incoming record was either fully
/// handled without a conflict (adopted / peer-ahead / already-current /
/// never-seen), or it is genuinely concurrent with the local record and the
/// caller must decide how to resolve it. No surviving caller turns
/// `Concurrent` into a resolution: the DAG engine resolves concurrency by
/// (lamport, change-hash) before a record ever reaches here, and the
/// materialization-audit path treats it as unreachable.
#[derive(Debug)]
pub enum LockedRecordOutcome {
    Settled,
    /// `materialize` reported `MaterializeResult::RetryRequired` for this
    /// record: an eager/pinned fetch could not obtain every block, a
    /// hazard-collision tombstone dropped or held without actually
    /// deleting anything, or some other "not done" outcome
    /// `MaterializeResult`'s own doc comment describes.
    RetryRequired,
    /// Carries only the local record, for the caller's diagnostic log: no
    /// surviving caller resolves a concurrency here, so the incoming record
    /// and its wire metadata would be dead payload.
    Concurrent {
        local: FileRecord,
    },
}

/// Rejects a peer-supplied `FileRecord.path` unless every component is an
/// ordinary path segment — no `..`, no absolute-path root/prefix (a
/// Windows drive letter, a leading `/`). Being authorized to sync a folder
/// group only grants access to *that folder*; without this check, a path
/// like `"../../../.ssh/authorized_keys"` or `"/etc/passwd"` would let any
/// device sharing the group write (via `materialize`) or delete (via a
/// tombstone) an arbitrary file anywhere on the receiving device's
/// filesystem, well outside the synced directory — `PathBuf::join` with an
/// absolute path silently discards the base entirely, and `..` components
/// aren't otherwise neutralized anywhere in the reconciliation path.
pub(crate) fn is_safe_relative_path(path: &str) -> bool {
    use std::path::Component;
    if path.is_empty() {
        return false;
    }
    std::path::Path::new(path).components().all(|c| matches!(c, Component::Normal(_)))
}

/// Builds a materializable `FileRecord` for `path` from a resolved
/// `FileVersion`. Each block carries its real `size` (canonical encoding v2
/// records a per-block size) and a prefix-sum `offset`, so the built record is
/// suitable for the derived materialized index. The version
/// vector is empty because causality in the change-history model is DAG
/// ancestry, not a version vector; the index row is only a DAG projection.
pub(crate) fn file_record_from_version(path: &str, version: &FileVersion) -> FileRecord {
    let mut offset = 0u64;
    let blocks = version
        .blocks
        .iter()
        .map(|vb| {
            let block = BlockInfo { hash: vb.hash.0.clone(), offset, size: vb.size };
            offset = offset.saturating_add(vb.size as u64);
            block
        })
        .collect();
    FileRecord {
        path: path.to_string(),
        size: version.size,
        mtime_unix_nanos: version.meta.mtime_unix_nanos,
        blocks,
        deleted: false,
    }
}

/// Content identity of two index rows used to corroborate equal authoring
/// identity: the deletion flag, size, mtime, and the ordered
/// block hash/size sequence — the same components `FileVersion`'s canonical
/// version hash commits to at this layer. Paths are deliberately not
/// compared (every caller already scopes to a single path); block offsets
/// are a prefix sum of the sizes, so comparing them would be redundant.
pub(crate) fn same_record_content(a: &FileRecord, b: &FileRecord) -> bool {
    a.deleted == b.deleted
        && a.size == b.size
        && a.mtime_unix_nanos == b.mtime_unix_nanos
        && a.blocks.len() == b.blocks.len()
        && a.blocks.iter().zip(&b.blocks).all(|(x, y)| x.hash == y.hash && x.size == y.size)
}

/// A record and the version that produced it, kept together so they
/// cannot come from different moments.
///
/// Every physical materialization has a source payload: an incoming wire
/// record, a resolved DAG version, the current row a hydration was asked
/// to place. That payload determines both the bytes to write and the
/// version those bytes are. Reading the version back out of the index row
/// instead -- at any point, however early -- asks about the row rather
/// than about the payload, and a supersession that keeps the same
/// authoring identity moves the row's version while the payload does not
/// move at all. The proof then names a version the bytes are not, and
/// nothing downstream can tell, because every other check is also
/// comparing against the row.
///
/// `record` is reachable only through this type. Passing the two
/// separately is what let them drift, so the shape that allowed it is
/// gone rather than merely unused.
#[derive(Clone, Debug)]
pub struct MaterializationPayload {
    record: FileRecord,
    version: FileVersion,
}

impl MaterializationPayload {
    /// From a resolved `FileVersion` and the path it is being placed at --
    /// the DAG projection's own shape, where the record is derived from
    /// the version and the two cannot disagree by construction.
    pub fn from_version(path: &str, version: FileVersion) -> Self {
        Self { record: file_record_from_version(path, &version), version }
    }

    /// From a record and the metadata that arrived with it on the wire.
    ///
    /// Safe because both halves are the source payload: the version is
    /// derived once, here, from exactly the values that will be written.
    /// What is never safe is re-reading that metadata from the row
    /// afterwards and calling the result the version that was applied.
    pub fn from_wire(record: FileRecord, meta: &IncomingWireMeta) -> Self {
        let version = FileVersion::from_index_row(
            record.blocks.clone(),
            record.size,
            record.mtime_unix_nanos,
            meta.record_kind,
            meta.unix_mode,
            meta.symlink_target.clone(),
            meta.xattrs.clone(),
        );
        Self { record, version }
    }

    /// From an already-committed current row this device is being asked to
    /// place on disk -- hydration's shape. One canonical read gives the
    /// record and the version together, so the fetch, the reconstruct, the
    /// exactness gate and the commit all speak about the same instant.
    pub fn from_current_row(path: &str, current: FileVersion) -> Self {
        Self::from_version(path, current)
    }

    /// A tombstone. It names no content, so the only version it can have
    /// is the one its own empty record derives -- there is nothing on
    /// disk for that to disagree with.
    pub fn tombstone(record: FileRecord) -> Self {
        let version = FileVersion::from_index_row(
            record.blocks.clone(),
            record.size,
            record.mtime_unix_nanos,
            RecordKind::File,
            None,
            None,
            Vec::new(),
        );
        Self { record, version }
    }

    pub fn record(&self) -> &FileRecord {
        &self.record
    }

    pub fn version(&self) -> &FileVersion {
        &self.version
    }

    pub fn path(&self) -> &str {
        &self.record.path
    }
}
