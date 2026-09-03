//! DAG/index-mutation logic extracted out of `yadorilink-sync-core`'s
//! `peer_session.rs` wire handlers -- responsibilities that are true
//! regardless of which peer sent the message, as opposed to
//! `PeerSyncSession`'s own protocol decode/admission/correlation state.

use std::collections::HashSet;
use std::collections::VecDeque;

use yadorilink_replica_domain::change::{Change, ChangeAuth};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, VersionHash};

use crate::change_ops;
use crate::error::AdmissionStoreError;
use crate::error::ReplicaEngineError;
use crate::outcomes::{
    AdmittedChange, CausalAuthOutcome, ChangeAdmissionOutcome, ChangeAdmissionRejection,
    CustodyEvaluation, CustodyWarning, FrontierEvaluation, FrontierRecordWarning,
};
use crate::ports::{AdmissionStoreOutcome, DurabilityRoot, ReplicaRetentionPolicy};
use crate::ReplicaEngineDependencies;

/// `(encoded file versions, their hashes)`, parallel by index -- see
/// `new_file_versions_for_change`'s own doc comment.
type NewFileVersions = (Vec<Vec<u8>>, Vec<[u8; 32]>);

/// Domain-level equivalent of `proto::VersionPresentQuery`, holding only the
/// fields `PeerReplicaEngine::holds_version_durably` actually needs.
/// `request_id` stays on the caller's side (needed only to build the wire
/// reply, never read by this check).
pub struct DurableVersionQuery {
    pub folder_group_id: String,
    pub file_path: String,
    pub block_hashes: Vec<Vec<u8>>,
    pub for_handoff: bool,
    pub version_hash: Vec<u8>,
    pub block_sizes: Vec<u32>,
}

/// One bounded, oldest-first page of a `changes_for_request` response.
/// `more` is `true` on every page but the last, so a caller can send each
/// page as its own wire `ChangeBatch` without recomputing the delta per
/// page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiEntropyPage {
    pub changes: Vec<Vec<u8>>,
    pub file_versions: Vec<Vec<u8>>,
    pub more: bool,
}

/// Owns DAG-state operations that are peer-identity-parameterized rather
/// than peer-CONNECTION-stateful -- i.e. they take a `group_id`/hash/etc.
/// as a plain parameter and read only replica state, with no dependency on
/// which live session is calling them.
pub struct PeerReplicaEngine {
    deps: ReplicaEngineDependencies,
}

impl PeerReplicaEngine {
    pub fn new(deps: ReplicaEngineDependencies) -> Self {
        Self { deps }
    }

    /// Iterative post-order walk of `hash`'s retained ancestry via the
    /// `parents_of` port, appending newly-discovered hashes to `ordered` in
    /// oldest-first (every parent before its children) order, `hash` itself
    /// last. Iterative rather than recursive so a genuinely deep
    /// single-branch history cannot blow the stack.
    fn collect_ancestor_closure(
        &self,
        root: &ChangeHash,
        seen: &mut HashSet<[u8; 32]>,
        ordered: &mut Vec<ChangeHash>,
    ) -> Result<(), ReplicaEngineError> {
        enum Frame {
            Discover(ChangeHash),
            Emit(ChangeHash),
        }
        if seen.contains(&root.0) {
            return Ok(());
        }
        let mut stack = vec![Frame::Discover(*root)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Discover(hash) => {
                    if !seen.insert(hash.0) {
                        continue;
                    }
                    stack.push(Frame::Emit(hash));
                    for parent in self.deps.history.parents_of(&hash)? {
                        stack.push(Frame::Discover(parent));
                    }
                }
                Frame::Emit(hash) => ordered.push(hash),
            }
        }
        Ok(())
    }

    /// The canonical encodings of every file version one change's content ops
    /// reference that `already_carried` does not already cover, plus their
    /// hashes so an accepting caller can fold them into its own carried set. A
    /// version this device does not hold is simply omitted -- the change still
    /// transfers, and the receiver holds it until a batch carries the version
    /// too.
    ///
    /// Resolved one change at a time, rather than for a whole page at once, so
    /// page assembly can bound a page by BYTES: the budget has to know a
    /// change's marginal version bytes *before* deciding to include it.
    fn new_file_versions_for_change(
        &self,
        group_id: &FolderGroupId,
        encoded_change: &[u8],
        already_carried: &HashSet<[u8; 32]>,
    ) -> Result<NewFileVersions, ReplicaEngineError> {
        let Ok(change) = Change::from_wire_bytes(encoded_change) else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut added: HashSet<[u8; 32]> = HashSet::new();
        let mut encodings: Vec<Vec<u8>> = Vec::new();
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        for op in &change.ops {
            let Some(version_hash) = change_ops::op_version_hash(op) else {
                continue;
            };
            if already_carried.contains(&version_hash.0) || !added.insert(version_hash.0) {
                continue;
            }
            if let Some(version) = self.deps.history.file_version(group_id, &version_hash)? {
                encodings.push(version.canonical_encoding());
                hashes.push(version_hash.0);
            }
        }
        Ok((encodings, hashes))
    }

    /// One BFS layer of `frontier`: replaces it with the not-yet-`seen`
    /// parents of its current contents, marking each newly-seen, and
    /// returns exactly those newly-discovered hashes so a caller can check
    /// them against the OTHER side's own seen set.
    fn expand_layer(
        &self,
        frontier: &mut VecDeque<ChangeHash>,
        seen: &mut HashSet<[u8; 32]>,
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        let current: Vec<ChangeHash> = frontier.drain(..).collect();
        let mut discovered = Vec::new();
        for hash in current {
            for parent in self.deps.history.parents_of(&hash)? {
                if seen.insert(parent.0) {
                    discovered.push(parent);
                }
            }
        }
        frontier.extend(discovered.iter().copied());
        Ok(discovered)
    }

    /// Discovers enough of `recognized_reachable(have_heads)` to correctly
    /// bound the `want_heads` walk in `changes_for_request`, without
    /// walking either side's full ancestry when `want_heads` and
    /// `have_heads` are actually close together in the causal graph.
    ///
    /// Alternates expanding one BFS layer of the `want` side and one of the
    /// `have` side, stopping the instant either side's newly-discovered
    /// hashes intersect what the OTHER side has already seen -- at that
    /// point every hash between `want_heads`/`have_heads` and the found
    /// boundary is already recorded, which is all `changes_for_request`'s
    /// own closure walk (seeded with this method's result) needs to stop
    /// at the right place. If one side's frontier empties first (its
    /// entire reachable set turned out smaller than the other's), that
    /// side's full reachable set is now known and the other side's walk
    /// continues alone until it also empties or an intersection is found.
    ///
    /// Only a hash this device can confirm is live (`self.deps.history.
    /// change(..).is_some()`) ever seeds the `have` side -- an unrecognized
    /// `have_heads` entry never narrows the result (see `changes_for_
    /// request`'s own doc comment for why).
    fn recognized_have_boundary(
        &self,
        want_heads: &[ChangeHash],
        have_heads: &[ChangeHash],
    ) -> Result<HashSet<[u8; 32]>, ReplicaEngineError> {
        // `*_seen` is populated FIRST, in full, before any frontier
        // decision below -- both because the return value (`have_seen`)
        // must include every recognized `have_heads` hash regardless of
        // whether it ever gets expanded, and because deciding what to
        // QUEUE for expansion needs the complete opposite-side set already
        // built (see the frontier-seeding comment below).
        let mut want_seen: HashSet<[u8; 32]> = HashSet::new();
        let mut have_seen: HashSet<[u8; 32]> = HashSet::new();
        for want in want_heads {
            want_seen.insert(want.0);
        }
        for have in have_heads {
            if self.deps.history.change(have)?.is_some() {
                have_seen.insert(have.0);
            }
        }

        // Phase E finding, first pass: a blanket early return used to fire
        // here on ANY want/have overlap across the WHOLE sets -- correct
        // for the common single-head "already fully caught up" case, but
        // wrong for a multi-head request where one head is already caught
        // up while ANOTHER genuinely diverges deep in shared history: it
        // returned `have_seen` as just the raw recognized `have_heads`
        // hashes, skipping the bidirectional search below entirely, so the
        // still-diverging head's later `collect_ancestor_closure` walk
        // could only stop at a literal `have_heads` hash instead of its
        // true (possibly much closer) shared ancestor.
        //
        // Phase E finding, second pass (a Codex review's finding on the
        // first pass's fix): simply removing the shortcut and queueing
        // EVERY head for expansion is not enough on its own. A head that
        // is ALREADY directly resolved by an exact want/have match (like
        // `branch1_tip` above) still had its own ancestry queued and
        // expanded alongside the genuinely-diverging heads, in the SAME
        // merged frontier/layer -- and the loop below stops the ENTIRE
        // search the instant ANY newly-discovered hash matches the other
        // side, regardless of WHICH head produced it. If the already-
        // matched head has any ancestry of its own that the other side's
        // search also reaches, that shallow, already-irrelevant
        // intersection can trigger the `break` before the genuinely-
        // diverging heads' own search has gone deep enough to find THEIR
        // true shared ancestor -- silently reintroducing the same
        // resource-shape violation the first-pass fix was meant to close,
        // just one layer later instead of immediately.
        //
        // The fix: a head that is already trivially resolved (its exact
        // hash appears on the opposite side) contributes NOTHING to
        // expand -- its own boundary is already known (itself), and
        // expanding its ancestry only risks contaminating the search for
        // OTHER heads. Only a head genuinely absent from the opposite
        // side's `*_seen` is queued at all.
        let mut want_frontier: VecDeque<ChangeHash> = VecDeque::new();
        let mut want_queued: HashSet<[u8; 32]> = HashSet::new();
        for want in want_heads {
            if !have_seen.contains(&want.0) && want_queued.insert(want.0) {
                want_frontier.push_back(*want);
            }
        }
        let mut have_frontier: VecDeque<ChangeHash> = VecDeque::new();
        let mut have_queued: HashSet<[u8; 32]> = HashSet::new();
        for have in have_heads {
            if have_seen.contains(&have.0)
                && !want_seen.contains(&have.0)
                && have_queued.insert(have.0)
            {
                have_frontier.push_back(*have);
            }
        }
        let mut want_turn = true;
        while !want_frontier.is_empty() || !have_frontier.is_empty() {
            if want_turn {
                if !want_frontier.is_empty() {
                    let discovered = self.expand_layer(&mut want_frontier, &mut want_seen)?;
                    if discovered.iter().any(|hash| have_seen.contains(&hash.0)) {
                        break;
                    }
                }
            } else if !have_frontier.is_empty() {
                let discovered = self.expand_layer(&mut have_frontier, &mut have_seen)?;
                if discovered.iter().any(|hash| want_seen.contains(&hash.0)) {
                    break;
                }
            }
            want_turn = !want_turn;
        }
        Ok(have_seen)
    }

    /// Computes `reachable(want_heads) - recognized_reachable(have_heads)`
    /// and delivers it as bounded, oldest-first pages of at most
    /// `max_changes_per_batch` changes each -- the delta is computed
    /// exactly once; the page cap only bounds how it is split for the
    /// wire, never how much of history is re-walked. Returns an empty
    /// `Vec` when there is nothing to send.
    ///
    /// `recognized_have_boundary` discovers the exclusion boundary via a
    /// bidirectional search bounded by how close `want_heads` and
    /// `have_heads` actually are, so a small divergence over a deep shared
    /// history costs work proportional to the divergence, not to either
    /// side's full depth -- the actual closure walk below only re-visits
    /// what that search already discovered was needed.
    ///
    /// `have_heads` is untrusted peer input: a claimed `have` hash only
    /// narrows the delta if this device *recognizes* it (a live row in
    /// `changes`, checked via `self.deps.history.change`). An unrecognized
    /// hash -- unknown, stale, or spoofed -- is not walked at all and so
    /// contributes nothing to the exclusion set; this can only make the
    /// sender include more history than strictly necessary, never omit
    /// history the requester still needs. Recognizing a pruned/checkpointed
    /// (non-live) `have` boundary as excludable too is a possible future
    /// refinement, not attempted here -- today "recognized" is exactly
    /// "live."
    ///
    /// Termination for a delta longer than `max_changes_per_batch` does
    /// not depend on forcing the requested tip into every page: oldest-
    /// first pagination guarantees every page's causal parents already
    /// arrived in an earlier page, so the final page -- which always
    /// contains every `want_heads` entry, since `collect_ancestor_closure`
    /// appends each root last -- is reached by construction, not by
    /// reservation.
    pub fn changes_for_request(
        &self,
        group_id: &FolderGroupId,
        want_heads: &[ChangeHash],
        have_heads: &[ChangeHash],
        max_changes_per_batch: usize,
    ) -> Result<Vec<AntiEntropyPage>, ReplicaEngineError> {
        let boundary = self.recognized_have_boundary(want_heads, have_heads)?;

        let mut seen = boundary;
        let mut ordered: Vec<ChangeHash> = Vec::new();
        for want in want_heads {
            self.collect_ancestor_closure(want, &mut seen, &mut ordered)?;
        }

        if ordered.is_empty() {
            return Ok(Vec::new());
        }

        let page_size = max_changes_per_batch.max(1);
        // Pages are filled greedily under BOTH bounds: at most `page_size`
        // changes, and at most `MAX_ANTI_ENTROPY_PAGE_BYTES` of encoded
        // payload including the file versions those changes reference (the
        // versions ride in the same wire frame, so leaving them out of the
        // budget would not bound the frame at all). A change that does not fit
        // the remaining budget starts the next page instead of being dropped;
        // a page always takes at least one change, so an over-budget change on
        // its own can never wedge the loop.
        let mut pages: Vec<AntiEntropyPage> = Vec::new();
        let mut index = 0usize;
        while index < ordered.len() {
            let mut changes: Vec<Vec<u8>> = Vec::new();
            let mut file_versions: Vec<Vec<u8>> = Vec::new();
            let mut seen_versions: HashSet<[u8; 32]> = HashSet::new();
            let mut page_bytes = 0usize;
            while index < ordered.len() && changes.len() < page_size {
                let Some(encoded) = self.deps.history.encoded_change(&ordered[index])? else {
                    // Not retained any more: it contributes nothing to this
                    // page and must not stall the walk.
                    index += 1;
                    continue;
                };
                // Resolve this change's own not-yet-carried versions before
                // committing to it, so the fit test sees the real bytes it
                // would add. Nothing is folded into the page's own
                // `seen_versions`/`file_versions` until the change is
                // accepted, so a change deferred to the next page leaves no
                // trace here.
                let (added_versions, added_version_hashes) =
                    self.new_file_versions_for_change(group_id, &encoded, &seen_versions)?;
                let added_bytes =
                    encoded.len() + added_versions.iter().map(Vec::len).sum::<usize>();
                if !changes.is_empty()
                    && page_bytes.saturating_add(added_bytes)
                        > yadorilink_replica_domain::change::MAX_ANTI_ENTROPY_PAGE_BYTES
                {
                    break;
                }
                page_bytes = page_bytes.saturating_add(added_bytes);
                changes.push(encoded);
                file_versions.extend(added_versions);
                seen_versions.extend(added_version_hashes);
                index += 1;
            }
            pages.push(AntiEntropyPage { changes, file_versions, more: false });
        }
        if let Some(last) = pages.len().checked_sub(1) {
            for page in pages.iter_mut().take(last) {
                page.more = true;
            }
        }
        Ok(pages)
    }

    /// Records the peer's announced heads as its acknowledged frontier for
    /// the group (best-effort -- a failure here becomes `record_warning`,
    /// never propagated), then returns the ancestor frontier still missing
    /// across every announced head together.
    pub fn record_frontier_and_find_missing(
        &self,
        group_id: &FolderGroupId,
        peer_device_id: &DeviceId,
        announced: &[ChangeHash],
    ) -> Result<FrontierEvaluation, ReplicaEngineError> {
        let record_warning = self
            .deps
            .frontier
            .record_acknowledged_frontier(group_id, peer_device_id, announced)
            .err()
            .map(|error| FrontierRecordWarning { message: error.to_string() });
        let missing = self.deps.history.missing_ancestor_frontier(announced)?;
        Ok(FrontierEvaluation { missing, record_warning })
    }

    /// Whether this device durably holds *exactly* the queried version and
    /// can be relied on as the group's copy of it. Every condition must
    /// hold, or the answer is a fail-closed `present: false`.
    ///
    /// Checked in order:
    /// 1. this device is actually `Eager` for the group;
    /// 2. a live (non-deleted) durability root exists for `(group, path)` in
    ///    the state set `for_handoff` allows (current-only for eviction, any
    ///    of current/superseded/trashed for a handoff);
    /// 3. the recomputed `VersionHash` of that root equals the query's;
    /// 4. the query's ordered block list and each block's declared size
    ///    match the matched root's (already implied by step 3, kept
    ///    explicit);
    /// 5. every block has verified provenance for the queried group;
    /// 6. every block in the matched root passes full checksum verification
    ///    (never merely an existence check), so a corrupt or truncated
    ///    block answers `present: false`.
    pub fn holds_version_durably(&self, query: &DurableVersionQuery) -> CustodyEvaluation {
        let group = FolderGroupId(query.folder_group_id.clone());
        let path = yadorilink_replica_domain::ids::SyncPath(query.file_path.clone());

        // 1. This device must be a full replica (Eager) of the group. An
        //    on-demand device may hold these blocks only transiently and can
        //    evict them at any moment, so it must never authorize a peer to
        //    drop its own copy on the strength of this device's cache.
        if !matches!(
            self.deps.durability.retention_policy(&group),
            Ok(Some(ReplicaRetentionPolicy::Eager))
        ) {
            return CustodyEvaluation { present: false, warning: None };
        }
        let Ok(query_hash_bytes): Result<[u8; 32], _> = query.version_hash.as_slice().try_into()
        else {
            return CustodyEvaluation { present: false, warning: None };
        };
        let query_hash = VersionHash(query_hash_bytes);

        // 2 + 3. Find a durability root at this path -- in the state set
        //    `for_handoff` allows -- whose own recomputed VersionHash
        //    matches the query.
        let matching_blocks = if query.for_handoff {
            let roots = match self.deps.durability.retained_roots(&group, &path) {
                Ok(roots) => roots,
                Err(_) => return CustodyEvaluation { present: false, warning: None },
            };
            match roots.into_iter().find(|root: &DurabilityRoot| {
                !root.deleted && root.version.version_hash == query_hash
            }) {
                Some(root) => root.version.blocks,
                None => return CustodyEvaluation { present: false, warning: None },
            }
        } else {
            let root = match self.deps.durability.current_root(&group, &path) {
                Ok(Some(root)) if !root.deleted => root,
                Err(error) => {
                    return CustodyEvaluation {
                        present: false,
                        warning: Some(CustodyWarning {
                            message: format!(
                                "current version record is unreadable for {}/{}: {error}",
                                query.folder_group_id, query.file_path
                            ),
                        }),
                    };
                }
                Ok(_) => return CustodyEvaluation { present: false, warning: None },
            };
            if root.version.version_hash != query_hash {
                return CustodyEvaluation { present: false, warning: None };
            }
            root.version.blocks
        };

        // 4. Explicit block-list/size check.
        if matching_blocks.len() != query.block_hashes.len()
            || matching_blocks.len() != query.block_sizes.len()
            || !matching_blocks.iter().zip(query.block_hashes.iter().zip(&query.block_sizes)).all(
                |(b, (queried_hash, queried_size))| {
                    &b.hash.0 == queried_hash && b.size == *queried_size
                },
            )
        {
            return CustodyEvaluation { present: false, warning: None };
        }

        // 5. Provenance.
        if !matching_blocks
            .iter()
            .all(|b| matches!(self.deps.durability.has_block_provenance(&group, &b.hash), Ok(true)))
        {
            return CustodyEvaluation { present: false, warning: None };
        }

        // 6. Full checksum verification.
        let present =
            matching_blocks.iter().all(|b| self.deps.durability.verify_block(&b.hash).is_ok());
        CustodyEvaluation { present, warning: None }
    }

    /// Checks that `change`'s pinned `auth_seq`/`auth_epoch` is
    /// non-decreasing along causal order relative to its DAG parents --
    /// closes a revoked-writer replay attack: a device revoked at policy
    /// seq N, still holding its signing key, could otherwise craft a new
    /// change stamped with an older grant seq M < N and have it admitted.
    /// A PLACEHOLDER stamp is exempt (genuine pre-policy bootstrap).
    ///
    /// This is an OPTIMISTIC fast-path, not the sole enforcement point: a
    /// parent whose pinned coordinate can't be read LIVE returns `Hold`,
    /// which the caller must treat as "proceed to admission anyway" (not
    /// "discard") -- `yadorilink-sync-sqlite::dag_store`'s own admission/
    /// promotion path (`check_causal_auth_monotonicity_at_promotion`)
    /// re-verifies this exact invariant once every parent's coordinate is
    /// actually resolvable (live or pruned), which is the real, permanent
    /// enforcement point. See that function's own doc comment for why
    /// discarding on `Hold` (the old behavior) turned a cold catch-up
    /// beyond the wire batch cap into an unnecessary one-hop-per-round
    /// staircase.
    pub fn check_causal_auth_monotonicity(
        &self,
        change: &Change,
    ) -> Result<CausalAuthOutcome, ReplicaEngineError> {
        let incoming_auth = ChangeAuth {
            auth_seq: change.auth_seq,
            auth_epoch: change.auth_epoch,
            policy_head_hash: change.policy_head_hash,
        };
        if incoming_auth == ChangeAuth::PLACEHOLDER {
            return Ok(CausalAuthOutcome::Exempt);
        }
        let mut max_parent_seq = 0u64;
        let mut max_parent_epoch = 0u64;
        let mut parent_pin_unreadable = false;
        for parent in &change.parents {
            match self.deps.history.change(parent) {
                Ok(Some(parent_change)) => {
                    max_parent_seq = max_parent_seq.max(parent_change.auth_seq);
                    max_parent_epoch = max_parent_epoch.max(parent_change.auth_epoch);
                }
                Ok(None) | Err(_) => {
                    parent_pin_unreadable = true;
                    break;
                }
            }
        }
        if parent_pin_unreadable {
            return Ok(CausalAuthOutcome::Hold);
        }
        if change.auth_seq < max_parent_seq || change.auth_epoch < max_parent_epoch {
            return Ok(CausalAuthOutcome::Rejected {
                auth_seq: change.auth_seq,
                auth_epoch: change.auth_epoch,
                max_parent_auth_seq: max_parent_seq,
                max_parent_auth_epoch: max_parent_epoch,
            });
        }
        Ok(CausalAuthOutcome::Accepted)
    }

    /// Returns the hash of the first referenced file version this device
    /// cannot yet resolve (not staged by this batch, not already held) --
    /// `None` if every version `change`'s ops reference is available.
    pub fn missing_referenced_version(
        &self,
        group_id: &FolderGroupId,
        change: &Change,
        staged_versions: &std::collections::BTreeMap<VersionHash, FileVersion>,
    ) -> Result<Option<VersionHash>, ReplicaEngineError> {
        for op in &change.ops {
            let Some(version_hash) = change_ops::op_version_hash(op) else {
                continue;
            };
            if !staged_versions.contains_key(&version_hash)
                && !self.deps.history.has_file_version(group_id, &version_hash)?
            {
                return Ok(Some(version_hash));
            }
        }
        Ok(None)
    }

    /// Admits an already-authenticated, causally-monotonic change into the
    /// DAG as durable-but-not-yet-projected. On success, folds in the paths
    /// of EVERY change that became durable as a result -- `change` itself
    /// AND any orphan its arrival unblocked.
    pub fn admit_authenticated_change(
        &self,
        change: &Change,
        claimed_hash: ChangeHash,
        referenced_versions: &[FileVersion],
    ) -> Result<ChangeAdmissionOutcome, ReplicaEngineError> {
        let mut outcomes =
            self.admit_authenticated_change_batch(&[(change, claimed_hash, referenced_versions)])?;
        Ok(outcomes.remove(0))
    }

    /// Bounded micro-batch sibling of [`Self::admit_authenticated_change`]:
    /// admits every item in `items`, in order, returning one outcome per
    /// item in the same order -- `admit_authenticated_change` itself is now
    /// just this called with a single-item slice, so the two can never
    /// drift apart. See `ChangeAdmissionPort::admit_unprojected_change_
    /// batch`'s own doc comment for the storage-layer guarantees this
    /// relies on (per-item atomicity/failure-isolation/ordering).
    ///
    /// A post-admission step that fails with a genuine `ReplicaEngineError`
    /// (`self.deps.history.change`/`missing_ancestor_frontier`, both
    /// pre-existing, unrelated to batching) still aborts the whole call via
    /// `?`, exactly as it already aborted the single-item caller's own
    /// `handle_change_batch` loop before this method existed -- batching
    /// does not change that failure's blast radius, only how many items'
    /// worth of admission work preceded it in one writer_gate hold.
    pub fn admit_authenticated_change_batch(
        &self,
        items: &[(&Change, ChangeHash, &[FileVersion])],
    ) -> Result<Vec<ChangeAdmissionOutcome>, ReplicaEngineError> {
        let port_items: Vec<(&Change, &[FileVersion])> =
            items.iter().map(|(change, _hash, versions)| (*change, *versions)).collect();
        let admission_results = self.deps.admission.admit_unprojected_change_batch(&port_items);
        let mut outcomes = Vec::with_capacity(items.len());
        for ((change, claimed_hash, _versions), result) in items.iter().zip(admission_results) {
            let outcome = match result {
                Err(AdmissionStoreError::ReservedNamespaceCollision { path }) => {
                    ChangeAdmissionOutcome::Rejected {
                        reason: ChangeAdmissionRejection::ReservedNamespaceCollision { path },
                    }
                }
                Err(AdmissionStoreError::NonPortablePath { path }) => {
                    ChangeAdmissionOutcome::Rejected {
                        reason: ChangeAdmissionRejection::NonPortablePath { path },
                    }
                }
                Err(AdmissionStoreError::Other(message)) => ChangeAdmissionOutcome::Rejected {
                    reason: ChangeAdmissionRejection::StorageFailure { message },
                },
                Ok(result) => match result.outcome {
                    AdmissionStoreOutcome::Applied => {
                        let mut admitted = Vec::new();
                        for hash in &result.newly_admitted {
                            let admitted_change = if hash == claimed_hash {
                                Some((*change).clone())
                            } else {
                                self.deps.history.change(hash)?
                            };
                            let Some(admitted_change) = admitted_change else {
                                continue;
                            };
                            let mut touched_paths = std::collections::BTreeSet::new();
                            for op in &admitted_change.ops {
                                change_ops::collect_op_paths(op, &mut touched_paths);
                            }
                            admitted.push(AdmittedChange {
                                hash: *hash,
                                lamport: admitted_change.lamport,
                                touched_paths,
                            });
                        }
                        ChangeAdmissionOutcome::Applied { admitted }
                    }
                    AdmissionStoreOutcome::Orphaned => {
                        let missing_parents =
                            self.deps.history.missing_ancestor_frontier(&[*claimed_hash])?;
                        ChangeAdmissionOutcome::Orphaned { missing_parents }
                    }
                },
            };
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Records this device's own current heads as its acknowledged frontier
    /// for the group. Must be called whenever the local head set advances
    /// (a local commit, or applying a peer's changes).
    pub fn record_local_frontier(
        &self,
        group_id: &FolderGroupId,
        local_device_id: &DeviceId,
    ) -> Result<(), ReplicaEngineError> {
        let heads = self.deps.history.group_heads(group_id)?;
        self.deps.frontier.record_acknowledged_frontier(group_id, local_device_id, &heads)
    }
}

#[cfg(test)]
mod tests;
