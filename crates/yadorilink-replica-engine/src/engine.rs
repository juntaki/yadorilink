//! DAG/index-mutation logic extracted out of `yadorilink-sync-core`'s
//! `peer_session.rs` wire handlers -- responsibilities that are true
//! regardless of which peer sent the message, as opposed to
//! `PeerSyncSession`'s own protocol decode/admission/correlation state.

use std::collections::HashSet;

use yadorilink_replica_domain::change::{Change, ChangeAuth};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, VersionHash};

use crate::change_ops;
use crate::error::ReplicaEngineError;
use crate::outcomes::{
    AdmittedChange, CausalAuthOutcome, ChangeAdmissionOutcome, ChangeAdmissionRejection,
    CustodyEvaluation, CustodyWarning, FrontierEvaluation, FrontierRecordWarning,
};
use crate::ports::{AdmissionStoreOutcome, DurabilityRoot, ReplicaRetentionPolicy};
use crate::ReplicaEngineDependencies;
use crate::error::AdmissionStoreError;

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

    /// Gathers the canonical encodings of every file version referenced by
    /// `encoded_changes`' content ops, deduplicated. A version this device
    /// does not hold is simply omitted -- the change still transfers, and
    /// the receiver holds it until a batch carries the version too.
    fn file_versions_for_changes(
        &self,
        group_id: &FolderGroupId,
        encoded_changes: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, ReplicaEngineError> {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut out: Vec<Vec<u8>> = Vec::new();
        for encoded in encoded_changes {
            let Ok(change) = Change::from_wire_bytes(encoded) else { continue };
            for op in &change.ops {
                let Some(version_hash) = change_ops::op_version_hash(op) else {
                    continue;
                };
                if !seen.insert(version_hash.0) {
                    continue;
                }
                if let Some(version) = self.deps.history.file_version(group_id, &version_hash)? {
                    out.push(version.canonical_encoding());
                }
            }
        }
        Ok(out)
    }

    /// Expands `want` into full ancestor closures, truncates to
    /// `max_changes_per_batch`, gathers encoded change bytes plus their
    /// referenced file versions. Returns `(batch, versions)` -- an empty
    /// `batch` means "nothing to send."
    pub fn changes_for_request(
        &self,
        group_id: &FolderGroupId,
        want: &[ChangeHash],
        max_changes_per_batch: usize,
    ) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), ReplicaEngineError> {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut ordered: Vec<ChangeHash> = Vec::new();
        for hash in want {
            self.collect_ancestor_closure(hash, &mut seen, &mut ordered)?;
        }
        ordered.truncate(max_changes_per_batch);

        let mut batch: Vec<Vec<u8>> = Vec::new();
        for hash in ordered {
            if let Some(encoded) = self.deps.history.encoded_change(&hash)? {
                batch.push(encoded);
            }
        }
        let versions =
            if batch.is_empty() { Vec::new() } else { self.file_versions_for_changes(group_id, &batch)? };
        Ok((batch, versions))
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
        if !matches!(self.deps.durability.retention_policy(&group), Ok(Some(ReplicaRetentionPolicy::Eager)))
        {
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
            match roots
                .into_iter()
                .find(|root: &DurabilityRoot| !root.deleted && root.version.version_hash == query_hash)
            {
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
        let present = matching_blocks.iter().all(|b| self.deps.durability.verify_block(&b.hash).is_ok());
        CustodyEvaluation { present, warning: None }
    }

    /// Checks that `change`'s pinned `auth_seq`/`auth_epoch` is
    /// non-decreasing along causal order relative to its DAG parents --
    /// closes a revoked-writer replay attack: a device revoked at policy
    /// seq N, still holding its signing key, could otherwise craft a new
    /// change stamped with an older grant seq M < N and have it admitted.
    /// A PLACEHOLDER stamp is exempt (genuine pre-policy bootstrap); a
    /// parent whose pinned coordinate can't be read holds the change
    /// (re-requests the missing ancestry) rather than admitting on trust.
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
            let missing_parents =
                self.deps.history.missing_ancestor_frontier(&change.parents)?;
            return Ok(CausalAuthOutcome::Hold { missing_parents });
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
        match self.deps.admission.admit_unprojected_change(change, referenced_versions) {
            Err(AdmissionStoreError::ReservedNamespaceCollision { path }) => Ok(
                ChangeAdmissionOutcome::Rejected {
                    reason: ChangeAdmissionRejection::ReservedNamespaceCollision { path },
                },
            ),
            Err(AdmissionStoreError::NonPortablePath { path }) => Ok(ChangeAdmissionOutcome::Rejected {
                reason: ChangeAdmissionRejection::NonPortablePath { path },
            }),
            Err(AdmissionStoreError::Other(message)) => Ok(ChangeAdmissionOutcome::Rejected {
                reason: ChangeAdmissionRejection::StorageFailure { message },
            }),
            Ok(result) => match result.outcome {
                AdmissionStoreOutcome::Applied => {
                    let mut admitted = Vec::new();
                    for hash in &result.newly_admitted {
                        let admitted_change = if *hash == claimed_hash {
                            Some(change.clone())
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
                    Ok(ChangeAdmissionOutcome::Applied { admitted })
                }
                AdmissionStoreOutcome::Orphaned => {
                    let missing_parents =
                        self.deps.history.missing_ancestor_frontier(&[claimed_hash])?;
                    Ok(ChangeAdmissionOutcome::Orphaned { missing_parents })
                }
            },
        }
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
