use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, VersionHash};
use yadorilink_replica_domain::session_state::RootSetSummary;

use crate::change_ops;
use crate::error::AdmissionStoreError;
use crate::error::ReplicaEngineError;
use crate::outcomes::{
    AdmittedChange, ChangeAdmissionOutcome, ChangeAdmissionRejection, CustodyEvaluation,
    CustodyWarning, FrontierEvaluation, FrontierRecordWarning,
};
use crate::ports::{AdmissionStoreOutcome, DurabilityRoot, ReplicaRetentionPolicy};
use crate::ReplicaEngineDependencies;

/// Domain-level equivalent of the wire's `VersionPresent` service request
/// (`yadorilink_peer_session::service_rpc::ServiceRequest::VersionPresent`),
/// holding only the fields `PeerReplicaEngine::holds_version_durably`
/// actually needs.
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

    /// This device's own durable state for a group, reduced to two digests
    /// and two counts — the answer to a background health question, not to a
    /// custody question.
    ///
    /// Deliberately shaped so that the two cannot be confused at the call
    /// site either. [`Self::holds_version_durably`] returns a
    /// `CustodyEvaluation`, is per version, and reaches step 6; this returns
    /// a summary, is per group, and touches no block at all. What a peer
    /// learns from comparing this against its own is that two indexes list
    /// the same versions — which is worth knowing every ninety seconds, and
    /// is not grounds for anyone to drop a copy of anything.
    ///
    /// `None` is a refusal, and the refusals are deliberately
    /// indistinguishable to the asker:
    ///
    /// 1. this device is not `Eager` for the group — the same first check
    ///    `holds_version_durably` makes, and for the same reason: an
    ///    on-demand device may evict at any moment, so its agreement is not
    ///    a durability claim;
    /// 2. the index could not be read, which fails closed like every other
    ///    unreadable-state path here.
    pub fn root_set_summary(&self, group: &FolderGroupId) -> Option<RootSetSummary> {
        if !matches!(
            self.deps.durability.retention_policy(group),
            Ok(Some(ReplicaRetentionPolicy::Eager))
        ) {
            return None;
        }
        self.deps.durability.root_set_summary(group).ok()
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

    /// Admits an already-authenticated change into the DAG as
    /// durable-but-not-yet-projected. On success, folds in the paths of
    /// EVERY change that became durable as a result -- `change` itself AND
    /// any orphan its arrival unblocked.
    pub fn admit_authenticated_change(
        &self,
        change: &Change,
        claimed_hash: ChangeHash,
        referenced_versions: &[FileVersion],
        evidence: &crate::ports::ChangeEvidence,
    ) -> Result<ChangeAdmissionOutcome, ReplicaEngineError> {
        let mut outcomes = self.admit_authenticated_change_batch(&[(
            change,
            claimed_hash,
            referenced_versions,
            evidence,
        )])?;
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
        items: &[(&Change, ChangeHash, &[FileVersion], &crate::ports::ChangeEvidence)],
    ) -> Result<Vec<ChangeAdmissionOutcome>, ReplicaEngineError> {
        let port_items: Vec<(&Change, &[FileVersion], &crate::ports::ChangeEvidence)> = items
            .iter()
            .map(|(change, _hash, versions, evidence)| (*change, *versions, *evidence))
            .collect();
        let admission_results = self.deps.admission.admit_unprojected_change_batch(&port_items);
        let mut outcomes = Vec::with_capacity(items.len());
        for ((change, claimed_hash, _versions, _evidence), result) in
            items.iter().zip(admission_results)
        {
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
                    // Deliberately not `Orphaned`: there is no ancestry to
                    // ask for. The author's own chain refuses this Change,
                    // and nothing a peer could send afterwards changes that.
                    AdmissionStoreOutcome::RefusedAuthorChain { reason } => {
                        ChangeAdmissionOutcome::Rejected {
                            reason: ChangeAdmissionRejection::AuthorChainRefused { reason },
                        }
                    }
                    // Deliberately not `Orphaned` either, and for a
                    // stronger reason: this Change's ancestry is complete
                    // in a history this replica does not have, so asking
                    // for more of it would ask for that whole history.
                    AdmissionStoreOutcome::RefusedForeignHistoryBase { reason } => {
                        ChangeAdmissionOutcome::Rejected {
                            reason: ChangeAdmissionRejection::ForeignHistoryBase { reason },
                        }
                    }
                    // Not `Orphaned`: the parent it lacks is refused here,
                    // so asking a peer for it would ask for something this
                    // replica has already decided never to hold.
                    AdmissionStoreOutcome::RefusedBehindRejectedParent { reason } => {
                        ChangeAdmissionOutcome::Rejected {
                            reason: ChangeAdmissionRejection::BehindRejectedParent { reason },
                        }
                    }
                    // Not `Orphaned`: the names are the Change's own signed
                    // bytes, measured against the base this replica is on.
                    AdmissionStoreOutcome::RefusedInvalidObservedBaseHead { reason } => {
                        ChangeAdmissionOutcome::Rejected {
                            reason: ChangeAdmissionRejection::InvalidObservedBaseHead { reason },
                        }
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
