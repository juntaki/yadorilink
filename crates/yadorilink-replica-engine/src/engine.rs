use yadorilink_replica_domain::ids::{FolderGroupId, VersionHash};
use yadorilink_replica_domain::session_state::RootSetSummary;

use crate::outcomes::{CustodyEvaluation, CustodyWarning};
use crate::ports::{DurabilityRoot, ReplicaRetentionPolicy};
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

/// Owns native-state operations that are peer-identity-parameterized rather
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
}
