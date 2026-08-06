//! Pure planning half of what used to be `PeerReplicaEngine::
//! enqueue_batch_materialization` -- decides WHICH paths need a
//! materialization job and with which trigger change/lamport, without
//! touching storage, the wall clock, or logging. The execute half (actually
//! persisting a job per plan, waking the materialization loop, and logging)
//! stays in `yadorilink-sync-core`, which alone has `materialization_
//! enqueue_pending`/`notify_materialization_wake`/`dst_trace`/the wall
//! clock.

use std::collections::{BTreeMap, BTreeSet};

use yadorilink_replica_domain::ids::ChangeHash;

use crate::outcomes::AdmittedChange;

pub struct MaterializationJobPlan {
    pub path: String,
    pub trigger_change: ChangeHash,
    pub trigger_lamport: u64,
}

/// `version_hash`/`lamport` planned per path is whichever admitted change
/// most recently touched it in THIS batch (by iteration order over
/// `admitted`) -- not a resolved winner (that requires the same DAG-head
/// fixpoint `reconcile_group_paths` already does, deliberately left to the
/// engine). A path with no matching admitted change (shouldn't happen in
/// practice, since `affected_paths` is derived from `admitted` itself, but
/// not structurally guaranteed by this function's own signature) plans a
/// zeroed trigger -- the caller's own `enqueue_pending` still writes a row,
/// same as the pre-split code's `unwrap_or(([0u8; 32], 0))` fallback.
pub fn plan_batch_materialization(
    admitted: &[AdmittedChange],
    affected_paths: &BTreeSet<String>,
) -> Vec<MaterializationJobPlan> {
    let mut path_versions: BTreeMap<&str, (ChangeHash, u64)> = BTreeMap::new();
    for change in admitted {
        for path in &change.touched_paths {
            path_versions.insert(path.as_str(), (change.hash, change.lamport));
        }
    }
    affected_paths
        .iter()
        .map(|path| {
            let (trigger_change, trigger_lamport) =
                path_versions.get(path.as_str()).copied().unwrap_or((ChangeHash([0u8; 32]), 0));
            MaterializationJobPlan { path: path.clone(), trigger_change, trigger_lamport }
        })
        .collect()
}
