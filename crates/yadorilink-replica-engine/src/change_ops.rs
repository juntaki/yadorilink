//! Small, pure helpers over `change::Op`, used by `PeerReplicaEngine` (this
//! crate) and by `yadorilink-sync-core`'s `peer_session.rs` (wire decode/
//! authorize) directly -- neither reaches into the other for these, so
//! `peer_session.rs` staying in `yadorilink-sync-core` never forces this
//! crate to depend back on it.

use std::collections::BTreeSet;

use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::VersionHash;

/// The content version an op references, or `None` for a delete (which lands
/// no content).
pub fn op_version_hash(op: &Op) -> Option<VersionHash> {
    match op {
        Op::Put { version, .. } | Op::Move { version, .. } => Some(*version),
        Op::Delete { .. } => None,
    }
}

/// Records every path an op touches into `set` (both endpoints of a move).
pub fn collect_op_paths(op: &Op, set: &mut BTreeSet<String>) {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => {
            set.insert(path.as_str().to_string());
        }
        Op::Move { from, to, .. } => {
            set.insert(from.as_str().to_string());
            set.insert(to.as_str().to_string());
        }
    }
}
