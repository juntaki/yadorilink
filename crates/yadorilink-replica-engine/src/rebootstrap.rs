//! History-base identity and the compaction release gate.
//!
//! The signed objects themselves (`HistoryBase`, `SnapshotManifest` and the
//! trust port that verifies one) live in `yadorilink_replica_domain::
//! rebootstrap` and are re-exported here. The legacy wire re-bootstrap -- a
//! signed `RebootstrapRequired` answer to a request for a pruned hash, and
//! the installer seam it drove -- is gone: a base now reaches a replica only
//! through the verified foreign merge in `yadorilink-sync-sqlite`
//! (`rebootstrap_store::commit_foreign_merge`).

pub use yadorilink_replica_domain::rebootstrap::{
    HistoryBase, HistoryEpoch, RebootstrapTrust, SnapshotManifest,
};

/// Explicit release gate for history compaction.
///
/// Gates the PRODUCER half (`compaction::execute_prune`'s own check), the
/// seal that commits a local compaction
/// (`yadorilink_sync_sqlite::rebootstrap_store::seal_group`, the only
/// non-test way to commit a history base locally), and the merge that
/// installs a peer's base (`rebootstrap_store::commit_foreign_merge`): each
/// refuses while this is false, outside that crate's test fixtures. With it
/// false, no production path installs a base at all.
///
/// Before it flips, the install every one of those paths shares must stay
/// safe: `yadorilink_sync_sqlite::rebootstrap_store::
/// replace_group_files_from_snapshot`'s own post-insert `debug_assert!`
/// re-checks, on every install in any debug build, that its DELETE +
/// re-INSERT of `files` carries forward a surviving path's local-only
/// `held_reason`/`held_since_unix_nanos`/`pinned` columns (never part of
/// the wire-derived snapshot) -- dropping them silently strips a
/// hazard-held path's only remaining tombstone protection. If that
/// `debug_assert!` (or its own `replace_group_files_from_snapshot_tests`
/// module) ever regresses, treat it as a release blocker for this gate.
pub const COMPACTION_SCHEDULING_READY: bool = false;

#[cfg(test)]
mod tests;
