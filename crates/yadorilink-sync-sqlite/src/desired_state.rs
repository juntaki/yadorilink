//! The *desired*-side half of the resolved-state comparison
//! `materialized_generation` relies on. `compute_resolved_path_state_hash`
//! is already a complete, reusable hash of "what a path resolves to" -- it does not depend on
//! causal basis or filesystem identity, by design. This module supplies
//! the *input* to it: turning a [`PathResolution`] (the DAG-level winner for
//! one path) into the `(MaterializedObjectKind, Option<VersionHash>)` pair
//! that hash function needs.
//!
//! Lives here, not in `yadorilink-replica-engine` (which owns
//! `PathResolution`/`resolve_path_heads`): this crate depends on
//! `yadorilink-replica-engine`, not the reverse, and `MaterializedObjectKind`/
//! `compute_resolved_path_state_hash`/`get_file_version` all live here. A
//! builder that calls all of them therefore belongs on this side of the
//! dependency edge.

use std::collections::HashMap;

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::conflict::PathResolution;
use yadorilink_replica_engine::namespace::{
    project, project_level, project_own_node, DirectoryNode, NamespaceProjection, PhysicalNode,
};

use crate::dag_store::{
    get_file_version, has_live_descendant, live_heads_at_level, live_heads_by_path, live_path_heads,
};
use crate::error::SyncSqliteError;
use crate::materialized_generation::{compute_resolved_path_state_hash, MaterializedObjectKind};

fn map_record_kind(kind: RecordKind) -> MaterializedObjectKind {
    match kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    }
}

/// Computes the desired-side `resolved_path_state_hash` for one path, given
/// the outcome of `resolve_path_heads` and the winning head's content
/// version. `resolve_path_heads` takes `&[PathHead]` and returns `winner` as
/// an index into it, so the caller already has the winning head (and its
/// `version_hash`) in hand at the point it calls this -- this function takes
/// that version hash directly rather than re-deriving it from `resolution`
/// and a `heads` slice, so it has no dependency on the caller's own
/// `PathHead` storage shape. No new hash shape: this calls the existing
/// `compute_resolved_path_state_hash` directly.
///
/// `PathResolution::Absent` -> `(MaterializedObjectKind::Absent, None)`.
/// `PathResolution::Present` -> looks up `winner_version_hash` via
/// [`get_file_version`] (already fail-closed: re-verifies the decoded
/// content's own hash against the request) to read the version's
/// [`RecordKind`], maps it to [`MaterializedObjectKind`], and hashes
/// `(object_kind, Some(winner_version_hash))`.
///
/// Returns [`SyncSqliteError::NotFound`] (via `get_file_version`'s own
/// fail-closed contract, or directly if the caller omits `winner_version_
/// hash` for a `Present` resolution) rather than ever collapsing an
/// unresolvable winner to `Absent`: a worker with no local record of the
/// winning file version cannot honestly say what the path resolves to, and
/// reporting `Absent` would let a real desired-state hash collide with the
/// one genuinely-absent state a tombstoned path also hashes to. The correct
/// reading of this error is "not yet resolvable" (the content index for
/// this version has not arrived locally yet) -- a caller should defer/retry
/// on it, never close an obligation against `MaterializedObjectKind::
/// Absent` because of it.
pub fn desired_resolved_path_state_hash(
    conn: &Connection,
    group_id: &str,
    path: &str,
    resolution: &PathResolution,
    winner_version_hash: Option<&VersionHash>,
) -> Result<[u8; 32], SyncSqliteError> {
    match resolution {
        PathResolution::Absent => Ok(compute_resolved_path_state_hash(
            group_id,
            path,
            MaterializedObjectKind::Absent,
            None,
        )),
        PathResolution::Present { .. } => {
            let version_hash = winner_version_hash.ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "resolve_path_heads reported {path} as Present but no winning version hash \
                     was supplied"
                ))
            })?;
            let version = get_file_version(conn, group_id, version_hash)?.ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "winning version {} for {path} is not locally resolvable",
                    version_hash.to_hex()
                ))
            })?;
            let object_kind = map_record_kind(version.meta.record_kind);
            Ok(compute_resolved_path_state_hash(group_id, path, object_kind, Some(version_hash)))
        }
    }
}

/// What the namespace projection places at one path on the path's own
/// account.
///
/// [`desired_resolved_path_state_hash`] answers per path: a path's own
/// heads, resolved on their own. A filesystem is not per path. A File `a`
/// cannot be materialized while `a/x` lives, and a deleted directory that
/// still holds a live child is still a directory. This is the per-path
/// answer with the tree constraint applied, as
/// [`yadorilink_replica_engine::namespace::project`] defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredPathState {
    /// Nothing is required at the path.
    Absent,
    /// A File or Symlink version stays at its own path.
    Entry { kind: RecordKind, version: VersionHash },
    /// A replicated Directory entry lives at the path.
    ExplicitDirectory { version: VersionHash },
    /// A directory required only to hold live descendants. When the path's
    /// own winner is a File or Symlink, that content is relocated to its
    /// conflict-copy sibling and is not part of this path's state.
    StructuralDirectory,
}

impl DesiredPathState {
    /// The state a projection node stands for, at the path the projection
    /// places it: a relocated or conflict-copy entry is proven at its copy
    /// name like any other entry there (such nodes come from
    /// [`desired_namespace_projection`], not from the own-account
    /// [`desired_path_state`]). `None` is absent.
    #[must_use]
    pub fn of_node(node: Option<&PhysicalNode>) -> Self {
        match node {
            None => DesiredPathState::Absent,
            Some(PhysicalNode::Directory(DirectoryNode::Explicit { version_hash })) => {
                DesiredPathState::ExplicitDirectory { version: VersionHash(*version_hash) }
            }
            Some(PhysicalNode::Directory(DirectoryNode::Structural)) => {
                DesiredPathState::StructuralDirectory
            }
            Some(PhysicalNode::Entry(entry)) => DesiredPathState::Entry {
                kind: entry.kind,
                version: VersionHash(entry.version_hash),
            },
        }
    }

    /// The materialized-generation kind and version this state is proven
    /// by.
    #[must_use]
    pub fn object_kind_and_version(&self) -> (MaterializedObjectKind, Option<VersionHash>) {
        match *self {
            Self::Absent => (MaterializedObjectKind::Absent, None),
            Self::Entry { kind, version } => (map_record_kind(kind), Some(version)),
            Self::ExplicitDirectory { version } => {
                (MaterializedObjectKind::Directory, Some(version))
            }
            Self::StructuralDirectory => (MaterializedObjectKind::StructuralDirectory, None),
        }
    }

    /// The `resolved_path_state_hash` a generation proving this state at
    /// `path` carries.
    #[must_use]
    pub fn resolved_path_state_hash(&self, group_id: &str, path: &str) -> [u8; 32] {
        let (kind, version) = self.object_kind_and_version();
        compute_resolved_path_state_hash(group_id, path, kind, version.as_ref())
    }
}

/// What `path` is required to be on its own account, read from the
/// current path frontier: its live heads, and whether anything strictly
/// below it holds a live content head.
///
/// Own account only: a path that is only the copy name of another path's
/// relocated or conflict-copy entry reads [`DesiredPathState::Absent`]
/// here, because where copies land depends on the names their siblings
/// take. The state required at a copy name is
/// [`DesiredPathState::of_node`] of [`desired_namespace_projection`]'s
/// node there. On every path the projection keeps on its own account, the
/// two agree.
///
/// Fails closed with [`SyncSqliteError::NotFound`] when a live content
/// head at `path` names a version whose kind is not locally resolvable,
/// for the same reason [`desired_resolved_path_state_hash`] does: without
/// the kind, whether the path is a directory is undecidable, and no answer
/// may stand in for that. Descendants' versions are not read: that one of
/// them is live is all that matters here.
///
/// Two reads (the path's heads, then its descendants): call it inside the
/// transaction whose snapshot the answer has to agree with, or an admission
/// between the two can pair heads and descendants from different frontiers.
pub fn desired_path_state(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<DesiredPathState, SyncSqliteError> {
    let heads = live_path_heads(conn, group_id, path)?;
    let mut kinds: HashMap<[u8; 32], RecordKind> = HashMap::new();
    for content in heads.iter().filter_map(|head| head.content.as_ref()) {
        if kinds.contains_key(&content.version_hash) {
            continue;
        }
        let version_hash = VersionHash(content.version_hash);
        let version = get_file_version(conn, group_id, &version_hash)?.ok_or_else(|| {
            SyncSqliteError::NotFound(format!(
                "live version {} at {path} is not locally resolvable",
                version_hash.to_hex()
            ))
        })?;
        kinds.insert(content.version_hash, version.meta.record_kind);
    }
    let descendant = has_live_descendant(conn, group_id, path)?;
    let node = project_own_node(path, &heads, descendant, |version| kinds.get(version).copied())
        .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?;
    Ok(DesiredPathState::of_node(node.as_ref()))
}

/// The group's whole desired physical tree, computed with
/// [`yadorilink_replica_engine::namespace::project`] from the current
/// path frontier: every path's own node, and every relocated and
/// conflict-copy entry at the copy name it takes.
///
/// Fails closed with [`SyncSqliteError::NotFound`] when any live content
/// head names a version whose kind is not locally resolvable, as
/// [`desired_path_state`] does for one path. One read of the group's live
/// heads plus one version read per distinct live version; call it inside
/// the transaction whose snapshot the answer has to agree with.
pub fn desired_namespace_projection(
    conn: &Connection,
    group_id: &str,
) -> Result<NamespaceProjection, SyncSqliteError> {
    let heads = live_heads_by_path(conn, group_id)?;
    let mut kinds: HashMap<[u8; 32], RecordKind> = HashMap::new();
    for (path, path_heads) in &heads {
        for content in path_heads.iter().filter_map(|head| head.content.as_ref()) {
            if kinds.contains_key(&content.version_hash) {
                continue;
            }
            let version_hash = VersionHash(content.version_hash);
            let version = get_file_version(conn, group_id, &version_hash)?.ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "live version {} at {path} is not locally resolvable",
                    version_hash.to_hex()
                ))
            })?;
            kinds.insert(content.version_hash, version.meta.record_kind);
        }
    }
    project(&heads, |version| kinds.get(version).copied())
        .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))
}

/// One directory level of [`desired_namespace_projection`]: every node
/// whose parent is `parent` (`""` for the root), own-account nodes and the
/// relocated and conflict-copy entries named there alike. Equal to the
/// whole projection's nodes at that level, at the cost of reading only
/// `parent`'s subtree (the whole group for the root) and the versions of
/// the level's own live heads.
///
/// Fails closed like [`desired_namespace_projection`]. Call it inside the
/// transaction whose snapshot the answer has to agree with.
pub fn desired_level_projection(
    conn: &Connection,
    group_id: &str,
    parent: &str,
) -> Result<NamespaceProjection, SyncSqliteError> {
    let (children, with_live_descendant) = live_heads_at_level(conn, group_id, parent)?;
    let mut kinds: HashMap<[u8; 32], RecordKind> = HashMap::new();
    for (path, path_heads) in &children {
        for content in path_heads.iter().filter_map(|head| head.content.as_ref()) {
            if kinds.contains_key(&content.version_hash) {
                continue;
            }
            let version_hash = VersionHash(content.version_hash);
            let version = get_file_version(conn, group_id, &version_hash)?.ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "live version {} at {path} is not locally resolvable",
                    version_hash.to_hex()
                ))
            })?;
            kinds.insert(content.version_hash, version.meta.record_kind);
        }
    }
    project_level(&children, &with_live_descendant, |version| kinds.get(version).copied())
        .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))
}

/// [`desired_path_state`]'s `resolved_path_state_hash`.
pub fn desired_projected_path_state_hash(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<[u8; 32], SyncSqliteError> {
    Ok(desired_path_state(conn, group_id, path)?.resolved_path_state_hash(group_id, path))
}

#[cfg(test)]
mod tests;
