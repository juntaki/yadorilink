//! The namespace projection: explicit replicated state → desired physical
//! tree, as a pure function.
//!
//! Replication is path-scoped. Every path carries its own live heads, and
//! [`resolve_path_heads`] settles each path on its own. A filesystem is not
//! path-scoped: `a` cannot be a regular file while `a/x` exists, and a
//! directory that exists only to hold `a/x` is not something any device
//! wrote. This module is the one place that turns the per-path answers into
//! a tree:
//!
//! ```text
//! E = resolve(history)   -- explicit state, one resolution per path
//! M = project(E)         -- this module
//! ```
//!
//! # Rules
//!
//! * **`NeedsDirectory(p)`** holds when `p` has a live Directory head, or
//!   when `p` is a proper ancestor of any path with a live content head.
//!   Every such `p` is a directory in the projection.
//! * A directory with at least one live Directory head is an
//!   [`DirectoryNode::Explicit`] directory carrying the highest-ranked
//!   Directory head's version. Directory heads that lose to it get no
//!   conflict copy: an empty directory copy carries no information, so the
//!   loser's metadata simply yields to the winner's.
//! * A directory with no live Directory head is
//!   [`DirectoryNode::Structural`]: derived only from its descendants,
//!   never replicated, never authored.
//! * **Structural directory wins.** When `NeedsDirectory(p)` holds, no
//!   File or Symlink stays at `p`, whatever the per-path resolver would
//!   have picked. The per-path winner, if it is a File or Symlink, is
//!   [`Placement::Relocated`] to its deterministic conflict-copy sibling;
//!   the other losing File/Symlink contents are ordinary
//!   [`Placement::ConflictCopy`] siblings exactly as without a directory.
//!   A live Directory head at `p` therefore beats a File at `p` even when
//!   the File ranks higher.
//! * Without a directory at `p`, the per-path resolution is used as is.
//! * **A deleted directory does not delete its subtree.** A Directory
//!   tombstone removes only the explicit entry; a surviving descendant
//!   keeps `p` as a structural directory.
//! * **Copy names never collide.** Every path that has a node on its own
//!   account (explicit or structural) keeps its name. A copy whose name is
//!   already taken retries with a numbered disambiguator inside the
//!   device field (`<device> 2`, `<device> 3`, …), allocated in the order
//!   of `(name, source path, version hash)`. The result is still a
//!   well-formed conflict-copy name of the same source.
//! * **An authored copy is the copy.** A losing File/Symlink whose exact
//!   bytes an explicit entry already holds at the loser's own copy name (a
//!   conflict copy some change authored there) gets no second copy; that
//!   entry keeps its own path and placement. A `Relocated` winner is never
//!   folded this way: it stays addressable as its source's content.
//!
//! Relocation is a projection, not a fact: nothing here is ever authored
//! into the change history. Two replicas holding the same explicit state
//! compute the same tree without talking to each other, and a relocated
//! entry moves back to its own path the moment the last descendant that
//! displaced it goes away.
//!
//! # Deliberately absent
//!
//! No device-dependent input. Case folding and Unicode normalization
//! collisions (`A` vs `a/x` on a case-insensitive volume) are resolved by a
//! device-local layer after this projection; this function is what seals
//! and summaries are compared against, so it must give every device the
//! same answer.

use std::collections::{BTreeMap, BTreeSet};

use yadorilink_replica_domain::file::RecordKind;

use crate::conflict::{
    conflict_copy_path_for_losing_change, dag_conflict_loser_is_a, resolve_path_heads, PathHead,
    PathHeadContent, PathResolution,
};

/// Why a projection could not be computed. Fail closed: a partial tree is
/// not a tree anyone may materialize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    /// A live content head names a version whose kind is not known, so
    /// whether it is a directory cannot be decided.
    Undecidable { path: String, version_hash: [u8; 32] },
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::Undecidable { path, version_hash } = self;
        write!(
            f,
            "namespace projection undecidable: kind of version {} at {path:?} is unknown",
            hex::encode(version_hash)
        )
    }
}

impl std::error::Error for ProjectionError {}

/// How a directory in the projection came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryNode {
    /// A replicated Directory entry lives at this path; `version_hash` is
    /// its winning version, whose metadata the directory carries.
    Explicit { version_hash: [u8; 32] },
    /// Derived only to hold live descendants. Never replicated.
    Structural,
}

/// Where a leaf sits relative to the path that owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// At its own path.
    AtPath,
    /// A per-path loser at its conflict-copy sibling, as it would be with
    /// no tree constraint at all.
    ConflictCopy,
    /// The per-path winner, displaced to its conflict-copy sibling because
    /// its own path has to be a directory.
    Relocated,
}

/// A File or Symlink version placed somewhere in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacedEntry {
    pub kind: RecordKind,
    pub version_hash: [u8; 32],
    /// The explicit path this content belongs to. Equal to the node's own
    /// path exactly when `placement` is [`Placement::AtPath`].
    pub source: String,
    pub placement: Placement,
}

/// One node of the desired physical tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhysicalNode {
    Directory(DirectoryNode),
    Entry(PlacedEntry),
}

impl PhysicalNode {
    #[must_use]
    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
}

/// The desired physical tree: every present node keyed by its path. A path
/// with no node is absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceProjection {
    nodes: BTreeMap<String, PhysicalNode>,
}

impl NamespaceProjection {
    #[must_use]
    pub fn nodes(&self) -> &BTreeMap<String, PhysicalNode> {
        &self.nodes
    }

    /// Overwrites (or inserts) the node at `path`. For a caller-side
    /// post-processing layer ONLY (e.g. stable projection binding)
    /// -- this pure module's own `project`/`place`/`project_own_node`
    /// never call it; they stay pure, current-head-set-only functions with
    /// no memory of anything not in their own input.
    pub fn set(&mut self, path: impl Into<String>, node: PhysicalNode) {
        self.nodes.insert(path.into(), node);
    }

    /// Removes the node at `path`, if any. See [`Self::set`]'s doc: for a
    /// caller-side post-processing layer only.
    pub fn remove(&mut self, path: &str) -> Option<PhysicalNode> {
        self.nodes.remove(path)
    }

    #[must_use]
    pub fn get(&self, path: &str) -> Option<&PhysicalNode> {
        self.nodes.get(path)
    }
}

/// Computes the desired physical tree from the live heads of every path.
///
/// `heads` holds, per path, the live heads [`resolve_path_heads`] takes
/// (content heads and removing heads alike; paths absent from the map have
/// none). `kind_of` names the kind of a version hash; a content head whose
/// kind it cannot name fails the whole projection with
/// [`ProjectionError::Undecidable`].
///
/// The result depends on the head *sets* only: reordering the heads of any
/// path yields the same projection.
pub fn project(
    heads: &BTreeMap<String, Vec<PathHead>>,
    kind_of: impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<NamespaceProjection, ProjectionError> {
    // Per live path: its best Directory head and its File/Symlink contents.
    let mut classes: BTreeMap<&str, PathClasses<'_>> = BTreeMap::new();
    for (path, path_heads) in heads {
        if let Some(path_classes) = classify_path(path, path_heads, &kind_of)? {
            classes.insert(path, path_classes);
        }
    }

    // NeedsDirectory: an explicit Directory head, or any live descendant.
    let mut needs_directory: BTreeSet<&str> = BTreeSet::new();
    for (path, path_classes) in &classes {
        if path_classes.best_directory.is_some() {
            needs_directory.insert(path);
        }
        needs_directory.extend(proper_ancestors(path));
    }
    place(&classes, &needs_directory, &kind_of)
}

/// Places every directory and leaf once the directories are known.
fn place(
    classes: &BTreeMap<&str, PathClasses<'_>>,
    needs_directory: &BTreeSet<&str>,
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<NamespaceProjection, ProjectionError> {
    let mut nodes: BTreeMap<String, PhysicalNode> = BTreeMap::new();
    for path in needs_directory {
        let node = match classes.get(path).and_then(|c| c.best_directory) {
            Some(head) => DirectoryNode::Explicit { version_hash: content_of(head).version_hash },
            None => DirectoryNode::Structural,
        };
        nodes.insert((*path).to_string(), PhysicalNode::Directory(node));
    }

    // Leaves that keep their own path claim it before any copy is named.
    let mut copies: Vec<CopyClaim<'_>> = Vec::new();
    for (path, path_classes) in classes {
        let displaced = needs_directory.contains(path);
        for (head, placement) in &path_classes.leaf_heads {
            let kind = kind_of_head(path, head, kind_of)?;
            let content = content_of(head);
            let placement = match placement {
                Placement::AtPath if !displaced => {
                    nodes.insert(
                        (*path).to_string(),
                        PhysicalNode::Entry(PlacedEntry {
                            kind,
                            version_hash: content.version_hash,
                            source: (*path).to_string(),
                            placement: Placement::AtPath,
                        }),
                    );
                    continue;
                }
                Placement::AtPath => Placement::Relocated,
                other => *other,
            };
            copies.push(CopyClaim {
                name: conflict_copy_name(path, head, None),
                source: path,
                head,
                kind,
                placement,
            });
        }
    }

    // Copies take their names in an order fixed by the explicit state
    // alone; a taken name retries with a numbered disambiguator.
    copies.sort_by(|a, b| {
        (&a.name, a.source, content_of(a.head).version_hash).cmp(&(
            &b.name,
            b.source,
            content_of(b.head).version_hash,
        ))
    });
    for claim in copies {
        // A loser whose bytes an explicit entry already holds at this exact
        // name (an authored conflict copy of it) is materialized already.
        let version_hash = content_of(claim.head).version_hash;
        if claim.placement == Placement::ConflictCopy
            && matches!(
                nodes.get(&claim.name),
                Some(PhysicalNode::Entry(held))
                    if held.placement == Placement::AtPath && held.version_hash == version_hash
            )
        {
            continue;
        }
        let mut name = claim.name;
        let mut attempt = 2u32;
        while nodes.contains_key(&name) {
            name = conflict_copy_name(claim.source, claim.head, Some(attempt));
            attempt += 1;
        }
        nodes.insert(
            name,
            PhysicalNode::Entry(PlacedEntry {
                kind: claim.kind,
                version_hash,
                source: claim.source.to_string(),
                placement: claim.placement,
            }),
        );
    }
    Ok(NamespaceProjection { nodes })
}

/// The node `path` holds on its own account: what [`project`] places at
/// `path` for `path`'s own heads, leaving aside a conflict copy of some
/// other path that may be named there.
///
/// Everything that decides it is local to `path` except one bit: whether
/// any proper descendant of `path` has a live content head. So a caller
/// holding a store of per-path heads can answer it with one path's heads
/// and one existence query below it, instead of projecting the subtree.
///
/// * a live Directory head at `path` makes it an explicit directory with
///   the best-ranked Directory head's version, whatever else is there;
/// * otherwise a live descendant makes it a structural directory (the
///   per-path winner, if any, is relocated to its copy name);
/// * otherwise the per-path winner stays at `path`, or nothing does.
///
/// Fails exactly when [`project`] would fail on `path`'s heads.
pub fn project_own_node(
    path: &str,
    heads: &[PathHead],
    has_live_descendant: bool,
    kind_of: impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<Option<PhysicalNode>, ProjectionError> {
    let Some(classes) = classify_path(path, heads, &kind_of)? else {
        return Ok(
            has_live_descendant.then_some(PhysicalNode::Directory(DirectoryNode::Structural))
        );
    };
    if let Some(head) = classes.best_directory {
        return Ok(Some(PhysicalNode::Directory(DirectoryNode::Explicit {
            version_hash: content_of(head).version_hash,
        })));
    }
    if has_live_descendant {
        return Ok(Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    }
    for (head, placement) in &classes.leaf_heads {
        if *placement == Placement::AtPath {
            return Ok(Some(PhysicalNode::Entry(PlacedEntry {
                kind: kind_of_head(path, head, &kind_of)?,
                version_hash: content_of(head).version_hash,
                source: path.to_string(),
                placement: Placement::AtPath,
            })));
        }
    }
    Ok(None)
}

/// Splits one path's live heads into its best Directory head and its
/// File/Symlink contents. `None` when the path resolves absent.
fn classify_path<'a>(
    path: &str,
    path_heads: &'a [PathHead],
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<Option<PathClasses<'a>>, ProjectionError> {
    let PathResolution::Present { winner, conflict_copies } = resolve_path_heads(path, path_heads)
    else {
        return Ok(None);
    };
    let mut best_directory: Option<&PathHead> = None;
    let mut leaf_heads: Vec<(&PathHead, Placement)> = Vec::new();
    let candidates = std::iter::once((winner, true))
        .chain(conflict_copies.iter().map(|copy| (copy.head, false)));
    for (index, is_winner) in candidates {
        let head = &path_heads[index];
        match kind_of_head(path, head, kind_of)? {
            RecordKind::Directory => {}
            _ if is_winner => leaf_heads.push((head, Placement::AtPath)),
            _ => leaf_heads.push((head, Placement::ConflictCopy)),
        }
    }
    // Every Directory head competes for the directory's metadata, not
    // only the class representatives the resolver reports: the winner
    // is the best-ranked Directory head of all.
    for head in path_heads.iter().filter(|h| h.content.is_some()) {
        if kind_of_head(path, head, kind_of)? == RecordKind::Directory
            && best_directory.is_none_or(|best| ranks_below(best, head))
        {
            best_directory = Some(head);
        }
    }
    Ok(Some(PathClasses { best_directory, leaf_heads }))
}

/// One path's content, split the way the tree needs it.
struct PathClasses<'a> {
    /// The best-ranked live Directory head, if any.
    best_directory: Option<&'a PathHead>,
    /// One representative head per distinct File/Symlink version: the
    /// per-path winner as `AtPath`, the resolver's losers as
    /// `ConflictCopy`. Directory losers are absent: they yield to the
    /// winning directory's metadata and are owed no copy.
    leaf_heads: Vec<(&'a PathHead, Placement)>,
}

/// A leaf that has to live at a conflict-copy sibling of `source`.
struct CopyClaim<'a> {
    name: String,
    source: &'a str,
    head: &'a PathHead,
    kind: RecordKind,
    placement: Placement,
}

fn content_of(head: &PathHead) -> &PathHeadContent {
    head.content.as_ref().expect("only content heads are classified")
}

fn ranks_below(a: &PathHead, b: &PathHead) -> bool {
    dag_conflict_loser_is_a(a.rank, &a.change_hash, b.rank, &b.change_hash)
}

fn kind_of_head(
    path: &str,
    head: &PathHead,
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<RecordKind, ProjectionError> {
    let version_hash = content_of(head).version_hash;
    kind_of(&version_hash)
        .ok_or_else(|| ProjectionError::Undecidable { path: path.to_string(), version_hash })
}

/// The conflict-copy sibling of `path` for `head`'s content, with the
/// numbered disambiguator folded into the device field when one is needed.
/// Only the device field changes, so the name still reads back as a copy
/// of `path` through the domain's copy-name parsers.
fn conflict_copy_name(path: &str, head: &PathHead, attempt: Option<u32>) -> String {
    let content = content_of(head);
    let device = match attempt {
        None => head.naming_device_id.clone(),
        Some(n) => format!("{} {n}", head.naming_device_id),
    };
    conflict_copy_path_for_losing_change(
        path,
        &device,
        content.mtime_unix_nanos,
        &content.version_hash,
    )
}

/// Every proper ancestor of `path`, nearest first.
fn proper_ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(parent_of(path), |p| parent_of(p))
}

fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

#[cfg(test)]
mod tests;
