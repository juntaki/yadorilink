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
//!
//! # Plans
//!
//! [`plan_transition`] turns two projections into an ordered list of
//! filesystem steps that is valid under POSIX rules at every intermediate
//! point: leaf removals, then directory removals deepest first, then
//! relocations, then directory creations shallowest first, then entry
//! writes shallowest first.

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

/// [`project`] restricted to one directory level: the nodes whose parent
/// is the parent of every path in `children`.
///
/// `children` holds the live heads of each path at that level (every key
/// must have the same parent); `with_live_descendant` names the paths at
/// that level that have a live content head strictly below them. That is
/// everything that decides the level: a node is a path's own account plus
/// the copies of its siblings, and a copy is always named beside its
/// source, so no path deeper or elsewhere can take a name here. The
/// result equals [`project`]'s nodes at this level, for a caller that
/// holds a store of per-path heads and must not read the whole group to
/// learn where one relocated file lives.
pub fn project_level(
    children: &BTreeMap<String, Vec<PathHead>>,
    with_live_descendant: &BTreeSet<String>,
    kind_of: impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<NamespaceProjection, ProjectionError> {
    debug_assert!(
        children
            .keys()
            .chain(with_live_descendant.iter())
            .map(|path| parent_of(path))
            .collect::<BTreeSet<_>>()
            .len()
            <= 1,
        "a level's paths share one parent"
    );
    let mut classes: BTreeMap<&str, PathClasses<'_>> = BTreeMap::new();
    for (path, path_heads) in children {
        if let Some(path_classes) = classify_path(path, path_heads, &kind_of)? {
            classes.insert(path, path_classes);
        }
    }
    let mut needs_directory: BTreeSet<&str> =
        with_live_descendant.iter().map(String::as_str).collect();
    for (path, path_classes) in &classes {
        if path_classes.best_directory.is_some() {
            needs_directory.insert(path);
        }
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
    dag_conflict_loser_is_a(a.lamport, &a.change_hash, b.lamport, &b.change_hash)
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

/// The name [`project`] gives `head`'s content when it has to leave
/// `path` (relocated, or a conflict copy) and nothing else has taken that
/// name: its conflict-copy sibling, before any numbered disambiguator.
#[must_use]
pub fn first_copy_name(path: &str, head: &PathHead) -> String {
    conflict_copy_name(path, head, None)
}

/// Every proper ancestor of `path`, nearest first.
fn proper_ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(parent_of(path), |p| parent_of(p))
}

fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

/// Number of components; the unit plans order by.
fn depth(path: &str) -> usize {
    path.bytes().filter(|b| *b == b'/').count() + 1
}

/// One filesystem step of a transition between two projections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanStep {
    /// Unlink the File or Symlink at `path`.
    RemoveEntry { path: String },
    /// Remove the directory at `path`, never recursively.
    ///
    /// Every tracked descendant has been removed or moved out by an earlier
    /// step, so anything still inside when this runs is content the
    /// replicated state does not know about. The materializer must then
    /// keep the directory and settle it as retained; it must not delete
    /// that content and must not retry forever.
    RemoveDirectory { path: String },
    /// Rename the entry at `from` to `to` (a relocation, or its reverse).
    /// Both ends share a parent directory.
    Move { from: String, to: String, entry: PlacedEntry },
    /// Create a directory that did not exist.
    CreateDirectory { path: String, node: DirectoryNode },
    /// A directory that stays a directory but changes how it is held
    /// (explicit ↔ structural, or a different explicit version). Never an
    /// rmdir.
    UpdateDirectory { path: String, node: DirectoryNode },
    /// Write `entry` at `path`, replacing any leaf already there.
    WriteEntry { path: String, entry: PlacedEntry },
}

/// Orders the filesystem steps that turn `prev` into `next`.
///
/// Steps describe the filesystem only. A leaf that keeps its name and
/// content while its [`Placement`] changes (a conflict copy that becomes
/// the displaced winner, or the reverse) needs no step; the caller reads
/// placement from `next`.
pub fn plan_transition(prev: &NamespaceProjection, next: &NamespaceProjection) -> Vec<PlanStep> {
    // A leaf's identity across the two trees: the same content of the
    // same source path (the version fixes the kind). Found at two
    // different places, it moved.
    let key_of = |entry: &PlacedEntry| (entry.source.clone(), entry.version_hash);
    let leaves = |projection: &NamespaceProjection| -> BTreeMap<_, String> {
        projection
            .nodes
            .iter()
            .filter_map(|(path, node)| match node {
                PhysicalNode::Entry(entry) => Some((key_of(entry), path.clone())),
                PhysicalNode::Directory(_) => None,
            })
            .collect()
    };
    let (prev_leaves, next_leaves) = (leaves(prev), leaves(next));

    let mut moves: Vec<(String, String, PlacedEntry)> = Vec::new();
    let mut move_destinations: BTreeSet<&str> = BTreeSet::new();
    for (key, from) in &prev_leaves {
        if let Some(to) = next_leaves.get(key).filter(|to| *to != from) {
            let Some(PhysicalNode::Entry(entry)) = next.nodes.get(to) else {
                unreachable!("next_leaves only indexes entries")
            };
            moves.push((from.clone(), to.clone(), entry.clone()));
            move_destinations.insert(to);
        }
    }

    let mut remove_entries: Vec<&str> = Vec::new();
    let mut remove_directories: Vec<&str> = Vec::new();
    for (path, node) in &prev.nodes {
        let after = next.nodes.get(path);
        match node {
            PhysicalNode::Entry(entry) => {
                if next_leaves.contains_key(&key_of(entry)) {
                    continue; // stays, or moves
                }
                // A leaf written in place replaces this one; anything else
                // arriving here needs the name free first.
                let replaced_in_place = matches!(after, Some(PhysicalNode::Entry(_)))
                    && !move_destinations.contains(path.as_str());
                if !replaced_in_place {
                    remove_entries.push(path);
                }
            }
            PhysicalNode::Directory(_) => {
                if !after.is_some_and(PhysicalNode::is_directory) {
                    remove_directories.push(path);
                }
            }
        }
    }
    let deepest_first = |a: &&str, b: &&str| depth(b).cmp(&depth(a)).then_with(|| b.cmp(a));
    remove_entries.sort_by(deepest_first);
    remove_directories.sort_by(deepest_first);

    let mut steps: Vec<PlanStep> = Vec::new();
    steps
        .extend(remove_entries.iter().map(|path| PlanStep::RemoveEntry { path: path.to_string() }));
    steps.extend(
        remove_directories.iter().map(|path| PlanStep::RemoveDirectory { path: path.to_string() }),
    );

    // Moves, each only once its destination is free. A cycle of moves
    // (never produced by distinct copy names in practice) is broken by
    // unlinking one source and writing its content afresh at the end;
    // the content is addressed by version, so nothing is lost.
    //
    // Always the smallest `(from, to)` move that is ready, and when none
    // is, the cycle is broken at the smallest remaining move. Sources are
    // distinct, and so are destinations, so freeing a source readies at
    // most the one move that targets it.
    let mut late_writes: Vec<(String, PlacedEntry)> = Vec::new();
    moves.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let source_index: BTreeMap<&str, usize> =
        moves.iter().enumerate().map(|(i, m)| (m.0.as_str(), i)).collect();
    let destination_index: BTreeMap<&str, usize> =
        moves.iter().enumerate().map(|(i, m)| (m.1.as_str(), i)).collect();
    let mut remaining: BTreeSet<usize> = (0..moves.len()).collect();
    let mut ready: BTreeSet<usize> =
        (0..moves.len()).filter(|&i| !source_index.contains_key(moves[i].1.as_str())).collect();
    let mut move_steps: Vec<PlanStep> = Vec::with_capacity(moves.len());
    while let Some(&first) = remaining.first() {
        let (index, is_ready) = match ready.pop_first() {
            Some(index) => (index, true),
            None => (first, false),
        };
        remaining.remove(&index);
        let (from, to, entry) = &moves[index];
        if let Some(&unblocked) = destination_index.get(from.as_str()) {
            if remaining.contains(&unblocked) {
                ready.insert(unblocked);
            }
        }
        if is_ready {
            move_steps.push(PlanStep::Move {
                from: from.clone(),
                to: to.clone(),
                entry: entry.clone(),
            });
        } else {
            move_steps.push(PlanStep::RemoveEntry { path: from.clone() });
            late_writes.push((to.clone(), entry.clone()));
        }
    }
    steps.extend(move_steps);

    let mut directories: Vec<(&str, DirectoryNode, bool)> = Vec::new();
    let mut writes: Vec<(String, PlacedEntry)> = late_writes;
    for (path, node) in &next.nodes {
        let before = prev.nodes.get(path);
        match node {
            PhysicalNode::Directory(directory) => match before {
                Some(PhysicalNode::Directory(existing)) if existing == directory => {}
                Some(PhysicalNode::Directory(_)) => directories.push((path, *directory, false)),
                _ => directories.push((path, *directory, true)),
            },
            PhysicalNode::Entry(entry) => {
                let key = key_of(entry);
                let stays = prev_leaves.get(&key) == Some(path);
                let moved_here = prev_leaves.contains_key(&key);
                if !stays && !moved_here {
                    writes.push((path.clone(), entry.clone()));
                }
            }
        }
    }
    directories.sort_by(|a, b| depth(a.0).cmp(&depth(b.0)).then_with(|| a.0.cmp(b.0)));
    writes.sort_by(|a, b| depth(&a.0).cmp(&depth(&b.0)).then_with(|| a.0.cmp(&b.0)));
    steps.extend(directories.into_iter().map(|(path, node, create)| {
        let path = path.to_string();
        if create {
            PlanStep::CreateDirectory { path, node }
        } else {
            PlanStep::UpdateDirectory { path, node }
        }
    }));
    steps.extend(writes.into_iter().map(|(path, entry)| PlanStep::WriteEntry { path, entry }));
    steps
}

#[cfg(test)]
mod tests;
