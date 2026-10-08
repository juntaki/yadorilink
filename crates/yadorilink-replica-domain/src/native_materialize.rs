//! Single-node projection (`project_own_node`) — turning one path's [`LiveHead`]s plus "does a
//! live descendant exist" into what the tree constraint places at that
//! path.
//!
//! Reuses [`crate::native_state::resolve_path`] for the per-path fold
//! (winner + one representative per distinct losing version) and adds
//! exactly the tree-constraint rule: a directory beats a
//! file. `RecordKind` is looked up externally, via the local file-version
//! store (`kind_of`) — it is not, and does not need to become, part of
//! [`crate::native_state::HeadPayload`].
//!
//! # Scope — what this covers
//!
//! * **`NeedsDirectory`**: a live Directory head, or `has_live_descendant`.
//! * **Explicit vs. Structural directory**: the highest-version live Directory
//!   head (independent of the overall per-path winner/loser fold — a
//!   Directory head competes for the directory's own metadata against
//!   every other Directory head, not against File/Symlink content) decides
//!   [`DirectoryNode::Explicit`]; otherwise, if a directory is needed at
//!   all, [`DirectoryNode::Structural`].
//! * **A directory beats a file, whatever its version**: when a directory is
//!   needed at this path (explicit or structural), the File/Symlink winner
//!   is not placed here at all — this function returns the directory node
//!   only (it does not
//!   itself compute *where* the displaced winner ends up; that needs the
//!   whole-tree `place` algorithm, which this module does not have —
//!   `Placement::Relocated` exists on [`PlacedEntry`], but only a future
//!   whole-tree function would ever construct it here).
//! * **Tombstone-doesn't-delete-subtree**: falls out for free, since
//!   `has_live_descendant` is an independent input the caller supplies —
//!   a Directory tombstone with a live descendant still yields
//!   `Structural`.
//!
//! # Scope — explicitly NOT covered here, deferred
//!
//! * The whole-tree function (`project`) that computes
//!   `NeedsDirectory` and conflict-copy name collisions across an entire
//!   subtree at once — this module only has the single-node primitive
//!   (which needs one path's heads and one existence query below it, not
//!   the whole subtree).
//! * **Copy-name collision disambiguation** (numbered `<device> 2`,
//!   `<device> 3`, … retries) and **"an authored copy is the copy"
//!   folding** — both are about *which path string* a conflict copy is
//!   given, which native does not attempt to make byte-identical across
//!   replicas (see `native_state::resolve_path`'s own doc: this
//!   is a materialization-time cosmetic detail compared by content set,
//!   not exact path).

use std::collections::{BTreeMap, BTreeSet};

use crate::file::RecordKind;
use crate::ids::{SyncPath, VersionHash};
use crate::native_state::{
    is_under, resolve_path, win_key, Dot, LiveHead, PathHeads, PathMaterialization, WinKey,
};

/// A live content head's kind could not be determined (its version is not
/// locally resolvable) — fail closed, matching
/// `yadorilink_replica_engine::namespace::ProjectionError::Undecidable`:
/// a partial answer is not a tree anyone may materialize.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("kind of version {version:?} at this path is undecidable")]
pub struct Undecidable {
    pub version: VersionHash,
}

/// How a directory at this path came to be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirectoryNode {
    Explicit { version: VersionHash },
    Structural,
}

/// Where a leaf sits relative to the path that owns it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Placement {
    AtPath,
    ConflictCopy,
    Relocated,
}

/// A File or Symlink version placed at (or displaced from) this path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlacedEntry {
    pub kind: RecordKind,
    pub version: VersionHash,
    /// The dot whose content this entry places — identifies which live
    /// head this entry came from, for a caller that needs to name a
    /// conflict-copy sibling from it.
    pub source_dot: Dot,
    pub placement: Placement,
}

/// One node of the desired physical tree at one path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PhysicalNode {
    Directory(DirectoryNode),
    Entry(PlacedEntry),
}

/// The node this path holds on its own account: local heads plus one
/// existence bit below, nothing else.
///
/// * a live Directory head (the highest-version one, if several) makes this an
///   explicit directory, whatever else is live here;
/// * otherwise `has_live_descendant` makes it a structural directory (this
///   function reports only that a directory is needed here — where a
///   displaced File/Symlink winner ends up is the whole-tree algorithm's
///   question, not this one's);
/// * otherwise the per-path winner ([`crate::native_state::resolve_path`])
///   stays [`Placement::AtPath`], or nothing is here at all.
pub fn project_own_node(
    heads: impl IntoIterator<Item = LiveHead>,
    has_live_descendant: bool,
    kind_of: impl Fn(&VersionHash) -> Option<RecordKind>,
) -> Result<Option<PhysicalNode>, Undecidable> {
    let heads: Vec<LiveHead> = heads.into_iter().collect();

    let mut best: Option<WinKey> = None;
    for head in &heads {
        let is_directory = match kind_of(&head.payload.version) {
            Some(kind) => kind == RecordKind::Directory,
            None => return Err(Undecidable { version: head.payload.version }),
        };
        let key = win_key(is_directory, head.payload.version);
        best = best.max(Some(key));
    }
    // The maximum key is a directory exactly when any live head is one: a
    // directory beats every file whatever the versions.
    if let Some(WinKey { is_directory: true, version }) = best {
        return Ok(Some(PhysicalNode::Directory(DirectoryNode::Explicit { version })));
    }
    if has_live_descendant {
        return Ok(Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    }

    match resolve_path(heads.clone()) {
        PathMaterialization::Absent => Ok(None),
        PathMaterialization::Present { winner, .. } => {
            let winner_head =
                heads.iter().find(|h| h.dot == winner).expect("winner is one of heads");
            let kind = kind_of(&winner_head.payload.version)
                .ok_or(Undecidable { version: winner_head.payload.version })?;
            Ok(Some(PhysicalNode::Entry(PlacedEntry {
                kind,
                version: winner_head.payload.version,
                source_dot: winner,
                placement: Placement::AtPath,
            })))
        }
    }
}

fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

/// Every path with a node in native's desired tree, in one pass over the
/// group's full per-path head map (`NativeState.heads`'s own shape, so a
/// caller can pass it directly) — built from repeated [`project_own_node`] calls, one per
/// candidate path (every path with its own live heads, plus every proper
/// ancestor of one, exactly the set [`project_own_node`]'s
/// `has_live_descendant` bit needs to be computed against).
///
/// Scoped exactly as [`project_own_node`]/[`crate::native_state::resolve_path`]
/// already are: a path's own node only, content set (kind + version), never
/// a conflict-copy path name — assigning and disambiguating copy names across the whole subtree at
/// once is not attempted here (see those two functions' docs for why).
pub fn project(
    heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    kind_of: impl Fn(&VersionHash) -> Option<RecordKind>,
) -> Result<BTreeMap<SyncPath, PhysicalNode>, Undecidable> {
    let mut candidate_paths: BTreeSet<String> = BTreeSet::new();
    for path in heads_by_path.keys() {
        let mut current = path.as_str();
        candidate_paths.insert(current.to_owned());
        while let Some(parent) = parent_of(current) {
            if !candidate_paths.insert(parent.to_owned()) {
                break; // this ancestor chain is already covered.
            }
            current = parent;
        }
    }

    let mut nodes = BTreeMap::new();
    for path in &candidate_paths {
        let live_heads: Vec<LiveHead> = heads_by_path
            .get(&SyncPath(path.clone()))
            .into_iter()
            .flat_map(|heads| {
                heads
                    .iter()
                    .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
            })
            .collect();
        let has_live_descendant = heads_by_path
            .keys()
            .any(|other| other.as_str() != path.as_str() && is_under(other.as_str(), path));
        if let Some(node) = project_own_node(live_heads, has_live_descendant, &kind_of)? {
            nodes.insert(SyncPath(path.clone()), node);
        }
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::author::{AuthorId, IncarnationId};
    use crate::ids::{AuthorSeq, DeviceId};
    use crate::native_state::{DeltaHash, HeadPayload};

    fn author(name: &str) -> AuthorId {
        AuthorId { device: DeviceId(name.to_owned()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn head(a: &str, seq: u64, version_byte: u8) -> LiveHead {
        LiveHead {
            dot: Dot { author: author(a), seq: AuthorSeq(seq) },
            payload: HeadPayload {
                version: VersionHash([version_byte; 32]),
                provenance: DeltaHash([version_byte; 32]),
            },
        }
    }

    fn kind_file(_: &VersionHash) -> Option<RecordKind> {
        Some(RecordKind::File)
    }

    #[test]
    fn no_heads_no_descendant_is_absent() {
        assert_eq!(project_own_node([], false, kind_file).unwrap(), None);
    }

    #[test]
    fn a_live_descendant_alone_makes_a_structural_directory() {
        let node = project_own_node([], true, kind_file).unwrap();
        assert_eq!(node, Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    }

    #[test]
    fn a_lone_file_head_stays_at_its_own_path() {
        let h = head("a", 1, 1);
        let dot = h.dot.clone();
        let node = project_own_node([h], false, kind_file).unwrap();
        assert_eq!(
            node,
            Some(PhysicalNode::Entry(PlacedEntry {
                kind: RecordKind::File,
                version: VersionHash([1u8; 32]),
                source_dot: dot,
                placement: Placement::AtPath,
            }))
        );
    }

    /// The core tree-constraint rule: a live descendant beats a File
    /// winner at this path, whatever its version — the file is relocated
    /// (this test asserts absence of an `AtPath` node here; a full
    /// relocation-siblings test lives at the differential level).
    #[test]
    fn a_live_descendant_beats_a_file_whatever_its_version() {
        let h = head("a", 1, 200);
        let node = project_own_node([h], true, kind_file).unwrap();
        assert_eq!(node, Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    }

    #[test]
    fn a_directory_head_wins_over_a_live_descendant_flag_and_over_files() {
        fn kind_mixed(v: &VersionHash) -> Option<RecordKind> {
            if v.0[0] == 9 {
                Some(RecordKind::Directory)
            } else {
                Some(RecordKind::File)
            }
        }
        let dir_head = head("a", 1, 9);
        let file_head = head("b", 1, 200); // higher version, but a file never beats a directory
        let node = project_own_node([dir_head, file_head], true, kind_mixed).unwrap();
        assert_eq!(
            node,
            Some(PhysicalNode::Directory(DirectoryNode::Explicit {
                version: VersionHash([9u8; 32])
            }))
        );
    }

    #[test]
    fn undecidable_kind_fails_closed() {
        let h = head("a", 1, 1);
        let err = project_own_node([h], false, |_| None).unwrap_err();
        assert_eq!(err, Undecidable { version: VersionHash([1u8; 32]) });
    }

    fn heads_map(entries: Vec<(&str, Vec<LiveHead>)>) -> BTreeMap<SyncPath, PathHeads> {
        entries
            .into_iter()
            .map(|(path, heads)| {
                let mut m = PathHeads::new();
                for h in heads {
                    m.insert(h.dot, h.payload);
                }
                (SyncPath(path.to_owned()), m)
            })
            .collect()
    }

    /// A structural directory gets a node even though it has no live heads
    /// of its own at all -- only a live descendant three levels down.
    #[test]
    fn project_gives_every_ancestor_a_structural_node_even_with_no_heads_of_its_own() {
        let heads = heads_map(vec![("a/b/c", vec![head("x", 1, 1)])]);
        let nodes = project(&heads, kind_file).unwrap();
        assert_eq!(
            nodes.get(&SyncPath("a".into())),
            Some(&PhysicalNode::Directory(DirectoryNode::Structural))
        );
        assert_eq!(
            nodes.get(&SyncPath("a/b".into())),
            Some(&PhysicalNode::Directory(DirectoryNode::Structural))
        );
        assert!(matches!(nodes.get(&SyncPath("a/b/c".into())), Some(PhysicalNode::Entry(_))));
    }

    #[test]
    fn project_of_empty_state_is_empty() {
        let heads: BTreeMap<SyncPath, PathHeads> = BTreeMap::new();
        assert!(project(&heads, kind_file).unwrap().is_empty());
    }

    /// Two unrelated files at the top level each get their own node,
    /// independent of each other.
    #[test]
    fn project_places_unrelated_top_level_files_independently() {
        let heads = heads_map(vec![("a", vec![head("x", 1, 1)]), ("b", vec![head("y", 1, 2)])]);
        let nodes = project(&heads, kind_file).unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes.get(&SyncPath("a".into())), Some(PhysicalNode::Entry(_))));
        assert!(matches!(nodes.get(&SyncPath("b".into())), Some(PhysicalNode::Entry(_))));
    }
}
