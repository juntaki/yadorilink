#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use yadorilink_replica_domain::conflict::{
    conflict_copy_source_path, conflict_copy_stem_was_truncated, is_conflict_copy_path,
};
use yadorilink_replica_domain::file::RecordKind;

use super::*;
use crate::conflict::{conflict_copy_path_for_losing_change, PathHead, PathHeadContent};

const FILE_1: [u8; 32] = [0x11; 32];
const FILE_2: [u8; 32] = [0x12; 32];
const DIR_1: [u8; 32] = [0xD1; 32];
const DIR_2: [u8; 32] = [0xD2; 32];
const LINK_1: [u8; 32] = [0x51; 32];
const UNKNOWN: [u8; 32] = [0xEE; 32];

fn kind_of(version: &[u8; 32]) -> Option<RecordKind> {
    match *version {
        FILE_1 | FILE_2 => Some(RecordKind::File),
        DIR_1 | DIR_2 => Some(RecordKind::Directory),
        LINK_1 => Some(RecordKind::Symlink),
        _ => None,
    }
}

/// A head of change `change` at `lamport`, landing `content` (or removing
/// the path when `None`).
fn head(change: u8, lamport: u64, device: &str, content: Option<[u8; 32]>) -> PathHead {
    let mut change_hash = [0u8; 32];
    change_hash[0] = change;
    PathHead {
        change_hash,
        rank: lamport,
        device_id: device.to_string(),
        naming_device_id: device.to_string(),
        content: content.map(|version_hash| PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
    }
}

fn put(change: u8, lamport: u64, version: [u8; 32]) -> PathHead {
    head(change, lamport, "dev-a", Some(version))
}

fn tomb(change: u8, lamport: u64) -> PathHead {
    head(change, lamport, "dev-a", None)
}

fn state(entries: Vec<(&str, Vec<PathHead>)>) -> BTreeMap<String, Vec<PathHead>> {
    entries.into_iter().map(|(path, heads)| (path.to_string(), heads)).collect()
}

fn proj(heads: &BTreeMap<String, Vec<PathHead>>) -> NamespaceProjection {
    project(heads, kind_of).expect("projection is decidable")
}

fn copy_name(path: &str, head: &PathHead) -> String {
    let content = head.content.as_ref().expect("content head");
    conflict_copy_path_for_losing_change(
        path,
        &head.naming_device_id,
        content.mtime_unix_nanos,
        &content.version_hash,
    )
}

fn at(projection: &NamespaceProjection, path: &str) -> Option<PhysicalNode> {
    projection.get(path).cloned()
}

fn entry(kind: RecordKind, version: [u8; 32], source: &str, placement: Placement) -> PhysicalNode {
    PhysicalNode::Entry(PlacedEntry {
        kind,
        version_hash: version,
        source: source.to_string(),
        placement,
    })
}

fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn proper_ancestors(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut current = path;
    while let Some(parent) = parent_of(current) {
        out.push(parent);
        current = parent;
    }
    out
}

// --- Invariant checkers --------------------------------------------------

/// Every rule the projection promises, checked against the explicit state
/// it was computed from:
///
/// * well-formed: every node's proper ancestors are directories;
/// * no spurious directories: a directory exists exactly where
///   `NeedsDirectory` holds, explicit exactly when a Directory head is live;
/// * no data loss: every distinct File/Symlink content at every path
///   appears exactly once, at its own path or at a conflict-copy sibling
///   of it, and nothing else is a leaf;
/// * directory metadata: an explicit directory carries its best-ranked
///   Directory head's version;
/// * the right leaf wins: at each path, the content head ranked highest by
///   `(lamport, change_hash)` is, when it is a File or Symlink, the one
///   leaf of that path at its own path (or `Relocated` when the path must
///   be a directory); every other leaf of that path is a `ConflictCopy`.
fn assert_projection_rules(
    heads: &BTreeMap<String, Vec<PathHead>>,
    projection: &NamespaceProjection,
    label: &str,
) {
    // Content classes per path, each path's winning content head, and
    // NeedsDirectory.
    let mut leaf_classes: BTreeSet<(String, [u8; 32])> = BTreeSet::new();
    let mut best_dir: BTreeMap<String, &PathHead> = BTreeMap::new();
    let mut winner: BTreeMap<String, &PathHead> = BTreeMap::new();
    let mut needs_dir: BTreeSet<String> = BTreeSet::new();
    for (path, path_heads) in heads {
        for h in path_heads {
            let Some(content) = &h.content else { continue };
            if winner
                .get(path)
                .is_none_or(|best| (best.rank, best.change_hash) < (h.rank, h.change_hash))
            {
                winner.insert(path.clone(), h);
            }
            for ancestor in proper_ancestors(path) {
                needs_dir.insert(ancestor.to_string());
            }
            if kind_of(&content.version_hash) == Some(RecordKind::Directory) {
                needs_dir.insert(path.clone());
                let better = best_dir
                    .get(path)
                    .is_none_or(|best| (best.rank, best.change_hash) < (h.rank, h.change_hash));
                if better {
                    best_dir.insert(path.clone(), h);
                }
            } else {
                leaf_classes.insert((path.clone(), content.version_hash));
            }
        }
    }

    for (path, node) in projection.nodes() {
        for ancestor in proper_ancestors(path) {
            assert!(
                projection.get(ancestor).is_some_and(PhysicalNode::is_directory),
                "{label}: ancestor {ancestor:?} of {path:?} is not a directory\n{projection:#?}"
            );
        }
        match node {
            PhysicalNode::Directory(directory) => {
                assert!(
                    needs_dir.contains(path),
                    "{label}: {path:?} is a directory nothing requires\n{projection:#?}"
                );
                let expected = match best_dir.get(path) {
                    Some(h) => DirectoryNode::Explicit {
                        version_hash: h.content.as_ref().expect("content").version_hash,
                    },
                    None => DirectoryNode::Structural,
                };
                assert_eq!(*directory, expected, "{label}: directory kind at {path:?}");
            }
            PhysicalNode::Entry(placed) => {
                assert_ne!(placed.kind, RecordKind::Directory, "{label}: directory placed as leaf");
                match placed.placement {
                    Placement::AtPath => {
                        assert_eq!(&placed.source, path, "{label}: AtPath away from its source");
                        assert!(
                            !needs_dir.contains(path),
                            "{label}: a leaf stayed at {path:?}, which must be a directory"
                        );
                    }
                    Placement::ConflictCopy | Placement::Relocated => {
                        assert!(
                            is_conflict_copy_path(path),
                            "{label}: {path:?} is not a copy name"
                        );
                        assert!(!conflict_copy_stem_was_truncated(path));
                        assert_eq!(
                            conflict_copy_source_path(path),
                            placed.source,
                            "{label}: copy {path:?} does not name its source"
                        );
                        assert_eq!(parent_of(path), parent_of(&placed.source));
                    }
                }
            }
        }
    }
    for directory in &needs_dir {
        assert!(
            projection.get(directory).is_some_and(PhysicalNode::is_directory),
            "{label}: {directory:?} needs to be a directory\n{projection:#?}"
        );
    }

    let mut placed: Vec<(String, [u8; 32])> = projection
        .nodes()
        .values()
        .filter_map(|node| match node {
            PhysicalNode::Entry(e) => Some((e.source.clone(), e.version_hash)),
            PhysicalNode::Directory(_) => None,
        })
        .collect();
    placed.sort();
    let distinct: BTreeSet<(String, [u8; 32])> = placed.iter().cloned().collect();
    assert_eq!(distinct.len(), placed.len(), "{label}: leaf duplicated\n{projection:#?}");
    for class in &distinct {
        assert!(leaf_classes.contains(class), "{label}: invented leaf {class:?}\n{projection:#?}");
    }
    // A losing content not placed on its own account is only acceptable
    // when an explicit entry already holds it at its deterministic copy
    // name: an authored conflict copy of that very loser.
    for (source, version) in leaf_classes.difference(&distinct) {
        let top = winner[source].content.as_ref().expect("content").version_hash;
        let preserved = *version != top
            && heads[source].iter().any(|h| {
                h.content.as_ref().is_some_and(|c| c.version_hash == *version)
                    && matches!(
                        projection.get(&copy_name(source, h)),
                        Some(PhysicalNode::Entry(e))
                            if e.placement == Placement::AtPath && e.version_hash == *version
                    )
            });
        assert!(preserved, "{label}: leaf content {version:?} of {source:?} lost\n{projection:#?}");
    }

    // Which leaf of each path wins, and how every other one is labelled.
    for (path, top) in &winner {
        let top_version = top.content.as_ref().expect("content").version_hash;
        let top_is_leaf = kind_of(&top_version) != Some(RecordKind::Directory);
        for (at_path, node) in projection.nodes() {
            let PhysicalNode::Entry(placed) = node else { continue };
            if &placed.source != path {
                continue;
            }
            let expected = if !(top_is_leaf && placed.version_hash == top_version) {
                Placement::ConflictCopy
            } else if needs_dir.contains(path) {
                Placement::Relocated
            } else {
                Placement::AtPath
            };
            assert_eq!(
                placed.placement, expected,
                "{label}: {at_path:?} (from {path:?}) is labelled wrongly\n{projection:#?}"
            );
        }
    }
}

// --- Exhaustive enumeration ---------------------------------------------

/// The head alphabet: a removal, two file versions, two directory
/// versions (a metadata conflict), and a symlink.
const ALPHABET: [Option<[u8; 32]>; 6] =
    [None, Some(FILE_1), Some(FILE_2), Some(DIR_1), Some(DIR_2), Some(LINK_1)];

/// Every ordered list of zero, one or two heads from the alphabet, so each
/// pair appears in both rank orders.
fn head_lists(path_index: u8) -> Vec<Vec<PathHead>> {
    let mut out = vec![Vec::new()];
    let mk = |position: u8, symbol: usize| {
        let content = ALPHABET[symbol];
        head(
            path_index * 16 + position * 8 + symbol as u8 + 1,
            u64::from(position) + 1,
            if position == 0 { "dev-a" } else { "dev-b" },
            content,
        )
    };
    for first in 0..ALPHABET.len() {
        out.push(vec![mk(0, first)]);
        for second in 0..ALPHABET.len() {
            out.push(vec![mk(0, first), mk(1, second)]);
        }
    }
    out
}

fn for_each_state(paths: &[&str], mut visit: impl FnMut(&BTreeMap<String, Vec<PathHead>>)) {
    let lists: Vec<Vec<Vec<PathHead>>> = (0..paths.len()).map(|i| head_lists(i as u8)).collect();
    let total: usize = lists.iter().map(Vec::len).product();
    for code in 0..total {
        let mut rest = code;
        let mut map = BTreeMap::new();
        for (i, path) in paths.iter().enumerate() {
            let choice = &lists[i][rest % lists[i].len()];
            rest /= lists[i].len();
            if !choice.is_empty() {
                map.insert((*path).to_string(), choice.clone());
            }
        }
        visit(&map);
    }
}

/// The path trees the exhaustive properties run over: a three-deep chain,
/// and a parent whose child sorts after a sibling that shares its prefix.
const TREES: [[&str; 3]; 2] = [["a", "a/x", "a/x/y"], ["a", "a b", "a/x"]];

#[test]
fn projection_is_function_of_resolve() {
    for tree in TREES {
        for_each_state(&tree, |heads| {
            let forward = proj(heads);
            let reversed: BTreeMap<String, Vec<PathHead>> = heads
                .iter()
                .map(|(path, hs)| (path.clone(), hs.iter().rev().cloned().collect()))
                .collect();
            assert_eq!(forward, proj(&reversed), "head order changed the projection: {heads:?}");
            // Removing heads never shows: a removal that is only concurrent
            // with content is not what decides the tree.
            let content_only: BTreeMap<String, Vec<PathHead>> = heads
                .iter()
                .map(|(path, hs)| {
                    (path.clone(), hs.iter().filter(|h| h.content.is_some()).cloned().collect())
                })
                .collect();
            assert_eq!(forward, proj(&content_only), "a tombstone changed the tree: {heads:?}");
        });
    }
}

#[test]
fn projection_never_drops_a_live_head() {
    for tree in TREES {
        for_each_state(&tree, |heads| {
            assert_projection_rules(heads, &proj(heads), &format!("{heads:?}"));
        });
    }
}

// --- Named cases ---------------------------------------------------------

#[test]
fn projection_prefers_directory_when_live_descendant_exists() {
    let file_a = put(1, 1, FILE_1);
    let heads = state(vec![("a", vec![file_a.clone()]), ("a/x", vec![put(2, 1, FILE_2)])]);
    let projection = proj(&heads);
    assert_eq!(at(&projection, "a"), Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    assert_eq!(
        at(&projection, "a/x"),
        Some(entry(RecordKind::File, FILE_2, "a/x", Placement::AtPath))
    );
    assert_eq!(
        at(&projection, &copy_name("a", &file_a)),
        Some(entry(RecordKind::File, FILE_1, "a", Placement::Relocated))
    );
    assert_eq!(projection.nodes().len(), 3);
    assert_projection_rules(&heads, &projection, "file a vs a/x");
}

#[test]
fn deleted_explicit_directory_with_live_child_projects_structural() {
    let heads = state(vec![("a", vec![tomb(3, 3)]), ("a/x", vec![put(2, 2, FILE_1)])]);
    let projection = proj(&heads);
    assert_eq!(at(&projection, "a"), Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    assert_eq!(projection.nodes().len(), 2);
}

#[test]
fn symlink_vs_descendant_relocates_symlink() {
    let link = put(1, 9, LINK_1);
    let heads = state(vec![("a", vec![link.clone()]), ("a/x", vec![put(2, 1, FILE_1)])]);
    let projection = proj(&heads);
    assert_eq!(at(&projection, "a"), Some(PhysicalNode::Directory(DirectoryNode::Structural)));
    assert_eq!(
        at(&projection, &copy_name("a", &link)),
        Some(entry(RecordKind::Symlink, LINK_1, "a", Placement::Relocated))
    );
}

#[test]
fn directory_beats_file_at_same_path_without_descendants() {
    // The File ranks higher, so the per-path resolver alone would put it at
    // `a`. The live Directory head still makes `a` a directory.
    let file = put(2, 5, FILE_1);
    let heads = state(vec![("a", vec![put(1, 1, DIR_1), file.clone()])]);
    let projection = proj(&heads);
    assert_eq!(
        at(&projection, "a"),
        Some(PhysicalNode::Directory(DirectoryNode::Explicit { version_hash: DIR_1 }))
    );
    assert_eq!(
        at(&projection, &copy_name("a", &file)),
        Some(entry(RecordKind::File, FILE_1, "a", Placement::Relocated))
    );
    assert_eq!(projection.nodes().len(), 2);

    // And when the Directory ranks higher, the File is an ordinary copy.
    let file = put(1, 1, FILE_1);
    let heads = state(vec![("a", vec![file.clone(), put(2, 5, DIR_1)])]);
    let projection = proj(&heads);
    assert_eq!(
        at(&projection, &copy_name("a", &file)),
        Some(entry(RecordKind::File, FILE_1, "a", Placement::ConflictCopy))
    );
}

/// DIR-1: an ExplicitDirectory keeps its path against a File or Symlink
/// there in either rank order, with or without a live descendant, and
/// the leaf moves to its copy name. No node is ever a directory at a
/// copy name: a Directory is never copied, only a leaf.
#[test]
fn explicit_directory_keeps_the_path_against_a_file_or_symlink_in_either_rank_order() {
    for leaf_version in [FILE_1, LINK_1] {
        let leaf_kind = kind_of(&leaf_version).expect("known kind");
        for leaf_ranks_higher in [true, false] {
            for with_descendant in [false, true] {
                let (leaf, directory) = if leaf_ranks_higher {
                    (head(2, 5, "dev-b", Some(leaf_version)), put(1, 1, DIR_1))
                } else {
                    (head(1, 1, "dev-b", Some(leaf_version)), put(2, 5, DIR_1))
                };
                let mut entries = vec![("a", vec![leaf.clone(), directory])];
                if with_descendant {
                    entries.push(("a/x", vec![put(3, 1, FILE_2)]));
                }
                let heads = state(entries);
                let projection = proj(&heads);
                let label = format!(
                    "{leaf_kind:?} ranks higher: {leaf_ranks_higher}, a/x: {with_descendant}"
                );
                assert_eq!(
                    at(&projection, "a"),
                    Some(PhysicalNode::Directory(DirectoryNode::Explicit { version_hash: DIR_1 })),
                    "{label}"
                );
                let placement =
                    if leaf_ranks_higher { Placement::Relocated } else { Placement::ConflictCopy };
                assert_eq!(
                    at(&projection, &copy_name("a", &leaf)),
                    Some(entry(leaf_kind, leaf_version, "a", placement)),
                    "{label}"
                );
                let directories: Vec<&String> = projection
                    .nodes()
                    .iter()
                    .filter(|(_, node)| node.is_directory())
                    .map(|(path, _)| path)
                    .collect();
                assert_eq!(directories, vec!["a"], "{label}");
                assert_eq!(projection.nodes().len(), 2 + usize::from(with_descendant), "{label}");
                assert_eq!(
                    project_own_node("a", &heads["a"], with_descendant, kind_of).unwrap(),
                    at(&projection, "a"),
                    "{label}"
                );
                assert_projection_rules(&heads, &projection, &label);
            }
        }
    }
}

#[test]
fn concurrent_leaves_at_one_path_keep_the_higher_ranked_in_place() {
    for (older, newer) in [(FILE_1, FILE_2), (LINK_1, FILE_1), (FILE_1, LINK_1)] {
        let (low, high) = (put(1, 1, older), head(2, 2, "dev-b", Some(newer)));
        // Both head orders: the rank, not the list position, decides.
        for heads in [vec![low.clone(), high.clone()], vec![high.clone(), low.clone()]] {
            let heads = state(vec![("a", heads)]);
            let projection = proj(&heads);
            let kind = |v| kind_of(&v).expect("known kind");
            assert_eq!(
                at(&projection, "a"),
                Some(entry(kind(newer), newer, "a", Placement::AtPath))
            );
            assert_eq!(
                at(&projection, &copy_name("a", &low)),
                Some(entry(kind(older), older, "a", Placement::ConflictCopy))
            );
            assert_eq!(projection.nodes().len(), 2);
            assert_projection_rules(&heads, &projection, "leaf vs leaf");
        }
    }
}

#[test]
fn concurrent_directory_metadata_loser_yields_no_copy() {
    let heads = state(vec![("a", vec![put(1, 1, DIR_1), put(2, 2, DIR_2)])]);
    let projection = proj(&heads);
    assert_eq!(
        projection.nodes().clone(),
        BTreeMap::from([(
            "a".to_string(),
            PhysicalNode::Directory(DirectoryNode::Explicit { version_hash: DIR_2 })
        )])
    );
}

#[test]
fn relocated_copy_name_colliding_with_live_entry_is_disambiguated() {
    let file = put(1, 1, FILE_1);
    let taken = copy_name("a", &file);
    // A live explicit entry already sits at the name the relocation would
    // use, and another path's subtree occupies... the same name as a
    // directory in the second variant.
    for occupant in ["leaf", "subtree"] {
        let mut heads = state(vec![("a", vec![file.clone()]), ("a/x", vec![put(2, 1, FILE_2)])]);
        match occupant {
            "leaf" => heads.insert(taken.clone(), vec![put(3, 1, FILE_2)]),
            _ => heads.insert(format!("{taken}/inner"), vec![put(3, 1, FILE_2)]),
        };
        let projection = proj(&heads);
        let occupant_node = at(&projection, &taken).expect("occupant keeps its name");
        match occupant {
            "leaf" => assert_eq!(
                occupant_node,
                entry(RecordKind::File, FILE_2, &taken, Placement::AtPath)
            ),
            _ => assert_eq!(occupant_node, PhysicalNode::Directory(DirectoryNode::Structural)),
        }
        let relocated: Vec<&String> = projection
            .nodes()
            .iter()
            .filter(|(_, node)| {
                matches!(node, PhysicalNode::Entry(e) if e.placement == Placement::Relocated)
            })
            .map(|(path, _)| path)
            .collect();
        assert_eq!(relocated.len(), 1, "{occupant}: {projection:#?}");
        assert_ne!(relocated[0], &taken);
        assert_projection_rules(&heads, &projection, occupant);
        // Deterministic: the same explicit state always picks the same name.
        assert_eq!(proj(&heads), projection);
    }
}

#[test]
fn loser_already_authored_at_its_copy_name_is_not_copied_again() {
    // A straggler re-asserts a version whose conflict copy an earlier
    // carrier already authored at the deterministic copy name. The authored
    // entry is that copy; a second, disambiguated copy of the same bytes
    // would be a duplicate no change could ever address.
    let loser = put(1, 1, FILE_1);
    let authored = copy_name("a", &loser);
    let heads = state(vec![
        ("a", vec![loser.clone(), head(2, 2, "dev-b", Some(FILE_2))]),
        (authored.as_str(), vec![put(3, 3, FILE_1)]),
    ]);
    let projection = proj(&heads);
    assert_eq!(
        projection.nodes().clone(),
        BTreeMap::from([
            ("a".to_string(), entry(RecordKind::File, FILE_2, "a", Placement::AtPath)),
            (authored.clone(), entry(RecordKind::File, FILE_1, &authored, Placement::AtPath)),
        ]),
    );
    assert_projection_rules(&heads, &projection, "authored copy");

    // Different bytes at that name are a genuine occupant: the loser still
    // gets its own, disambiguated copy.
    let heads = state(vec![
        ("a", vec![loser.clone(), head(2, 2, "dev-b", Some(FILE_2))]),
        (authored.as_str(), vec![put(3, 3, FILE_2)]),
    ]);
    let projection = proj(&heads);
    assert_eq!(projection.nodes().len(), 3, "{projection:#?}");
    assert_projection_rules(&heads, &projection, "occupied copy name");
}

#[test]
fn unknown_version_kind_is_undecidable() {
    let heads = state(vec![("a", vec![put(1, 1, UNKNOWN)])]);
    assert_eq!(
        project(&heads, kind_of),
        Err(ProjectionError::Undecidable { path: "a".to_string(), version_hash: UNKNOWN })
    );
    // A removal needs no kind.
    let heads = state(vec![("a", vec![tomb(1, 1)])]);
    assert_eq!(project(&heads, kind_of), Ok(NamespaceProjection::default()));
}

/// A path's own node needs only its own heads and whether anything below
/// it is live; it must be exactly what the whole-tree projection puts at
/// that path for that path's own content.
#[test]
fn own_node_agrees_with_the_full_projection() {
    for tree in TREES {
        for_each_state(&tree, |heads| {
            let full = proj(heads);
            for path in tree {
                let below = format!("{path}/");
                let has_live_descendant = heads.iter().any(|(other, hs)| {
                    other.starts_with(&below) && hs.iter().any(|h| h.content.is_some())
                });
                let own_heads = heads.get(path).cloned().unwrap_or_default();
                let own = project_own_node(path, &own_heads, has_live_descendant, kind_of)
                    .expect("decidable");
                let expected = match full.get(path) {
                    Some(PhysicalNode::Entry(entry)) if entry.source != path => None,
                    other => other.cloned(),
                };
                assert_eq!(own, expected, "own node of {path:?} in {heads:?}");
            }
        });
    }
}

#[test]
fn own_node_of_an_unknown_kind_is_undecidable() {
    let heads = vec![put(1, 1, UNKNOWN)];
    assert!(matches!(
        project_own_node("a", &heads, false, kind_of),
        Err(ProjectionError::Undecidable { .. })
    ));
}
