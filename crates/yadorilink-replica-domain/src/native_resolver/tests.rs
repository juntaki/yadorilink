//! The resolver's invariants, pinned on the pure function: a level is
//! settled the way the materializer settles it (placements planned and
//! recorded, nodes placed, rows written to match), heads come and go, and
//! the tree that results is checked.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::*;
use crate::author::{AuthorId, IncarnationId};
use crate::ids::{AuthorSeq, DeviceId};
use crate::native_materialize::project_own_node;
use crate::native_state::DeltaHash;

fn dot(author: &str, seq: u64) -> Dot {
    Dot {
        author: AuthorId { device: DeviceId(author.into()), incarnation: IncarnationId([1; 16]) },
        seq: AuthorSeq(seq),
    }
}

fn payload(version: u8) -> HeadPayload {
    HeadPayload { version: VersionHash([version; 32]), provenance: DeltaHash([version; 32]) }
}

#[derive(Default)]
struct Level {
    heads: BTreeMap<SyncPath, PathHeads>,
    placements: Vec<PlacementRecord>,
    bindings: BTreeMap<HeadKey, String>,
    rows: BTreeMap<String, RowFact>,
    nodes: BTreeMap<SyncPath, PhysicalNode>,
    sources: BTreeMap<SyncPath, String>,
    kept: KeptCopies,
}

impl Level {
    fn put(&mut self, path: &str, author: &str, seq: u64, version: u8) {
        self.heads
            .entry(SyncPath(path.into()))
            .or_default()
            .insert(dot(author, seq), payload(version));
    }

    /// An author removes a head having seen the copies on its own tree: every
    /// version shown at a copy name that stays live is declared kept.
    fn remove(&mut self, path: &str, author: &str, seq: u64) {
        let key = SyncPath(path.into());
        let copies: Vec<VersionHash> = self
            .heads
            .get(&key)
            .into_iter()
            .flat_map(|heads| heads.iter())
            .filter(|(d, _)| **d != dot(author, seq))
            .map(|(_, p)| p.version)
            .filter(|version| self.copy_name(path, version.0[0]).is_some())
            .collect();
        for version in copies {
            self.kept.insert((key.clone(), version));
        }
        self.remove_unaware(path, author, seq);
    }

    /// An author removes a head without having seen the other versions.
    fn remove_unaware(&mut self, path: &str, author: &str, seq: u64) {
        let key = SyncPath(path.into());
        if let Some(heads) = self.heads.get_mut(&key) {
            heads.remove(&dot(author, seq));
            if heads.is_empty() {
                self.heads.remove(&key);
            }
        }
    }

    /// One reconcile: plan and record placements, place the nodes, and write
    /// the rows the materializer would write. Returns the ops planned.
    fn settle(&mut self) -> Vec<PlacementOp> {
        let kinds: HashMap<VersionHash, RecordKind> = self
            .heads
            .values()
            .flat_map(|heads| heads.values().map(|p| (p.version, RecordKind::File)))
            .collect();
        let mut raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();
        for (path, heads) in &self.heads {
            let live = heads.iter().map(|(d, p)| LiveHead { dot: d.clone(), payload: p.clone() });
            if let Some(node) = project_own_node(live, false, |v| kinds.get(v).copied()).unwrap() {
                raw.insert(path.clone(), node);
            }
        }
        let raw_names: BTreeSet<String> = raw.keys().map(|p| p.as_str().to_owned()).collect();
        let no_descendant = BTreeSet::new();
        let snapshot = LevelSnapshot {
            heads_by_path: &self.heads,
            placements: &self.placements,
            bindings: &self.bindings,
            rows: &self.rows,
            kinds: &kinds,
            has_descendant: &no_descendant,
            kept: &self.kept,
        };
        let ops = plan_placements(&snapshot, &raw_names);
        replay_ops(&mut self.placements, &ops);
        for op in &ops {
            if let PlacementOp::Bind(key, name) = op {
                self.bindings.entry(key.clone()).or_insert_with(|| name.clone());
            }
        }
        let mut level = AppliedLevel { nodes: raw, sources: BTreeMap::new() };
        apply_placements("", &self.placements, &self.heads, &kinds, &self.kept, &mut level);
        self.rows = level
            .nodes
            .iter()
            .filter_map(|(path, node)| match node {
                PhysicalNode::Entry(entry) => Some((
                    path.as_str().to_owned(),
                    RowFact { deleted: false, file_like: true, version: entry.version },
                )),
                PhysicalNode::Directory(_) => None,
            })
            .collect();
        self.nodes = level.nodes;
        self.sources = level.sources;
        ops
    }

    fn version_at(&self, path: &str) -> Option<u8> {
        match self.nodes.get(&SyncPath(path.into())) {
            Some(PhysicalNode::Entry(entry)) => Some(entry.version.0[0]),
            _ => None,
        }
    }

    /// The physical name showing `version` of source `source`, other than
    /// the source's own path.
    fn copy_name(&self, source: &str, version: u8) -> Option<String> {
        self.nodes.iter().find_map(|(path, node)| match node {
            PhysicalNode::Entry(entry)
                if path.as_str() != source
                    && entry.version.0[0] == version
                    && self.sources.get(path).map(String::as_str) == Some(source) =>
            {
                Some(path.as_str().to_owned())
            }
            _ => None,
        })
    }

    fn shown(&self) -> Vec<(String, u8)> {
        self.nodes
            .iter()
            .filter_map(|(path, node)| match node {
                PhysicalNode::Entry(entry) => Some((path.as_str().to_owned(), entry.version.0[0])),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn a_lone_head_holds_the_real_name() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.settle();
    assert_eq!(level.shown(), vec![("x".to_owned(), 1)]);
}

#[test]
fn a_contested_paths_winner_holds_the_real_name_and_the_loser_a_copy_name() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.settle();
    level.put("x", "b", 1, 2);
    level.settle();
    assert_eq!(level.version_at("x"), Some(2));
    let copy = level.copy_name("x", 1).expect("the loser has a copy name");
    assert_ne!(copy, "x");
    assert_eq!(level.shown().len(), 2);
}

#[test]
fn a_new_winner_takes_the_real_name_and_the_old_winner_goes_to_a_copy_name() {
    let mut level = Level::default();
    level.put("x", "a", 1, 2);
    level.put("x", "b", 1, 1);
    level.settle();
    assert_eq!(level.version_at("x"), Some(2));
    let loser = level.copy_name("x", 1).unwrap();

    level.put("x", "c", 1, 3);
    level.settle();
    assert_eq!(level.version_at("x"), Some(3));
    assert_eq!(
        level.copy_name("x", 1).as_deref(),
        Some(loser.as_str()),
        "the loser keeps its name"
    );
    let old_winner = level.copy_name("x", 2).expect("the old winner is kept at a copy name");
    assert_ne!(old_winner, "x");
    assert_eq!(level.shown().len(), 3, "every live version is shown exactly once");
}

#[test]
fn a_copy_that_becomes_the_global_winner_claims_the_real_name() {
    let mut level = Level::default();
    level.put("x", "a", 1, 2);
    level.put("x", "b", 1, 1);
    level.settle();
    let copy = level.copy_name("x", 1).unwrap();
    // The copy's content is replaced by a version that now wins.
    level.remove("x", "b", 1);
    level.put("x", "b", 2, 3);
    level.settle();
    assert_eq!(level.version_at("x"), Some(3));
    assert!(level.copy_name("x", 2).is_some());
    assert!(
        level.nodes.get(&SyncPath(copy)).is_none_or(|node| match node {
            PhysicalNode::Entry(entry) => entry.version.0[0] != 3,
            _ => true,
        }),
        "the winner is not also shown at its old copy name"
    );
}

#[test]
fn deleting_the_winner_does_not_promote_a_loser() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.put("x", "b", 1, 2);
    level.settle();
    let copy = level.copy_name("x", 1).unwrap();
    level.remove("x", "b", 1);
    level.settle();
    assert_eq!(level.version_at("x"), None, "the emptied name is not refilled by the survivor");
    assert_eq!(level.copy_name("x", 1), Some(copy));
    assert_eq!(level.shown().len(), 1);
}

#[test]
fn a_lone_survivor_nobody_declared_takes_the_real_name() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.put("x", "b", 1, 2);
    level.settle();
    assert!(level.copy_name("x", 1).is_some());
    // The winner is removed by an author that never saw the loser.
    level.remove_unaware("x", "b", 1);
    level.settle();
    assert_eq!(level.version_at("x"), Some(1), "the survivor is promoted");
    assert_eq!(level.shown().len(), 1);
}

/// A replica that never saw the contest reaches the same tree as one that
/// lived through it, once the removal declared the survivor a kept copy.
#[test]
fn a_replica_that_never_saw_the_contest_derives_the_same_copy_name() {
    let mut lived_through = Level::default();
    lived_through.put("x", "a", 1, 1);
    lived_through.put("x", "b", 1, 2);
    lived_through.settle();
    lived_through.remove("x", "b", 1);
    lived_through.settle();

    let mut late = Level::default();
    late.put("x", "a", 1, 1);
    late.kept = lived_through.kept.clone();
    late.settle();

    assert_eq!(late.version_at("x"), None);
    assert_eq!(late.shown(), lived_through.shown());
}

/// The declaration may arrive before the head it names.
#[test]
fn a_declaration_that_arrives_before_its_head_still_names_the_copy() {
    let mut level = Level::default();
    level.kept.insert((SyncPath("x".into()), VersionHash([1; 32])));
    level.settle();
    level.put("x", "a", 1, 1);
    level.settle();
    assert_eq!(level.version_at("x"), None);
    assert!(level.copy_name("x", 1).is_some());
}

/// A loser's copy name is a function of its source path and version, not of the
/// device whose head happens to represent it: two replicas that learn the same
/// loser through different authors, or in a different order, name it alike.
#[test]
fn a_copy_name_does_not_depend_on_which_device_represents_the_version() {
    let name_with_loser_from = |loser_author: &str| {
        let mut level = Level::default();
        level.put("x", "a", 1, 2);
        level.put("x", loser_author, 1, 1);
        level.settle();
        level.copy_name("x", 1).expect("the loser has a copy name")
    };
    assert_eq!(name_with_loser_from("b"), name_with_loser_from("c"));

    // The representative changing after the name is assigned moves nothing,
    // and a replica that only ever saw the other representative agrees.
    let mut lived_through = Level::default();
    lived_through.put("x", "a", 1, 2);
    lived_through.put("x", "b", 1, 1);
    lived_through.settle();
    lived_through.put("x", "c", 1, 1);
    lived_through.remove("x", "b", 1);
    lived_through.settle();
    let mut only_saw_c = Level::default();
    only_saw_c.put("x", "a", 1, 2);
    only_saw_c.put("x", "c", 1, 1);
    only_saw_c.settle();
    assert_eq!(lived_through.copy_name("x", 1), only_saw_c.copy_name("x", 1));
}

#[test]
fn a_late_head_of_a_shown_version_does_not_move_its_copy() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.put("x", "b", 1, 2);
    level.settle();
    let copy = level.copy_name("x", 1).unwrap();
    // Another device authors the same content as the loser's head.
    level.put("x", "c", 1, 1);
    level.settle();
    assert_eq!(level.copy_name("x", 1), Some(copy));
    assert_eq!(level.shown().len(), 2, "one entry per distinct content");
    // The original representative goes away: nothing visible changes.
    let before = level.shown();
    level.remove("x", "a", 1);
    level.settle();
    assert_eq!(level.shown(), before);
}

#[test]
fn settling_again_changes_nothing() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.put("x", "b", 1, 2);
    level.put("x", "c", 1, 3);
    level.settle();
    let shown = level.shown();
    let ops = level.settle();
    assert!(
        ops.iter().all(|op| matches!(op, PlacementOp::Bind(..))),
        "no placement changes: {ops:?}"
    );
    assert_eq!(level.shown(), shown);
}

#[test]
fn a_placement_naming_another_write_is_retired() {
    let mut level = Level::default();
    level.put("x", "a", 1, 1);
    level.put("x", "b", 1, 2);
    level.settle();
    let copy = level.copy_name("x", 1).unwrap();
    // The head at the placed dot is replaced by another write with the same
    // dot but different provenance: what the placement names is gone.
    level.heads.get_mut(&SyncPath("x".into())).unwrap().get_mut(&dot("a", 1)).unwrap().provenance =
        DeltaHash([99; 32]);
    let ops = level.settle();
    assert!(
        ops.contains(&PlacementOp::Delete(copy))
            || ops.iter().any(|op| matches!(op, PlacementOp::Put(_)))
    );
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % bound
    }
}

#[test]
fn randomized_histories_keep_every_invariant() {
    for seed in 0..300u64 {
        let mut rng = Rng(seed + 1);
        let mut level = Level::default();
        // (source, version) -> the copy name it was first given.
        let mut copy_of: BTreeMap<(String, u8), String> = BTreeMap::new();
        let mut seqs: BTreeMap<String, u64> = BTreeMap::new();
        for step in 0..40 {
            let path = ["x", "y"][rng.next(2) as usize];
            let author = ["a", "b", "c"][rng.next(3) as usize];
            if rng.next(3) == 0 {
                let existing: Vec<Dot> = level
                    .heads
                    .get(&SyncPath(path.into()))
                    .map(|h| h.keys().cloned().collect())
                    .unwrap_or_default();
                if !existing.is_empty() {
                    let victim = &existing[rng.next(existing.len() as u64) as usize];
                    level.remove(path, &victim.author.device.0, victim.seq.get());
                }
            } else {
                let seq = seqs.entry(format!("{path}/{author}")).or_insert(0);
                *seq += 1;
                // Replacing an author's head at a path supersedes its earlier one.
                let earlier: Vec<Dot> = level
                    .heads
                    .get(&SyncPath(path.into()))
                    .map(|h| h.keys().filter(|d| d.author.device.0 == author).cloned().collect())
                    .unwrap_or_default();
                for d in earlier {
                    level.remove(path, author, d.seq.get());
                }
                level.put(path, author, *seq, 1 + rng.next(4) as u8);
            }
            let context = format!("seed {seed} step {step}");
            let before_shown = level.shown();
            level.settle();
            let shown = level.shown();

            // Every live version of every source is shown exactly once, and
            // nothing else is shown.
            let mut expected: BTreeSet<(String, u8)> = BTreeSet::new();
            for (source, heads) in &level.heads {
                for p in heads.values() {
                    expected.insert((source.as_str().to_owned(), p.version.0[0]));
                }
            }
            let mut got: Vec<(String, u8)> = level
                .nodes
                .iter()
                .filter_map(|(path, node)| match node {
                    PhysicalNode::Entry(entry) => Some((
                        level
                            .sources
                            .get(path)
                            .cloned()
                            .unwrap_or_else(|| path.as_str().to_owned()),
                        entry.version.0[0],
                    )),
                    _ => None,
                })
                .collect();
            got.sort();
            let unique: BTreeSet<_> = got.iter().cloned().collect();
            assert_eq!(got.len(), unique.len(), "{context}: a version is shown twice: {shown:?}");
            assert_eq!(unique, expected, "{context}: shown {shown:?}");

            for (source, heads) in &level.heads {
                let live: Vec<LiveHead> = heads
                    .iter()
                    .map(|(d, p)| LiveHead { dot: d.clone(), payload: p.clone() })
                    .collect();
                let PathMaterialization::Present { winner, conflict_copies } = resolve_path(live)
                else {
                    continue;
                };
                if !conflict_copies.is_empty() {
                    let winner_version = heads[&winner].version.0[0];
                    assert_eq!(
                        level.version_at(source.as_str()),
                        Some(winner_version),
                        "{context}: the contested winner of {source:?} must hold the real name"
                    );
                }
                // A version that has a copy name and is still live keeps it,
                // unless it has become the contested winner.
                for p in heads.values() {
                    let version = p.version.0[0];
                    let winner_takes =
                        !conflict_copies.is_empty() && heads[&winner].version.0[0] == version;
                    let key = (source.as_str().to_owned(), version);
                    if winner_takes {
                        // Holding the real name ends the copy's identity.
                        copy_of.remove(&key);
                        continue;
                    }
                    if let Some(name) = copy_of.get(&key) {
                        assert_eq!(
                                level.copy_name(source.as_str(), version).as_ref(),
                                Some(name),
                                "{context}: {key:?} moved off its copy name; heads {:?} placements {:?} shown {shown:?}",
                                level.heads.get(source).map(|h| h.iter().map(|(d, p)| (d.author.device.0.clone(), d.seq.get(), p.version.0[0])).collect::<Vec<_>>()),
                                level.placements.iter().map(|p| (p.physical_path.clone(), p.payload.version.0[0], p.origin)).collect::<Vec<_>>()
                        );
                    } else if let Some(name) = level.copy_name(source.as_str(), version) {
                        copy_of.insert(key, name);
                    }
                }
            }
            // A version's copy name is forgotten once the version is gone.
            copy_of.retain(|(source, version), _| {
                level
                    .heads
                    .get(&SyncPath(source.clone()))
                    .is_some_and(|h| h.values().any(|p| p.version.0[0] == *version))
            });

            // Settling again is a no-op.
            // A placement holds while its row still shows it, so one that lost
            // its head is retired by the settle after the row has gone; the
            // tree itself does not move.
            level.settle();
            assert_eq!(level.shown(), shown, "{context}: second settle changed the tree");
            let before_nodes = level.shown();
            let before_placements = level.placements.clone();
            let ops = level.settle();
            assert!(
                ops.iter().all(|op| matches!(op, PlacementOp::Bind(..))),
                "{context}: not idempotent: {ops:?}\nheads {:?}\nplacements {before_placements:?}\nshown {before_nodes:?}",
                level.heads
            );
            assert_eq!(level.shown(), shown, "{context}: second settle changed the tree");
            let _ = before_shown;
        }
    }
}

/// One recorded change of a level's heads: what an author did, with the copies
/// its own tree showed declared kept when it removed a head.
#[derive(Clone, Debug)]
enum Transition {
    Put { path: &'static str, author: &'static str, seq: u64, version: u8 },
    Remove { path: &'static str, author: &'static str, seq: u64, kept: Vec<u8> },
}

impl Level {
    fn apply(&mut self, transition: &Transition) {
        match transition {
            Transition::Put { path, author, seq, version } => {
                self.put(path, author, *seq, *version);
            }
            Transition::Remove { path, author, seq, kept } => {
                for version in kept {
                    self.kept.insert((SyncPath((*path).into()), VersionHash([*version; 32])));
                }
                self.remove_unaware(path, author, *seq);
            }
        }
    }

    /// Every copy name and the version it shows, per source.
    fn copies(&self) -> BTreeMap<(String, u8), String> {
        let mut out = BTreeMap::new();
        for (path, node) in &self.nodes {
            let PhysicalNode::Entry(entry) = node else { continue };
            let source = self.sources.get(path).cloned().unwrap_or_else(|| path.as_str().into());
            if source != path.as_str() {
                out.insert((source, entry.version.0[0]), path.as_str().to_owned());
            }
        }
        out
    }
}

/// The same history reaches the same tree and the same copy names whether a
/// replica settles after every change, in batches of one to four, or only at
/// the end: what a loser is shown as is a function of the heads and the
/// declarations, never of which transitions a replica happened to observe.
#[test]
fn every_batching_of_one_history_reaches_the_same_tree() {
    for seed in 0..400u64 {
        let mut rng = Rng(seed + 7);
        // The history, recorded from an author replica that settles each step
        // and so sees exactly the copies it declares kept.
        let mut author_view = Level::default();
        let mut history: Vec<Transition> = Vec::new();
        let mut seqs: BTreeMap<String, u64> = BTreeMap::new();
        for _ in 0..(6 + rng.next(10)) {
            let path = ["x", "y"][rng.next(2) as usize];
            let key = SyncPath(path.into());
            let live: Vec<Dot> = author_view
                .heads
                .get(&key)
                .map(|heads| heads.keys().cloned().collect())
                .unwrap_or_default();
            let transition = if !live.is_empty() && rng.next(3) == 0 {
                let victim = &live[rng.next(live.len() as u64) as usize];
                let kept: Vec<u8> = author_view
                    .heads
                    .get(&key)
                    .into_iter()
                    .flat_map(|heads| heads.iter())
                    .filter(|(dot, _)| *dot != victim)
                    .map(|(_, payload)| payload.version.0[0])
                    .filter(|version| author_view.copy_name(path, *version).is_some())
                    .collect();
                let author: &'static str = ["a", "b", "c"]
                    .into_iter()
                    .find(|name| **name == *victim.author.device.0)
                    .expect("a known author");
                Transition::Remove { path, author, seq: victim.seq.get(), kept }
            } else {
                let author = ["a", "b", "c"][rng.next(3) as usize];
                let seq = seqs.entry(format!("{path}/{author}")).or_insert(0);
                *seq += 1;
                // An author's new head replaces its earlier one at the path.
                let earlier: Vec<Dot> =
                    live.iter().filter(|dot| dot.author.device.0 == author).cloned().collect();
                for dot in earlier {
                    let transition =
                        Transition::Remove { path, author, seq: dot.seq.get(), kept: Vec::new() };
                    author_view.apply(&transition);
                    history.push(transition);
                }
                Transition::Put { path, author, seq: *seq, version: 1 + rng.next(4) as u8 }
            };
            author_view.apply(&transition);
            history.push(transition);
            author_view.settle();
        }

        let replay = |batch: &dyn Fn(&mut Rng) -> usize| {
            let mut level = Level::default();
            let mut rng = Rng(seed + 1000);
            let mut pending = 0;
            let mut until = batch(&mut rng);
            for transition in &history {
                level.apply(transition);
                pending += 1;
                if pending >= until {
                    level.settle();
                    pending = 0;
                    until = batch(&mut rng);
                }
            }
            level.settle();
            level
        };
        let each = replay(&|_| 1);
        let random = replay(&|rng| 1 + rng.next(4) as usize);
        let once = replay(&|_| usize::MAX);
        for (name, other) in [("random batches", &random), ("settled once", &once)] {
            assert_eq!(
                each.shown(),
                other.shown(),
                "seed {seed}: {name} shows another tree\n{history:?}"
            );
            assert_eq!(
                each.copies(),
                other.copies(),
                "seed {seed}: {name} names copies otherwise\n{history:?}"
            );
        }
    }
}

mod copy_names {
    use super::*;
    use crate::conflict::{
        conflict_copy_source_path, conflict_copy_stem_was_truncated, is_conflict_copy_of,
        is_conflict_copy_path, MAX_COMPONENT_BYTES,
    };

    #[test]
    fn a_copy_name_carries_no_fake_date_and_a_short_hash() {
        let name = numbered_copy_name("docs/report.txt", [7u8; 32], 1);
        assert!(!name.contains("1970"), "{name}");
        assert_eq!(name, format!("docs/report (conflicted copy, sync, {}).txt", "07".repeat(16)));
        // The suffix, not counting the stem and extension, stays short.
        let suffix_len = name.len() - "docs/report.txt".len();
        assert!(suffix_len <= 64, "{name} has a {suffix_len}-byte suffix");
    }

    #[test]
    fn the_name_is_a_function_of_path_version_and_attempt_alone() {
        let a = numbered_copy_name("x.txt", [1u8; 32], 1);
        assert_eq!(a, numbered_copy_name("x.txt", [1u8; 32], 1));
        assert_ne!(a, numbered_copy_name("x.txt", [2u8; 32], 1));
        assert_ne!(a, numbered_copy_name("x.txt", [1u8; 32], 2));
        assert!(numbered_copy_name("x.txt", [1u8; 32], 2).contains("sync 2"));
    }

    #[test]
    fn the_name_shows_the_first_128_bits_of_the_hash() {
        let mut late = [9u8; 32];
        late[15] = 0;
        let mut later = late;
        later[31] ^= 1;
        // The prefix is what tells versions apart; a difference past it is
        // not shown.
        assert_ne!(
            numbered_copy_name("x", [9u8; 32], 1),
            numbered_copy_name("x", late, 1),
            "a difference inside the shown prefix must change the name"
        );
        assert_eq!(numbered_copy_name("x", late, 1), numbered_copy_name("x", later, 1));
    }

    #[test]
    fn relocation_names_use_the_same_short_form() {
        let name = numbered_relocation_name("a", "device-b", [3u8; 32], 1);
        assert_eq!(name, format!("a (conflicted copy, device-b, {})", "03".repeat(16)));
        assert!(numbered_relocation_name("a", "device-b", [3u8; 32], 2).contains("device-b 2"));
    }

    #[test]
    fn copy_of_a_copy_collapses_to_one_suffix_and_is_still_recognized() {
        let first = numbered_copy_name("docs/report.txt", [1u8; 32], 1);
        let second = numbered_copy_name(&first, [2u8; 32], 1);
        assert_eq!(second.matches("(conflicted copy").count(), 1, "{second}");
        assert!(is_conflict_copy_path(&first));
        assert_eq!(conflict_copy_source_path(&first), "docs/report.txt");
        assert_eq!(conflict_copy_source_path(&second), "docs/report.txt");
        assert!(is_conflict_copy_of(&first, "docs/report.txt"));
        assert!(is_conflict_copy_of(&second, "docs/report.txt"));
    }

    #[test]
    fn a_long_stem_still_fits_the_component_limit() {
        let long = format!("{}.txt", "n".repeat(300));
        let name = numbered_copy_name(&long, [4u8; 32], 1);
        assert!(name.len() <= MAX_COMPONENT_BYTES, "{} bytes", name.len());
        assert!(conflict_copy_stem_was_truncated(&name));
    }
}
