use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_plan::{
    NativeDesiredNode, NativeLevelPlan, NativePlannedNode,
};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, HeadPayload, LiveHead, NativeState};
use yadorilink_replica_engine::namespace::{
    DirectoryNode, NamespaceProjection, PhysicalNode, Placement,
};

use super::*;
use crate::stable_projection_binding;

fn group() -> FolderGroupId {
    FolderGroupId("g".to_string())
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_string()), incarnation: IncarnationId([1; 16]) }
}

fn version(kind: RecordKind, mtime: i64) -> FileVersion {
    // A directory version carries no time.
    let mtime = if kind == RecordKind::Directory { 0 } else { mtime };
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: kind,
            xattrs: Vec::new(),
        },
    )
}

/// The `n`-th file version in winner order: `file(1)` beats `file(2)`, which
/// beats `file(3)`, because the order of concurrent heads is the version hash.
fn file(n: i64) -> FileVersion {
    let mut pool: Vec<FileVersion> = (1..=16).map(|m| version(RecordKind::File, m)).collect();
    pool.sort_by_key(|v| std::cmp::Reverse(v.version_hash));
    pool.swap_remove(n as usize - 1).clone()
}

fn payload(v: &FileVersion) -> HeadPayload {
    HeadPayload { version: v.version_hash, provenance: DeltaHash(v.version_hash.0) }
}

fn store(c: &Connection, versions: &[&FileVersion]) {
    for v in versions {
        crate::dag_store::put_file_version(c, "g", v).unwrap();
    }
}

fn install(c: &Connection, state: &NativeState) {
    crate::native_store::install_state(c, &group(), state).unwrap();
}

fn level(c: &Connection, parent: &str) -> NamespaceProjection {
    native_desired_level_projection(c, "g", parent).unwrap()
}

/// Every File/Symlink version in `projection`, with how often it appears.
fn placed_versions(projection: &NamespaceProjection) -> BTreeMap<[u8; 32], usize> {
    let mut out = BTreeMap::new();
    for node in projection.nodes().values() {
        if let PhysicalNode::Entry(entry) = node {
            *out.entry(entry.version_hash).or_default() += 1;
        }
    }
    out
}

fn entry_at<'a>(
    projection: &'a NamespaceProjection,
    path: &str,
) -> &'a yadorilink_replica_engine::namespace::PlacedEntry {
    match projection.get(path) {
        Some(PhysicalNode::Entry(entry)) => entry,
        other => panic!("expected an entry at {path:?}, found {other:?}"),
    }
}

#[test]
fn a_conflict_winner_and_loser_each_appear_exactly_once() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);

    let tree = level(&c, "");
    assert_eq!(tree.nodes().len(), 2);
    assert_eq!(entry_at(&tree, "x").version_hash, win.version_hash.0);
    assert_eq!(entry_at(&tree, "x").placement, Placement::AtPath);
    let placed = tree.nodes().iter().find(|(p, _)| p.as_str() != "x").expect("a copy");
    let PhysicalNode::Entry(copy) = placed.1 else { panic!("copy must be an entry") };
    assert_eq!(copy.version_hash, lose.version_hash.0);
    assert_eq!(copy.source, "x");
    assert_eq!(copy.placement, Placement::ConflictCopy);
    assert!(placed_versions(&tree).values().all(|n| *n == 1));

    // Asking again names the same copy: the name is stable.
    assert_eq!(level(&c, ""), tree);
}

#[test]
fn a_losers_name_survives_the_winner_being_deleted() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let a = author("a");
    let mut state = NativeState::new();
    let winner_dot = state.put(&a, SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);
    let before = level(&c, "");
    let copy_name = before.nodes().keys().find(|p| p.as_str() != "x").unwrap().clone();

    // The deleting author saw the copy, so its delta declares it kept.
    stable_projection_binding::native_keep_heads_of_version(&c, "g", "x", &lose.version_hash.0)
        .unwrap();
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.delete(&a, SyncPath("x".into()), std::slice::from_ref(&winner_dot)).unwrap();
    install(&c, &state);

    let after = level(&c, "");
    assert!(after.get("x").is_none(), "the lone survivor is not promoted onto the winner's name");
    assert_eq!(entry_at(&after, &copy_name).version_hash, lose.version_hash.0);
}

#[test]
fn a_lone_survivor_no_delta_declared_is_promoted_onto_the_winners_name() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let a = author("a");
    let mut state = NativeState::new();
    let winner_dot = state.put(&a, SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);
    let before = level(&c, "");
    assert!(before.nodes().keys().any(|p| p.as_str() != "x"), "the loser has a copy name");

    // The winner is removed by an author that never saw the loser.
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.delete(&a, SyncPath("x".into()), std::slice::from_ref(&winner_dot)).unwrap();
    install(&c, &state);

    let after = level(&c, "");
    assert_eq!(entry_at(&after, "x").version_hash, lose.version_hash.0);
    assert_eq!(after.nodes().len(), 1);
}

#[test]
fn a_file_displaced_by_a_directory_is_relocated_and_returns_when_the_directory_goes() {
    let c = conn();
    let (f, child) = (file(1), file(2));
    store(&c, &[&f, &child]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("a".into()), &[], payload(&f)).unwrap();
    let child_dot = state.put(&author("a"), SyncPath("a/x".into()), &[], payload(&child)).unwrap();
    install(&c, &state);

    let root = level(&c, "");
    assert!(matches!(root.get("a"), Some(PhysicalNode::Directory(DirectoryNode::Structural))));
    let relocated = root.nodes().iter().find(|(p, _)| p.as_str() != "a").expect("relocated file");
    let PhysicalNode::Entry(entry) = relocated.1 else { panic!() };
    assert_eq!((entry.source.as_str(), entry.placement), ("a", Placement::Relocated));
    assert_eq!(placed_versions(&root).get(&f.version_hash.0), Some(&1));

    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.delete(&author("a"), SyncPath("a/x".into()), std::slice::from_ref(&child_dot)).unwrap();
    install(&c, &state);
    let root = level(&c, "");
    assert_eq!(root.nodes().len(), 1, "the relocation ends with the directory: {root:?}");
    assert_eq!(entry_at(&root, "a").placement, Placement::AtPath);
}

#[test]
fn an_explicit_directory_beats_a_higher_ranked_file_which_takes_a_copy_name() {
    let c = conn();
    let (dir, f) = (version(RecordKind::Directory, 1), file(2));
    store(&c, &[&dir, &f]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("d".into()), &[], payload(&dir)).unwrap();
    state.put(&author("b"), SyncPath("d".into()), &[], payload(&f)).unwrap();
    install(&c, &state);

    let root = level(&c, "");
    assert_eq!(
        root.get("d"),
        Some(&PhysicalNode::Directory(DirectoryNode::Explicit {
            version_hash: dir.version_hash.0
        }))
    );
    assert_eq!(placed_versions(&root), BTreeMap::from([(f.version_hash.0, 1)]));
}

#[test]
fn a_numbered_collision_never_drops_an_entry() {
    let c = conn();
    let (f, child) = (file(1), file(2));
    store(&c, &[&f, &child]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("a".into()), &[], payload(&f)).unwrap();
    state.put(&author("a"), SyncPath("a/x".into()), &[], payload(&child)).unwrap();
    install(&c, &state);
    let first = crate::native_projection_binding::numbered_copy_name("a", f.version_hash.0, 1);
    // Another file already legitimately sits at the relocation's first name.
    let squatter = file(3);
    store(&c, &[&squatter]);
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.put(&author("z"), SyncPath(first.clone()), &[], payload(&squatter)).unwrap();
    install(&c, &state);

    let root = level(&c, "");
    let versions = placed_versions(&root);
    assert_eq!(versions.get(&f.version_hash.0), Some(&1), "{root:?}");
    assert_eq!(versions.get(&squatter.version_hash.0), Some(&1), "{root:?}");
    assert_eq!(entry_at(&root, &first).version_hash, squatter.version_hash.0);
}

#[test]
fn an_unresolvable_version_fails_closed_and_leaves_no_placement() {
    let c = conn();
    let missing = file(1);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&missing)).unwrap();
    install(&c, &state);

    let err = native_desired_level_projection(&c, "g", "").unwrap_err();
    assert!(matches!(err, SyncSqliteError::NotFound(_)), "{err:?}");
    let err = native_desired_path_state(&c, "g", "x").unwrap_err();
    assert!(matches!(err, SyncSqliteError::NotFound(_)), "{err:?}");

    // Once the version is known the same query decides.
    store(&c, &[&missing]);
    assert_eq!(level(&c, "").nodes().len(), 1);
}

#[test]
fn a_descendants_missing_version_does_not_block_its_ancestors_level() {
    let c = conn();
    let dir = version(RecordKind::Directory, 1);
    let missing = file(2);
    store(&c, &[&dir]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("d".into()), &[], payload(&dir)).unwrap();
    state.put(&author("a"), SyncPath("d/x".into()), &[], payload(&missing)).unwrap();
    install(&c, &state);

    assert!(level(&c, "").get("d").is_some());
    assert!(native_desired_level_projection(&c, "g", "d").is_err());
}

#[test]
fn the_per_path_state_agrees_with_the_level_on_every_own_account_path() {
    let c = conn();
    let (win, lose, other) = (file(1), file(2), file(3));
    store(&c, &[&win, &lose, &other]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    state.put(&author("a"), SyncPath("y".into()), &[], payload(&other)).unwrap();
    install(&c, &state);

    let tree = level(&c, "");
    for path in ["x", "y", "missing"] {
        let expected = match tree.get(path) {
            Some(PhysicalNode::Entry(entry)) if entry.placement == Placement::AtPath => {
                DesiredPathState::Entry {
                    kind: entry.kind,
                    version: VersionHash(entry.version_hash),
                }
            }
            None => DesiredPathState::Absent,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(native_desired_path_state(&c, "g", path).unwrap(), expected, "{path}");
    }
}

#[test]
fn a_placement_survives_a_restart_because_it_is_stored() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);
    let before = level(&c, "");

    // A fresh evaluation reads the same rows and names the same copy.
    let rows = stable_projection_binding::native_placements(&c, "g").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(level(&c, ""), before);
    let _ = (Dot { author: author("a"), seq: yadorilink_replica_domain::ids::AuthorSeq(1) },);
}

fn obligation(
    c: &Connection,
    path: &str,
) -> Option<crate::projection_obligations::ProjectionObligation> {
    crate::projection_obligations::lookup_projection_obligation(c, "g", path).unwrap()
}

#[test]
fn a_versions_arrival_rearms_exactly_the_paths_that_waited_for_it() {
    let c = conn();
    let (waiting, other) = (file(1), file(2));
    store(&c, &[&other]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("waits".into()), &[], payload(&waiting)).unwrap();
    state.put(&author("a"), SyncPath("fine".into()), &[], payload(&other)).unwrap();
    install(&c, &state);
    assert!(
        native_desired_level_projection(&c, "g", "").is_err(),
        "undecidable while the version is missing"
    );
    assert!(obligation(&c, "waits").is_none());

    // The same version arriving twice re-arms once: the second is no news.
    store(&c, &[&waiting]);
    let armed = obligation(&c, "waits").expect("arrival arms the waiting path");
    assert_eq!(armed.invalidation_generation, 1);
    assert!(obligation(&c, "fine").is_none(), "a path that never waited stays untouched");
    store(&c, &[&waiting]);
    assert_eq!(obligation(&c, "waits").unwrap().invalidation_generation, 1);

    assert_eq!(level(&c, "").nodes().len(), 2);
}

#[test]
fn a_delta_arms_its_paths_and_marks_a_local_one_local() {
    use yadorilink_replica_domain::signed_delta::{DeltaOp, NativeDelta};
    let c = conn();
    let delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: author("a"),
        seq: yadorilink_replica_domain::ids::AuthorSeq(1),
        prev: None,
        ops: vec![
            DeltaOp {
                path: SyncPath("p".into()),
                removes: Vec::new(),
                put: None,
                keeps: Vec::new(),
                keep_put: false,
            },
            DeltaOp {
                path: SyncPath("q".into()),
                removes: Vec::new(),
                put: None,
                keeps: Vec::new(),
                keep_put: false,
            },
        ],
        signature: [0; 64],
    };
    arm_projection_for_delta(&c, "g", &delta, false).unwrap();
    assert_eq!(
        obligation(&c, "p").unwrap().origin,
        crate::projection_obligations::ObligationOrigin::Remote
    );
    arm_projection_for_delta(&c, "g", &delta, true).unwrap();
    let local = obligation(&c, "q").unwrap();
    assert_eq!(local.origin, crate::projection_obligations::ObligationOrigin::Local);
    assert_eq!(local.invalidation_generation, 2);
}

// ---------------------------------------------------------------------
// Randomized-history property checks. There is no second implementation to
// compare with byte for byte -- native's own rule is the reference -- so
// these assert what any correct desired tree has to satisfy.
// ---------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The whole desired tree, gathered level by level from the root through
/// every directory node.
fn whole_tree(c: &Connection) -> BTreeMap<String, PhysicalNode> {
    let mut out = BTreeMap::new();
    let mut pending = vec![String::new()];
    while let Some(parent) = pending.pop() {
        for (path, node) in level(c, &parent).nodes() {
            if matches!(node, PhysicalNode::Directory(_)) {
                pending.push(path.clone());
            }
            out.insert(path.clone(), node.clone());
        }
    }
    out
}

fn whole_plan(c: &Connection) -> BTreeMap<SyncPath, NativePlannedNode> {
    let mut out = BTreeMap::new();
    let mut pending = vec![String::new()];
    while let Some(parent) = pending.pop() {
        let NativeLevelPlan { nodes } = native_plan_level(c, "g", &parent).unwrap();
        for (path, node) in nodes {
            if !matches!(node, NativePlannedNode::Entry { .. }) {
                pending.push(path.as_str().to_owned());
            }
            out.insert(path, node);
        }
    }
    out
}

fn describe_heads(state: &NativeState) -> String {
    let mut out = Vec::new();
    for (path, heads) in &state.heads {
        for (dot, p) in heads {
            out.push(format!(
                "{}={}#{}:v{}",
                path.as_str(),
                dot.author.device.0,
                dot.seq.get(),
                p.version.0[0]
            ));
        }
    }
    out.join(", ")
}

fn describe_tree(tree: &BTreeMap<String, PhysicalNode>) -> String {
    tree.iter()
        .map(|(path, node)| match node {
            PhysicalNode::Directory(DirectoryNode::Explicit { .. }) => {
                format!("{path}/ (explicit)")
            }
            PhysicalNode::Directory(DirectoryNode::Structural) => format!("{path}/"),
            PhysicalNode::Entry(e) => {
                format!("{path} <- {}:v{} {:?}", e.source, e.version_hash[0], e.placement)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn dot_of(
    entry: &yadorilink_replica_engine::namespace::PlacedEntry,
    state: &NativeState,
) -> Option<Dot> {
    state
        .heads
        .get(&SyncPath(entry.source.clone()))?
        .iter()
        .find(|(_, payload)| payload.version.0 == entry.version_hash)
        .map(|(dot, _)| dot.clone())
}

/// The author of a step saw the copies on its own tree: every head the step
/// leaves in place at the path it edited (one live before the step and still
/// live after it) whose content shows as a copy is declared kept, exactly. A
/// head the step itself puts is not.
fn declare_copies_left_in_place(
    c: &Connection,
    state: &NativeState,
    path: &SyncPath,
    named: &BTreeMap<(String, [u8; 32]), String>,
    before: &BTreeSet<Dot>,
) {
    for (source, version) in named.keys() {
        if source != path.as_str() {
            continue;
        }
        for head in state.heads_at(path) {
            if head.payload.version.0 == *version && before.contains(&head.dot) {
                assert!(stable_projection_binding::native_keep_head(
                    c,
                    "g",
                    source,
                    head.dot.author.device.as_str(),
                    &head.dot.author.incarnation.0,
                    head.dot.seq.get(),
                    &head.payload.provenance.0,
                )
                .unwrap());
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one scenario driver, read top to bottom
fn randomized_histories_always_yield_a_valid_native_tree() {
    const PATHS: [&str; 7] = ["a", "a/b", "a/b/c", "d", "d/e", "f", "f/g"];
    let files: Vec<FileVersion> = (1..=6).map(file).collect();
    let dirs: Vec<FileVersion> = vec![version(RecordKind::Directory, 0)];
    let kind_of = |hash: &VersionHash| -> RecordKind {
        if dirs.iter().any(|d| d.version_hash == *hash) {
            RecordKind::Directory
        } else {
            RecordKind::File
        }
    };

    for seed in 1..=150u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let c = conn();
        store(&c, &files.iter().chain(dirs.iter()).collect::<Vec<_>>());
        let mut state = NativeState::new();
        let mut counter = 0u64;
        // Placed head -> physical path, for the stability check.
        let mut named: BTreeMap<(String, [u8; 32]), String> = BTreeMap::new();

        for _step in 0..14 {
            let path = SyncPath(PATHS[rng.below(PATHS.len())].to_owned());
            let who = author(["p", "q", "r"][rng.below(3)]);
            let live: Vec<Dot> = state.heads_at(&path).map(|h| h.dot).collect();
            let before: BTreeSet<Dot> = live.iter().cloned().collect();
            if !live.is_empty() && rng.below(4) == 0 {
                let victim = live[rng.below(live.len())].clone();
                let _ = state.delete(&who, path.clone(), std::slice::from_ref(&victim));
            } else {
                counter += 1;
                let v = if rng.below(5) == 0 { &dirs[0] } else { &files[rng.below(files.len())] };
                let observed: Vec<Dot> = if rng.below(2) == 0 { live } else { Vec::new() };
                let mut p = payload(v);
                let mut provenance = [7u8; 32];
                provenance[..8].copy_from_slice(&counter.to_le_bytes());
                provenance[8..16].copy_from_slice(&seed.to_le_bytes());
                p.provenance = DeltaHash(provenance);
                if state.put(&who, path.clone(), &observed, p).is_err() {
                    continue;
                }
            }
            install(&c, &state);
            declare_copies_left_in_place(&c, &state, &path, &named, &before);
            let tree = whole_tree(&c);
            assert_eq!(whole_tree(&c), tree, "seed {seed}: a second evaluation must agree");

            // 0. The plan names the exact live head behind every node, once.
            let plan = whole_plan(&c);
            assert_eq!(
                plan.keys().map(SyncPath::as_str).collect::<Vec<_>>(),
                tree.keys().map(String::as_str).collect::<Vec<_>>(),
                "seed {seed}"
            );
            let mut stood_for: BTreeSet<(SyncPath, Dot)> = BTreeSet::new();
            for (physical, node) in &plan {
                if let NativePlannedNode::Entry { head, placement, .. } = node {
                    let live = state
                        .heads
                        .get(&head.source_path)
                        .and_then(|heads| heads.get(head.dot()))
                        .unwrap_or_else(|| {
                            panic!("seed {seed}: {physical:?} names a head that is not live")
                        });
                    assert_eq!(live.version, head.version(), "seed {seed}");
                    assert_eq!(live.provenance, head.head.payload.provenance, "seed {seed}");
                    if *placement
                        == yadorilink_replica_domain::native_materialize::Placement::AtPath
                    {
                        assert_eq!(
                            &head.source_path, physical,
                            "seed {seed}: an own-path entry stands for itself"
                        );
                    }
                    assert!(
                        stood_for.insert((head.source_path.clone(), head.dot().clone())),
                        "seed {seed}: one head stands for two physical entries ({physical:?})"
                    );
                }
            }
            // 1. Every live file version of a path appears exactly once
            // (heads of one path that agree on the version are one piece of
            // content); nothing that is not live appears at all.
            let mut seen: BTreeMap<(String, [u8; 32]), usize> = BTreeMap::new();
            for (physical, node) in &tree {
                if let PhysicalNode::Entry(entry) = node {
                    assert!(
                        dot_of(entry, &state).is_some(),
                        "seed {seed}: {physical:?} shows content that is not live"
                    );
                    *seen.entry((entry.source.clone(), entry.version_hash)).or_default() += 1;
                }
            }
            for (path, heads) in &state.heads {
                for payload in heads.values() {
                    if kind_of(&payload.version) == RecordKind::Directory {
                        continue;
                    }
                    assert_eq!(
                        seen.get(&(path.as_str().to_owned(), payload.version.0)).copied(),
                        Some(1),
                        "seed {seed}: version v{} at {path:?} must appear exactly once\nheads: {}\ntree: {}",
                        payload.version.0[0],
                        describe_heads(&state),
                        describe_tree(&tree)
                    );
                }
            }
            // 2. A directory head gives an explicit directory at its path.
            for (path, heads) in &state.heads {
                if heads.values().any(|p| kind_of(&p.version) == RecordKind::Directory) {
                    assert!(
                        matches!(tree.get(path.as_str()), Some(PhysicalNode::Directory(DirectoryNode::Explicit { .. }))),
                        "seed {seed}: {path:?} carries a directory head but is not an explicit directory"
                    );
                }
            }
            // 3. Every node's parent is a directory.
            for physical in tree.keys() {
                let parent = physical.rsplit_once('/').map(|(parent, _)| parent);
                if let Some(parent) = parent {
                    assert!(
                        matches!(tree.get(parent), Some(PhysicalNode::Directory(_))),
                        "seed {seed}: {physical:?} sits under {parent:?}, which is not a directory"
                    );
                }
            }
            // 4. An entry at its own path is that path's native winner.
            for (physical, node) in &tree {
                let PhysicalNode::Entry(entry) = node else { continue };
                if entry.placement != Placement::AtPath {
                    continue;
                }
                let heads: Vec<LiveHead> = state.heads_at(&SyncPath(physical.clone())).collect();
                let winner = yadorilink_replica_domain::native_state::resolve_path(heads);
                let yadorilink_replica_domain::native_state::PathMaterialization::Present {
                    winner,
                    ..
                } = winner
                else {
                    panic!("seed {seed}: {physical:?} holds an entry but has no winner")
                };
                let expected =
                    state.heads_at(&SyncPath(physical.clone())).find(|h| h.dot == winner).unwrap();
                assert_eq!(
                    expected.payload.version.0, entry.version_hash,
                    "seed {seed}: {physical:?}"
                );
            }
            // 6. A contested path's global winner holds the real name (a lone
            // survivor of a deleted winner does not count: nothing contests it).
            for (path, heads) in &state.heads {
                let live: Vec<LiveHead> = state.heads_at(path).collect();
                let versions: BTreeSet<_> = heads.values().map(|p| p.version).collect();
                if versions.len() < 2
                    || matches!(tree.get(path.as_str()), Some(PhysicalNode::Directory(_)))
                {
                    continue;
                }
                if heads.values().any(|p| kind_of(&p.version) == RecordKind::Directory) {
                    continue;
                }
                let yadorilink_replica_domain::native_state::PathMaterialization::Present {
                    winner,
                    ..
                } = yadorilink_replica_domain::native_state::resolve_path(live.clone())
                else {
                    continue;
                };
                let winner_version =
                    live.iter().find(|h| h.dot == winner).unwrap().payload.version.0;
                match tree.get(path.as_str()) {
                    Some(PhysicalNode::Entry(entry)) if entry.placement == Placement::AtPath => {
                        assert_eq!(entry.version_hash, winner_version, "seed {seed}: {path:?}");
                    }
                    other => panic!(
                        "seed {seed}: the winner of contested {path:?} must hold the real name, found {other:?}\nheads: {}\ntree: {}",
                        describe_heads(&state),
                        describe_tree(&tree)
                    ),
                }
            }
            // 5. A conflict copy keeps the name it was first given for as long
            // as its content is still live at its path, whichever head holds it
            // and whatever else has become of the path. The
            // expectation is what an EARLIER step assigned; it is checked
            // against this step's tree before this step records anything new.
            named.retain(|(source, version), _| {
                let path = SyncPath(source.clone());
                let live: Vec<LiveHead> = state.heads_at(&path).collect();
                if !live.iter().any(|h| h.payload.version.0 == *version) {
                    return false;
                }
                // Content that has become the global winner of a CONTESTED path
                // takes the real name and gives its copy name up.
                let contested =
                    live.iter().map(|h| h.payload.version).collect::<BTreeSet<_>>().len() > 1;
                let winner =
                    match yadorilink_replica_domain::native_state::resolve_path(live.clone()) {
                        yadorilink_replica_domain::native_state::PathMaterialization::Present {
                            winner,
                            ..
                        } => live.iter().find(|h| h.dot == winner).map(|h| h.payload.version.0),
                        _ => None,
                    };
                // A lone survivor keeps its copy name only while a kept head
                // of that content is live: the declaration covers those heads
                // and nothing put later.
                let kept = stable_projection_binding::native_kept_versions(&c, "g", source)
                    .unwrap()
                    .contains(version);
                if !contested && !kept {
                    return false;
                }
                !(contested && winner == Some(*version))
            });
            for ((source, version), physical) in &named {
                match tree.get(physical) {
                    Some(PhysicalNode::Entry(entry)) if entry.source == *source && entry.version_hash == *version => {}
                    other => panic!(
                        "seed {seed}: copy of v{} of {source:?} lost its name {physical:?}: {other:?}\nheads: {}\ntree: {}",
                        version[0],
                        describe_heads(&state),
                        describe_tree(&tree)
                    ),
                }
            }
            for (physical, node) in &tree {
                if let PhysicalNode::Entry(entry) = node {
                    if entry.placement == Placement::ConflictCopy {
                        named
                            .entry((entry.source.clone(), entry.version_hash))
                            .or_insert_with(|| physical.clone());
                    }
                }
            }
        }
    }
}

#[test]
fn one_delta_landing_at_two_paths_keeps_each_entry_at_its_own_source() {
    use yadorilink_replica_domain::native_state::PathEdit;
    let c = conn();
    let (fa, fb) = (file(1), file(2));
    store(&c, &[&fa, &fb]);
    let mut state = NativeState::new();
    // One dot, two paths.
    state
        .author(
            &author("a"),
            vec![
                PathEdit {
                    path: SyncPath("a".into()),
                    observed: Vec::new(),
                    put: Some(payload(&fa)),
                },
                PathEdit {
                    path: SyncPath("b".into()),
                    observed: Vec::new(),
                    put: Some(payload(&fb)),
                },
            ],
        )
        .unwrap();
    install(&c, &state);

    let tree = level(&c, "");
    assert_eq!(entry_at(&tree, "a").source, "a");
    assert_eq!(entry_at(&tree, "b").source, "b");
    assert_eq!(entry_at(&tree, "a").version_hash, fa.version_hash.0);
    assert_eq!(entry_at(&tree, "b").version_hash, fb.version_hash.0);
}

#[test]
fn two_files_of_one_delta_that_both_need_directories_are_both_relocated() {
    use yadorilink_replica_domain::native_state::PathEdit;
    let c = conn();
    let (fa, fb, ca, cb) = (file(1), file(2), file(3), file(4));
    store(&c, &[&fa, &fb, &ca, &cb]);
    let mut state = NativeState::new();
    state
        .author(
            &author("a"),
            vec![
                PathEdit {
                    path: SyncPath("a".into()),
                    observed: Vec::new(),
                    put: Some(payload(&fa)),
                },
                PathEdit {
                    path: SyncPath("b".into()),
                    observed: Vec::new(),
                    put: Some(payload(&fb)),
                },
            ],
        )
        .unwrap();
    state.put(&author("a"), SyncPath("a/x".into()), &[], payload(&ca)).unwrap();
    state.put(&author("a"), SyncPath("b/y".into()), &[], payload(&cb)).unwrap();
    install(&c, &state);

    let root = level(&c, "");
    let relocated: BTreeMap<String, [u8; 32]> = root
        .nodes()
        .values()
        .filter_map(|node| match node {
            PhysicalNode::Entry(e) if e.placement == Placement::Relocated => {
                Some((e.source.clone(), e.version_hash))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        relocated,
        BTreeMap::from([
            ("a".to_string(), fa.version_hash.0),
            ("b".to_string(), fb.version_hash.0)
        ]),
        "{root:?}"
    );
}

#[test]
fn a_bound_sole_survivor_does_not_hide_the_directory_its_path_has_to_be() {
    let c = conn();
    let (win, lose, child) = (file(1), file(2), file(3));
    store(&c, &[&win, &lose, &child]);
    let a = author("a");
    let mut state = NativeState::new();
    let winner_dot = state.put(&a, SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);
    level(&c, ""); // names the loser
                   // The winner goes; the loser is the sole survivor, and x gains a child.
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.delete(&a, SyncPath("x".into()), std::slice::from_ref(&winner_dot)).unwrap();
    state.put(&a, SyncPath("x/child".into()), &[], payload(&child)).unwrap();
    install(&c, &state);

    assert_eq!(
        native_desired_path_state(&c, "g", "x").unwrap(),
        DesiredPathState::StructuralDirectory,
        "x has a live descendant, so it is a directory whatever a file head was named"
    );
    assert!(matches!(
        level(&c, "").get("x"),
        Some(PhysicalNode::Directory(DirectoryNode::Structural))
    ));
}

#[test]
fn a_winner_rewritten_with_the_same_content_is_a_different_plan() {
    let c = conn();
    let f = file(1);
    store(&c, &[&f]);
    let a = author("a");
    let mut state = NativeState::new();
    let first = state.put(&a, SyncPath("x".into()), &[], payload(&f)).unwrap();
    install(&c, &state);
    let before = native_plan_level(&c, "g", "").unwrap();
    assert_eq!(native_plan_level(&c, "g", "").unwrap(), before, "same state, same plan");

    // The same content rewritten by a later delta (a new dot): the
    // projection is unchanged, the plan is not -- prepared work must notice.
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.put(&a, SyncPath("x".into()), std::slice::from_ref(&first), payload(&f)).unwrap();
    install(&c, &state);
    let after = native_plan_level(&c, "g", "").unwrap();
    assert_ne!(after, before);
    assert_eq!(native_desired_level_projection(&c, "g", "").unwrap().nodes().len(), 1);
}

#[test]
fn a_planned_copy_stands_for_its_source_head_and_inherits_its_demand() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    let loser_dot = state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);

    let plan = native_plan_level(&c, "g", "").unwrap();
    let (copy_path, node) = plan
        .nodes
        .iter()
        .find(|(_, node)| {
            matches!(
                node,
                NativePlannedNode::Entry {
                    placement:
                        yadorilink_replica_domain::native_materialize::Placement::ConflictCopy,
                    ..
                }
            )
        })
        .expect("a planned copy");
    let NativePlannedNode::Entry { head, .. } = node else { unreachable!() };
    assert_ne!(copy_path.as_str(), "x");
    assert_eq!(head.source_path, SyncPath("x".into()));
    assert_eq!(head.dot(), &loser_dot);
}

#[test]
fn an_explicit_directory_plan_names_its_directory_head() {
    let c = conn();
    let dir = version(RecordKind::Directory, 1);
    store(&c, &[&dir]);
    let mut state = NativeState::new();
    let dot = state.put(&author("a"), SyncPath("d".into()), &[], payload(&dir)).unwrap();
    install(&c, &state);

    match native_plan_path(&c, "g", "d").unwrap() {
        NativeDesiredNode::ExplicitDirectory { head } => {
            assert_eq!((head.source_path.as_str(), head.dot()), ("d", &dot));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(native_plan_path(&c, "g", "nothing").unwrap(), NativeDesiredNode::Absent);
}

#[test]
fn an_unresolvable_version_fails_the_plan_instead_of_planning_an_absence() {
    let c = conn();
    let missing = file(1);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&missing)).unwrap();
    install(&c, &state);

    assert!(matches!(native_plan_path(&c, "g", "x"), Err(SyncSqliteError::NotFound(_))));
    assert!(matches!(native_plan_level(&c, "g", ""), Err(SyncSqliteError::NotFound(_))));
}

/// The physical names a level's plan gives must not depend on which query
/// ran first. A per-path plan (or an ensure around one path) sees only that
/// path's heads; it must still see the other names taken at the level.
fn conflict_next_to_a_file_on_its_first_copy_name() -> (NativeState, FileVersion, String) {
    let (win, lose, squatter) = (file(1), file(2), file(3));
    let first = crate::native_projection_binding::numbered_copy_name("x", lose.version_hash.0, 1);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    // An ordinary live file already sits on the copy's first candidate name.
    state.put(&author("z"), SyncPath(first.clone()), &[], payload(&squatter)).unwrap();
    (state, squatter, first)
}

fn seeded(state: &NativeState, versions: &[FileVersion]) -> Connection {
    let c = conn();
    store(&c, &versions.iter().collect::<Vec<_>>());
    install(&c, state);
    c
}

#[test]
fn the_level_plan_does_not_depend_on_a_per_path_query_having_run_first() {
    let (state, squatter, first) = conflict_next_to_a_file_on_its_first_copy_name();
    let versions = [file(1), file(2), squatter.clone()];

    let direct = seeded(&state, &versions);
    let expected = native_plan_level(&direct, "g", "").unwrap();

    for prelude in ["path", "around", "ancestors-of-a-child"] {
        let c = seeded(&state, &versions);
        match prelude {
            "path" => {
                native_plan_path(&c, "g", "x").unwrap();
            }
            "around" => {
                crate::native_projection_binding::ensure_native_placements_around(&c, "g", "x")
                    .unwrap()
            }
            _ => crate::native_projection_binding::ensure_native_placements_around(
                &c, "g", "x/deeper",
            )
            .unwrap(),
        }
        assert_eq!(native_plan_level(&c, "g", "").unwrap(), expected, "after {prelude}");
    }

    // And the file that was already there keeps its own name.
    match expected.nodes.get(&SyncPath(first.clone())) {
        Some(NativePlannedNode::Entry { head, placement, .. }) => {
            assert_eq!(head.version(), squatter.version_hash);
            assert_eq!(
                *placement,
                yadorilink_replica_domain::native_materialize::Placement::AtPath
            );
        }
        other => panic!("{first:?} must stay the file that lives there: {other:?}"),
    }
}

/// A placement is the exact head it names -- dot AND provenance. A stored
/// row whose provenance is not the live head's names another write and is
/// neither applied nor kept. (The conflict-copy path rewrites its own rows
/// from the live head, so the guard is exercised on the pieces directly.)
/// The index row at `path` showing `version`, as the materializer leaves it.
fn show_row(c: &Connection, path: &str, version: &FileVersion) {
    let tx = c.unchecked_transaction().unwrap();
    crate::file_index::upsert_file_in_tx(
        &tx,
        "g",
        &yadorilink_replica_domain::file::FileRecord {
            path: path.to_string(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        },
        "device-x",
    )
    .unwrap();
    crate::file_index::apply_local_meta_columns_in_tx(
        &tx,
        "g",
        path,
        &yadorilink_replica_domain::session_state::LocalFileMetaColumns {
            record_kind: version.meta.record_kind,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: version.meta.unix_mode,
            xattrs: Vec::new(),
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

fn a_placement_row_with_the_wrong_provenance(
    c: &Connection,
) -> (BTreeMap<SyncPath, PathHeads>, HashMap<VersionHash, RecordKind>) {
    let lose = file(2);
    store(c, &[&lose]);
    // The index row at the held name shows that version, so the hold would
    // stay live on its own: only the provenance can retire it.
    show_row(c, "x held", &lose);
    let dot = Dot { author: author("b"), seq: yadorilink_replica_domain::ids::AuthorSeq(1) };
    let heads: PathHeads = PathHeads::from([(dot.clone(), payload(&lose))]);
    let children = BTreeMap::from([(SyncPath("x".into()), heads)]);
    let kinds = HashMap::from([(lose.version_hash, RecordKind::File)]);
    stable_projection_binding::native_placement_put(
        c,
        "g",
        &stable_projection_binding::NativePlacementRow {
            physical_path: "x held".into(),
            source_path: "x".into(),
            author: "b".into(),
            incarnation: [1; 16],
            seq: 1,
            provenance: [0; 32], // not the live head's provenance
            version: lose.version_hash.0,
            origin: "reconciliation_hold".into(),
        },
    )
    .unwrap();
    (children, kinds)
}

#[test]
fn a_placement_naming_another_write_is_not_applied() {
    let c = conn();
    let (children, kinds) = a_placement_row_with_the_wrong_provenance(&c);
    let mut level = resolver::AppliedLevel::default();
    let placements = crate::native_projection_binding::placement_records(&c, "g").unwrap();
    resolver::apply_placements(
        "",
        &placements,
        &children,
        &kinds,
        &resolver::KeptCopies::new(),
        &mut level,
    );
    assert!(level.nodes.is_empty(), "the stale row must not place the head: {:?}", level.nodes);
}

#[test]
fn a_placement_naming_another_write_is_forgotten() {
    let c = conn();
    let (children, _) = a_placement_row_with_the_wrong_provenance(&c);
    ensure_native_projection_bindings(&c, "g", &children, &BTreeMap::new()).unwrap();
    let rows = stable_projection_binding::native_placements_for_source(&c, "g", "x").unwrap();
    assert!(
        rows.iter().all(|row| row.physical_path != "x held"),
        "the stale hold must be dropped: {rows:?}"
    );
}

fn payload_by(v: &FileVersion, provenance: u8) -> HeadPayload {
    HeadPayload { version: v.version_hash, provenance: DeltaHash([provenance; 32]) }
}

fn only_copy(plan: &NativeLevelPlan) -> (SyncPath, NativeLocatedHead) {
    let copies: Vec<_> = plan
        .nodes
        .iter()
        .filter_map(|(path, node)| match node {
            NativePlannedNode::Entry {
                head,
                placement: yadorilink_replica_domain::native_materialize::Placement::ConflictCopy,
                ..
            } => Some((path.clone(), head.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(copies.len(), 1, "exactly one visible copy: {plan:?}");
    copies.into_iter().next().unwrap()
}

/// The copy is the content, not the head that happened to represent it: when
/// another head of the same content outranks the representative, the name
/// stays and the plan names the new representative.
#[test]
fn a_copy_keeps_its_name_when_another_head_of_its_content_becomes_the_representative() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload_by(&win, 1)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload_by(&lose, 1)).unwrap();
    install(&c, &state);
    let (name, first) = only_copy(&native_plan_level(&c, "g", "").unwrap());
    assert_eq!(first.dot().author.device.0, "b");

    // The same content, at the same rank but a higher provenance, from another device.
    state.put(&author("c"), SyncPath("x".into()), &[], payload_by(&lose, 9)).unwrap();
    install(&c, &state);

    let (same_name, representative) = only_copy(&native_plan_level(&c, "g", "").unwrap());
    assert_eq!(same_name, name, "nothing visible changed, so the name must not");
    assert_eq!(
        representative.dot().author.device.0,
        "c",
        "the plan names the head that represents it now"
    );
    assert_eq!(
        stable_projection_binding::native_placements_for_source(&c, "g", "x").unwrap().len(),
        1,
        "one visible copy is one placement, not one per head that ever represented it"
    );
    // ... and it stays put across further evaluations and a representative that vanishes.
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    let c_dot = representative.dot().clone();
    state.delete(&author("c"), SyncPath("x".into()), std::slice::from_ref(&c_dot)).unwrap();
    install(&c, &state);
    let (after_removal, last) = only_copy(&native_plan_level(&c, "g", "").unwrap());
    assert_eq!(after_removal, name, "the content is still live through the other head");
    assert_eq!(last.dot().author.device.0, "b");
}

/// A binding an earlier representative kept must not pull a copy back from
/// the name its content already has.
#[test]
fn an_old_representatives_binding_does_not_move_a_named_copy() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("w"), SyncPath("x".into()), &[], payload_by(&win, 1)).unwrap();
    state.put(&author("a"), SyncPath("x".into()), &[], payload_by(&lose, 5)).unwrap(); // the representative
    state.put(&author("b"), SyncPath("x".into()), &[], payload_by(&lose, 1)).unwrap();
    install(&c, &state);
    let a_dot = head_dot_of("a", &state);
    let b_dot = head_dot_of("b", &state);
    // A once had its own copy at N (its binding survives); the content now
    // lives at M, named through B.
    let n = "x (old name)";
    let m = "x (current name)";
    stable_projection_binding::native_bind(
        &c,
        "g",
        &("x".to_string(), "a".to_string(), a_dot.author.incarnation.0, a_dot.seq.get()),
        n,
    )
    .unwrap();
    stable_projection_binding::native_placement_put(
        &c,
        "g",
        &stable_projection_binding::NativePlacementRow {
            physical_path: m.into(),
            source_path: "x".into(),
            author: "b".into(),
            incarnation: b_dot.author.incarnation.0,
            seq: b_dot.seq.get(),
            provenance: [1; 32],
            version: lose.version_hash.0,
            origin: "conflict_copy".into(),
        },
    )
    .unwrap();

    crate::native_projection_binding::ensure_native_placements_around(&c, "g", "x").unwrap();

    let names: Vec<String> = stable_projection_binding::native_placements_for_source(&c, "g", "x")
        .unwrap()
        .into_iter()
        .map(|row| row.physical_path)
        .collect();
    assert_eq!(names, vec![m.to_string()], "the content keeps the name it has");
}

fn head_dot_of(device: &str, state: &NativeState) -> Dot {
    state
        .heads
        .get(&SyncPath("x".into()))
        .unwrap()
        .keys()
        .find(|dot| dot.author.device.0 == device)
        .cloned()
        .unwrap()
}
/// The two transitions are different. A winner that is DELETED by an author that saw
/// the copy leaves the copy where it is and the real name empty.
#[test]
fn a_loser_left_alone_by_a_deleted_winner_is_not_promoted() {
    let c = conn();
    let (v1, v2) = (file(1), file(2));
    store(&c, &[&v1, &v2]);
    let a = author("a");
    let mut state = NativeState::new();
    let winner_dot = state.put(&a, SyncPath("x".into()), &[], payload_by(&v1, 1)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload_by(&v2, 1)).unwrap();
    install(&c, &state);
    let (copy_name, _) = only_copy(&native_plan_level(&c, "g", "").unwrap());

    // The deleting author saw the copy, so its delta declares it kept.
    stable_projection_binding::native_keep_heads_of_version(&c, "g", "x", &v2.version_hash.0)
        .unwrap();
    state.delete(&a, SyncPath("x".into()), std::slice::from_ref(&winner_dot)).unwrap();
    install(&c, &state);

    let plan = native_plan_level(&c, "g", "").unwrap();
    assert!(!plan.nodes.contains_key(&SyncPath("x".into())), "the real name stays empty: {plan:?}");
    let (name, _) = only_copy(&plan);
    assert_eq!(name, copy_name);
}

#[test]
fn a_planned_entry_with_no_row_is_a_gap_until_its_row_exists() {
    use yadorilink_replica_domain::file::FileRecord;
    let mut c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("d/x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("d/x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);

    // Nothing projected: the path and its copy are both owed.
    assert_eq!(native_plan_gap_paths(&c, "g").unwrap(), BTreeSet::from(["d/x".to_owned()]));

    // Rows for the winner and for the copy the plan names.
    let tree = level(&c, "d");
    let tx = c.transaction().unwrap();
    for path in tree.nodes().keys() {
        let record = FileRecord {
            path: path.as_str().to_owned(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        crate::file_index::upsert_file_in_tx(&tx, "g", &record, "a").unwrap();
    }
    tx.commit().unwrap();
    assert!(native_plan_gap_paths(&c, "g").unwrap().is_empty());
}
