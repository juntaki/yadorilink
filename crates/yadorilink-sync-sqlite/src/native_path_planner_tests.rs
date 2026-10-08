//! Pins what planning one path costs in a directory of many siblings, and that the
//! path-scoped plan is the plan the whole level gives that path.

use rusqlite::Connection;

use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::native_plan::NativePlannedNode;

use crate::native_store::head_row_counters;
use crate::stable_projection_binding::level_row_counters;

fn version(kind: RecordKind, mtime: i64) -> FileVersion {
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

/// The `n`-th file version in winner order: `ranked(1)` beats `ranked(2)`,
/// because concurrent heads are ordered by version hash.
fn ranked(n: i64) -> FileVersion {
    let mut pool: Vec<FileVersion> = (1..=16).map(|m| version(RecordKind::File, m)).collect();
    pool.sort_by_key(|v| std::cmp::Reverse(v.version_hash));
    pool.swap_remove(n as usize - 1)
}

fn insert_head(c: &Connection, path: &str, device: &str, seq: u64, v: &FileVersion) {
    c.prepare_cached(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
         provenance) VALUES ('g', ?1, ?2, zeroblob(16), ?3, ?4, ?4)",
    )
    .unwrap()
    .execute(rusqlite::params![path, device, seq as i64, v.version_hash.0.as_slice()])
    .unwrap();
}

fn count_vm_work(c: &Connection) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = ticks.clone();
    c.progress_handler(
        1000,
        Some(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }),
    );
    ticks
}

const CONTESTED: usize = 3;

/// A directory `big` of `files` plain files plus `CONTESTED` contested files whose
/// conflict copies are already named (the state a settled group is in).
fn big_directory(files: usize) -> (Connection, Vec<String>) {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    let (a, b, plain) = (ranked(1), ranked(2), ranked(3));
    for v in [&a, &b, &plain] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    c.execute_batch("BEGIN").unwrap();
    for f in 0..files {
        insert_head(&c, &format!("big/file-{f:06}"), "a", f as u64 + 1, &plain);
    }
    for k in 0..CONTESTED {
        let path = format!("big/contested-{k}");
        insert_head(&c, &path, "a", 100_000 + k as u64, &a);
        insert_head(&c, &path, "b", 200_000 + k as u64, &b);
    }
    c.execute_batch("COMMIT").unwrap();
    crate::native_desired_state::native_plan_level(&c, "g", "big").unwrap();
    let sample = [0, files / 3, files / 2, files - 1]
        .iter()
        .map(|f| format!("big/file-{f:06}"))
        .chain(["big/contested-1".to_string()])
        .collect();
    (c, sample)
}

/// What planning one path reads: `(head rows, placement rows, vm work in thousands)`.
fn one_path_cost(
    files: usize,
    plan_one: &dyn Fn(&Connection, &str) -> Option<NativePlannedNode>,
) -> (u64, u64, u64) {
    let (c, sample) = big_directory(files);
    let ticks = count_vm_work(&c);
    let (mut heads, mut placements) = (0, 0);
    ticks.store(0, std::sync::atomic::Ordering::Relaxed);
    for path in &sample {
        head_row_counters::reset();
        level_row_counters::reset();
        let node = plan_one(&c, path);
        assert!(node.is_some(), "{path} is planned");
        heads += head_row_counters::snapshot().0;
        placements += level_row_counters::snapshot().0;
    }
    let n = sample.len() as u64;
    (heads / n, placements / n, ticks.load(std::sync::atomic::Ordering::Relaxed) / n)
}

fn plan_one_path(c: &Connection, path: &str) -> Option<NativePlannedNode> {
    crate::native_desired_state::native_plan_node(c, "g", path).unwrap()
}

#[test]
fn planning_one_path_does_not_read_its_siblings() {
    let costs: Vec<_> =
        [1000usize, 4000, 10_000].iter().map(|n| (*n, one_path_cost(*n, &plan_one_path))).collect();
    for (n, (heads, placements, vm)) in &costs {
        eprintln!(
            "{n} siblings: {heads} head rows, {placements} placement rows, {vm}k vm per path"
        );
    }
    for (n, (heads, placements, _)) in &costs {
        // The path's own heads, its ancestors' and the few paths its placements name.
        assert!(*heads <= 40, "{n} siblings: one path read {heads} head rows");
        assert!(*placements <= 4 * (CONTESTED as u64 + 1), "{n} siblings: {placements} placements");
    }
    let (small, large) = (costs[0].1 .2, costs[2].1 .2);
    assert!(
        (large as f64) <= 1.5 * small.max(1) as f64,
        "ten times the siblings grew one path's plan from {small} to {large} (vm work)"
    );
}

/// A directory `cheap` holding `copies` contested files (so `copies` recorded conflict copies)
/// and a few plain files, planned once so the placements are recorded.
fn copy_heavy_directory(copies: usize) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    let (a, b, plain) = (ranked(1), ranked(2), ranked(3));
    for v in [&a, &b, &plain] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    c.execute_batch("BEGIN").unwrap();
    for k in 0..copies {
        let path = format!("cheap/c-{k:06}");
        insert_head(&c, &path, "a", 2 * k as u64 + 1, &a);
        insert_head(&c, &path, "b", 2 * k as u64 + 2, &b);
    }
    for f in 0..20 {
        insert_head(&c, &format!("cheap/file-{f:02}"), "a", 1_000_000 + f, &plain);
    }
    c.execute_batch("COMMIT").unwrap();
    native_plan_level(&c, "g", "cheap").unwrap();
    c
}

/// What planning one name reads in a directory of recorded copies, per kind of request.
/// `(head rows, placement rows, vm work in thousands)`.
fn request_costs(copies: usize) -> Vec<(&'static str, (u64, u64, u64))> {
    let c = copy_heavy_directory(copies);
    let b = ranked(2);
    let plain = ranked(3);
    crate::dag_store::put_file_version(&c, "g", &plain).unwrap();
    let mid = copies / 2;
    let ticks = count_vm_work(&c);
    let measure = |label: &'static str, name: String| {
        head_row_counters::reset();
        level_row_counters::reset();
        ticks.store(0, std::sync::atomic::Ordering::Relaxed);
        let planned = native_plan_node(&c, "g", &name).unwrap();
        let vm = ticks.load(std::sync::atomic::Ordering::Relaxed);
        (label, (head_row_counters::snapshot().0, level_row_counters::snapshot().0, vm), planned)
    };
    let mut out = Vec::new();
    // A file that did not exist: its own name holds nothing, so what could land on it is looked up.
    insert_head(&c, "cheap/new-file", "a", 2_000_000, &plain);
    let (label, cost, planned) = measure("new file", "cheap/new-file".to_owned());
    assert!(planned.is_some());
    out.push((label, cost));
    // A path with its two contesting heads.
    let (label, cost, planned) = measure("contested path", format!("cheap/c-{mid:06}"));
    assert!(planned.is_some());
    out.push((label, cost));
    // The copy of a contested path, asked for by its name.
    let copy = numbered_copy_name(&format!("cheap/c-{mid:06}"), b.version_hash.0, 1);
    let (label, cost, planned) = measure("copy name", copy);
    assert!(planned.is_some());
    out.push((label, cost));
    // An entry that went: its name holds nothing.
    c.execute("DELETE FROM native_heads WHERE group_id='g' AND path='cheap/file-07'", []).unwrap();
    let (label, cost, planned) = measure("deleted entry", "cheap/file-07".to_owned());
    assert!(planned.is_none());
    out.push((label, cost));
    out
}

/// Planning one name reads no head of the placements' names one by one: the heads read stay
/// constant while the directory's recorded copies grow, whatever the request. The placement rows
/// of the level are read once per request, so a directory of many copies costs those rows (and
/// the one set-based lookup of which of their names a head holds) per request.
#[test]
fn a_request_in_a_directory_of_copies_reads_a_constant_number_of_heads() {
    let tables: Vec<_> = [1000usize, 4000].iter().map(|n| (*n, request_costs(*n))).collect();
    for (copies, costs) in &tables {
        for (label, (heads, placements, vm)) in costs {
            eprintln!(
                "{copies} copies: {label}: {heads} head rows, {placements} placement rows, {vm}k vm"
            );
        }
    }
    for (copies, costs) in &tables {
        for (label, (heads, placements, _)) in costs {
            assert!(*heads <= 40, "{copies} copies, {label}: {heads} head rows");
            // The level's placement rows, read a few times over (before and after bringing
            // the names up to date), never per name.
            assert!(
                *placements <= 4 * *copies as u64 + 40,
                "{copies} copies, {label}: {placements} placement rows"
            );
        }
    }
}

// --- the path-scoped plan is the level plan's node, for every path --------------------------

use std::collections::BTreeSet;

use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::native_plan::NativeLevelPlan;

use crate::native_desired_state::{
    native_plan_level, native_plan_node, native_plan_nodes, read_native_plan_node, PlanRead,
};
use crate::native_projection_binding::{ensure_native_placements_around, numbered_copy_name};

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

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

struct World {
    c: Connection,
    files: Vec<FileVersion>,
    dirs: Vec<FileVersion>,
    symlink: FileVersion,
    seq: u64,
    names: Vec<String>,
}

fn world() -> World {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    let files: Vec<FileVersion> = (1..=4).map(ranked).collect();
    let dirs = vec![version(RecordKind::Directory, 0)];
    let mut symlink = version(RecordKind::Symlink, 9);
    symlink.meta.symlink_target = Some(b"target".to_vec());
    let symlink = FileVersion::new(Vec::new(), 0, symlink.meta);
    for v in files.iter().chain(&dirs).chain([&symlink]) {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    // Names that collide: case-only and unicode variants, and the names a copy of one of
    // them is given, so a later file can take the name a copy already holds.
    let stems = ["a", "b", "A", "é", "e\u{301}", "ü", "d1", "x y"];
    let mut names: Vec<String> = Vec::new();
    for parent in ["", "d", "d/sub"] {
        for stem in stems {
            let path = if parent.is_empty() { stem.to_owned() } else { format!("{parent}/{stem}") };
            for v in files.iter().take(3) {
                for attempt in 1..=3 {
                    names.push(numbered_copy_name(&path, v.version_hash.0, attempt));
                }
            }
            // Where an entry sitting on a copy's name goes when a placement takes the name
            // from it: a numbered name of the copy.
            for v in files.iter().take(3) {
                let copy = numbered_copy_name(&path, v.version_hash.0, 1);
                for other in files.iter().take(3) {
                    for attempt in 2..=3 {
                        names.push(numbered_copy_name(&copy, other.version_hash.0, attempt));
                    }
                }
            }
            names.push(path);
        }
    }
    names.extend(["d", "d/sub", "d/sub/deep", "d/sub/deep/er", "plain"].map(str::to_owned));
    names.sort();
    names.dedup();
    World { c, files, dirs, symlink, seq: 0, names }
}

impl World {
    fn heads_of(&self, path: &str) -> Vec<(String, u64, Vec<u8>)> {
        let mut stmt = self
            .c
            .prepare("SELECT author, seq, version FROM native_heads WHERE group_id='g' AND path=?1")
            .unwrap();
        stmt.query_map([path], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    fn placed_name(&self, rng: &mut Rng) -> Option<String> {
        let mut stmt =
            self.c.prepare("SELECT physical_path FROM native_physical_placement").unwrap();
        let names: Vec<String> =
            stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        (!names.is_empty()).then(|| rng.pick(&names).clone())
    }

    fn head_paths(&self) -> Vec<String> {
        let mut stmt =
            self.c.prepare("SELECT DISTINCT path FROM native_heads WHERE group_id='g'").unwrap();
        stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
    }

    /// What a delta's arrival does for a path it touched; skipped for a few steps, so that
    /// some states hold heads whose placements nothing has brought up to date yet.
    fn ensure(&self, name: &str, lazy: bool) {
        if !lazy {
            ensure_native_placements_around(&self.c, "g", name).unwrap();
        }
    }

    /// A copy of one of the live heads recorded at `physical`, as a placement left over from
    /// a state the heads have since moved on from.
    fn record_copy_at(&self, source: &str, physical: &str) {
        let Some((author, seq, version)) = self.heads_of(source).into_iter().next() else {
            return;
        };
        let version: [u8; 32] = version.try_into().unwrap();
        let row = crate::stable_projection_binding::NativePlacementRow {
            physical_path: physical.to_owned(),
            source_path: source.to_owned(),
            author,
            incarnation: [0; 16],
            seq,
            provenance: version,
            version,
            origin: "conflict_copy".to_owned(),
        };
        crate::stable_projection_binding::native_placement_put(&self.c, "g", &row).unwrap();
    }

    fn step(&mut self, rng: &mut Rng) {
        if rng.below(14) == 0 {
            let heads = self.head_paths();
            if !heads.is_empty() {
                let source = rng.pick(&heads).clone();
                let physical = rng.pick(&self.names).clone();
                if physical != source {
                    self.record_copy_at(&source, &physical);
                }
            }
            return;
        }
        let lazy = rng.below(5) == 0;
        let name = match rng.below(12) {
            // A name already holding a placement: a file arriving on a copy's name.
            0..=2 => self.placed_name(rng).unwrap_or_else(|| rng.pick(&self.names).clone()),
            // A name an entry sitting on a held name would be displaced to.
            10..=11 => {
                let held = self.head_paths();
                let base = if held.is_empty() || rng.below(3) == 0 {
                    self.placed_name(rng)
                } else {
                    Some(rng.pick(&held).clone())
                };
                match base {
                    Some(base) => {
                        let v = rng.pick(&self.files).version_hash.0;
                        numbered_copy_name(&base, v, 2 + rng.below(2) as u32)
                    }
                    None => rng.pick(&self.names).clone(),
                }
            }
            // A few names that everything collides on.
            3..=6 => rng.pick(&["a", "b", "A", "d/a", "d/b", "d", "d/sub"]).to_string(),
            _ => rng.pick(&self.names).clone(),
        };
        match rng.below(10) {
            // A head: mostly files, sometimes a directory or a symlink, from one of three
            // devices (two heads of a path from different devices is a contest).
            0..=5 => {
                let device = ["a", "b", "c"][rng.below(3)];
                if self.heads_of(&name).iter().any(|(d, _, _)| d == device) {
                    return;
                }
                let v = match rng.below(10) {
                    0 => self.dirs[0].clone(),
                    1 => self.symlink.clone(),
                    _ => rng.pick(&self.files).clone(),
                };
                self.seq += 1;
                insert_head(&self.c, &name, device, self.seq, &v);
                self.ensure(&name, lazy);
            }
            // A head goes (a removal or a supersession).
            6..=8 => {
                let heads = self.heads_of(&name);
                if heads.is_empty() {
                    return;
                }
                let (device, seq, _) = rng.pick(&heads).clone();
                self.c
                    .execute(
                        "DELETE FROM native_heads WHERE group_id='g' AND path=?1 AND author=?2 \
                         AND seq=?3",
                        rusqlite::params![name, device, seq as i64],
                    )
                    .unwrap();
                // A keep goes with its head.
                self.c
                    .execute(
                        "DELETE FROM native_head_keep WHERE group_id='g' AND path=?1 \
                         AND author=?2 AND seq=?3",
                        rusqlite::params![name, device, seq as i64],
                    )
                    .unwrap();
                self.ensure(&name, lazy);
            }
            // A delta declares every live head of a version at the path kept, as an author
            // that observed that whole same-version cohort does.
            _ => {
                let v = rng.pick(&self.files).version_hash.0;
                crate::stable_projection_binding::native_keep_heads_of_version(
                    &self.c, "g", &name, &v,
                )
                .unwrap();
                self.ensure(&name, lazy);
            }
        }
    }

    /// Every name worth asking about: the paths with heads, their ancestors, the placed names
    /// and the sources, and a few names that have nothing.
    fn candidate_names(&self, rng: &mut Rng) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        for path in self.head_paths() {
            let mut cur = Some(path.as_str());
            while let Some(p) = cur {
                out.insert(p.to_owned());
                cur = p.rsplit_once('/').map(|(parent, _)| parent);
            }
        }
        let mut stmt = self
            .c
            .prepare("SELECT physical_path, source_path FROM native_physical_placement")
            .unwrap();
        for row in
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap()
        {
            let (physical, source) = row.unwrap();
            out.insert(physical);
            out.insert(source);
        }
        for _ in 0..6 {
            out.insert(rng.pick(&self.names).clone());
        }
        out
    }
}

/// Which shapes the generated states reached, so the comparison cannot pass by never
/// meeting the cases the path-scoped plan has to get right.
#[derive(Default, Debug)]
struct Coverage {
    copies: usize,
    relocated: usize,
    displaced: usize,
    /// Displaced entries that skipped at least one numbered name something else held.
    displaced_past_a_held_name: usize,
    structural: usize,
    explicit: usize,
    /// Scoped plans whose read needed nothing recorded, and ones whose read needed a write.
    read_only: usize,
    read_needs_write: usize,
}

impl Coverage {
    fn note(&mut self, plan: &NativeLevelPlan) {
        use yadorilink_replica_domain::native_materialize::Placement;
        for (physical, node) in &plan.nodes {
            match node {
                NativePlannedNode::StructuralDirectory => self.structural += 1,
                NativePlannedNode::ExplicitDirectory { .. } => self.explicit += 1,
                NativePlannedNode::Entry { placement, head, .. } => {
                    match placement {
                        Placement::ConflictCopy => self.copies += 1,
                        Placement::Relocated => self.relocated += 1,
                        Placement::AtPath => {}
                    }
                    // A placed entry that is not a copy of its source's own name: an
                    // entry moved off a name that something else was placed on.
                    if *placement == Placement::AtPath && head.source_path != *physical {
                        self.displaced += 1;
                        let version = head.version().0;
                        if (3..8).any(|attempt| {
                            numbered_copy_name(head.source_path.as_str(), version, attempt)
                                == physical.as_str()
                        }) {
                            self.displaced_past_a_held_name += 1;
                        }
                    }
                }
            }
        }
    }
}

/// Every recorded placement and stable name, as text.
fn recorded_placements(c: &Connection) -> Vec<String> {
    let mut rows = Vec::new();
    for sql in [
        "SELECT physical_path || '|' || source_path || '|' || author || '|' || seq || '|' || \
         hex(version) || '|' || hex(provenance) || '|' || origin FROM native_physical_placement",
        "SELECT source_path || '|' || author || '|' || seq || '|' || stable_path \
         FROM native_stable_projection_binding",
    ] {
        let mut stmt = c.prepare(sql).unwrap();
        rows.extend(stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|r| r.unwrap()));
    }
    rows.sort();
    rows
}

fn restricted(level: &NativeLevelPlan, names: &BTreeSet<String>) -> NativeLevelPlan {
    use yadorilink_replica_domain::native_plan::NativePlannedNode;
    let mut plan = level.clone();
    plan.nodes.retain(|physical, node| {
        names.contains(physical.as_str())
            || matches!(node, NativePlannedNode::Entry { head, .. }
                if names.contains(head.source_path.as_str()))
    });
    plan
}

/// Compares, for every name and every level, the path-scoped plan with the level plan.
fn compare(world: &World, rng: &mut Rng, context: &str, seen: &mut Coverage) -> usize {
    let names = world.candidate_names(rng);
    let mut levels: BTreeSet<&str> = names.iter().map(|n| parent_of(n)).collect();
    levels.insert("");
    let mut compared = 0;
    for level in levels {
        let on_level: BTreeSet<String> =
            names.iter().filter(|n| parent_of(n) == level).cloned().collect();
        // Scoped first: it records only what its own names need, as a delta's arrival does.
        // Each is read first, as the repository does: a read that needs nothing recorded is
        // the plan, and the write that follows must agree and record nothing.
        let mut exact = Vec::new();
        for name in &on_level {
            let read = read_native_plan_node(&world.c, "g", name).unwrap();
            let before = recorded_placements(&world.c);
            let node = native_plan_node(&world.c, "g", name).unwrap();
            if read == PlanRead::NeedsPlacements {
                seen.read_needs_write += 1;
            } else if let PlanRead::Planned(read) = read {
                seen.read_only += 1;
                assert_eq!(read, node, "{context}: read plan of {name:?}");
                assert_eq!(
                    recorded_placements(&world.c),
                    before,
                    "{context}: a plan whose read needed nothing recorded recorded something \
                     for {name:?}"
                );
            }
            exact.push((name.clone(), node));
        }
        // A random subset asked together.
        let subset: BTreeSet<String> =
            on_level.iter().filter(|_| rng.below(3) == 0).cloned().collect();
        let together = native_plan_nodes(&world.c, "g", level, &subset).unwrap();
        let whole = native_plan_level(&world.c, "g", level).unwrap();
        seen.note(&whole);
        // A name asked for alone also answers for the entries placed elsewhere that stand for it
        // (the copies of a source), which the callers of a single-name request read.
        for name in &on_level {
            let alone = BTreeSet::from([name.clone()]);
            assert_eq!(
                native_plan_nodes(&world.c, "g", level, &alone).unwrap(),
                restricted(&whole, &alone),
                "{context}: name {name:?} alone (level {level:?})"
            );
        }
        for (name, node) in exact {
            assert_eq!(
                node.as_ref(),
                whole.nodes.get(&SyncPath(name.clone())),
                "{context}: node at {name:?} (level {level:?})"
            );
            compared += 1;
        }
        assert_eq!(together, restricted(&whole, &subset), "{context}: subset {subset:?}");
    }
    compared
}

#[test]
fn the_path_scoped_plan_is_the_level_plan_node_for_every_path() {
    let seeds: u64 =
        std::env::var("PATH_PLANNER_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(400);
    let mut compared = 0;
    let mut seen = Coverage::default();
    for seed in
        std::env::var("PATH_PLANNER_FIRST").ok().and_then(|v| v.parse().ok()).unwrap_or(1)..=seeds
    {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut world = world();
        let steps = 10 + rng.below(30);
        for i in 0..steps {
            world.step(&mut rng);
            if i % 7 == 6 {
                compared += compare(&world, &mut rng, &format!("seed {seed} step {i}"), &mut seen);
            }
        }
        compared += compare(&world, &mut rng, &format!("seed {seed} end"), &mut seen);
    }
    eprintln!("{seeds} seeds, {compared} node comparisons, {seen:?}");
    assert!(compared > 20 * seeds as usize);
    assert!(seen.copies > 0 && seen.relocated > 0 && seen.structural > 0 && seen.explicit > 0);
    assert!(seen.read_only > 0 && seen.read_needs_write > 0, "{seen:?}");
    // The displacer paths are reached by the generated states, not only by the targeted tests.
    assert!(seen.displaced > 0, "no generated state displaced an entry: {seen:?}");
    assert!(
        seen.displaced_past_a_held_name > 0,
        "no generated state displaced an entry past a held name: {seen:?}"
    );
}

/// A file that arrives on the name a conflict copy holds is moved to a numbered name, the
/// first one nothing holds; asking for that name alone finds it.
#[test]
fn an_entry_displaced_by_a_copy_is_found_at_the_first_free_numbered_name() {
    let w = world();
    let (win, lose, other) = (&w.files[0], &w.files[1], &w.files[2]);
    insert_head(&w.c, "x", "a", 1, win);
    insert_head(&w.c, "x", "b", 2, lose);
    ensure_native_placements_around(&w.c, "g", "x").unwrap();
    let copy = numbered_copy_name("x", lose.version_hash.0, 1);
    // Files arrive on the copy's name and on the first name the displaced one would take.
    insert_head(&w.c, &copy, "c", 3, other);
    let first_choice = numbered_copy_name(&copy, other.version_hash.0, 2);
    insert_head(&w.c, &first_choice, "c", 4, other);
    for name in [&copy, &first_choice] {
        ensure_native_placements_around(&w.c, "g", name).unwrap();
    }
    let landed = numbered_copy_name(&copy, other.version_hash.0, 3);

    let node = native_plan_node(&w.c, "g", &landed).unwrap();
    let whole = native_plan_level(&w.c, "g", "").unwrap();
    assert_eq!(node.as_ref(), whole.nodes.get(&SyncPath(landed.clone())));
    match node {
        Some(NativePlannedNode::Entry { head, .. }) => assert_eq!(head.source_path.as_str(), copy),
        other => panic!("the displaced entry is not at {landed:?}: {other:?}"),
    }
    for name in [&copy, &first_choice, &"x".to_owned()] {
        assert_eq!(
            native_plan_node(&w.c, "g", name).unwrap().as_ref(),
            whole.nodes.get(&SyncPath(name.clone())),
            "{name}"
        );
    }
}

/// Asks for every name of `asked` alone and all of them together, then for the whole level, and
/// requires each scoped answer to be the level plan's nodes for those names. Returns the level
/// plan so the test can pin the shape it set up.
fn scoped_agrees_with_level(w: &World, level: &str, asked: &[&str]) -> NativeLevelPlan {
    let mut scoped = Vec::new();
    for name in asked {
        let alone = BTreeSet::from([(*name).to_owned()]);
        scoped.push((alone.clone(), native_plan_nodes(&w.c, "g", level, &alone).unwrap()));
    }
    let together: BTreeSet<String> = asked.iter().map(|n| (*n).to_owned()).collect();
    scoped.push((together.clone(), native_plan_nodes(&w.c, "g", level, &together).unwrap()));
    let whole = native_plan_level(&w.c, "g", level).unwrap();
    for (names, plan) in scoped {
        assert_eq!(plan, restricted(&whole, &names), "names {names:?}");
    }
    whole
}

fn source_of(plan: &NativeLevelPlan, name: &str) -> Option<String> {
    match plan.nodes.get(&SyncPath(name.to_owned())) {
        Some(NativePlannedNode::Entry { head, .. }) => Some(head.source_path.as_str().to_owned()),
        _ => None,
    }
}

/// Two contested paths whose copy names are each taken by a file that arrived afterwards: both
/// files are displaced, and each landing name is answered on its own.
#[test]
fn two_entries_displaced_in_one_level_are_each_found() {
    let w = world();
    let (win, lose, other) = (&w.files[0], &w.files[1], &w.files[2]);
    let mut landings = Vec::new();
    let mut copies = Vec::new();
    for (i, path) in ["x", "y"].iter().enumerate() {
        let seq = 10 * i as u64;
        insert_head(&w.c, path, "a", seq + 1, win);
        insert_head(&w.c, path, "b", seq + 2, lose);
        ensure_native_placements_around(&w.c, "g", path).unwrap();
        let copy = numbered_copy_name(path, lose.version_hash.0, 1);
        insert_head(&w.c, &copy, "c", seq + 3, other);
        ensure_native_placements_around(&w.c, "g", &copy).unwrap();
        landings.push(numbered_copy_name(&copy, other.version_hash.0, 2));
        copies.push(copy);
    }
    let asked: Vec<&str> = landings.iter().chain(&copies).map(String::as_str).collect();
    let whole = scoped_agrees_with_level(&w, "", &asked);
    for (landing, copy) in landings.iter().zip(&copies) {
        assert_eq!(source_of(&whole, landing).as_deref(), Some(copy.as_str()), "{landing}");
    }
    let displaced = whole
        .nodes
        .values()
        .filter(|n| {
            matches!(n, NativePlannedNode::Entry { head, placement, .. }
            if *placement == yadorilink_replica_domain::native_materialize::Placement::AtPath
                && head.source_path.as_str().contains("conflicted copy"))
        })
        .count();
    assert_eq!(displaced, 2);
}

/// A displaced entry skips every numbered name something holds: here two heads sit on the first
/// two, and the entry is found at the third.
#[test]
fn an_entry_displaced_past_two_held_names_is_found() {
    let w = world();
    let (win, lose, other) = (&w.files[0], &w.files[1], &w.files[2]);
    insert_head(&w.c, "x", "a", 1, win);
    insert_head(&w.c, "x", "b", 2, lose);
    ensure_native_placements_around(&w.c, "g", "x").unwrap();
    let copy = numbered_copy_name("x", lose.version_hash.0, 1);
    insert_head(&w.c, &copy, "c", 3, other);
    ensure_native_placements_around(&w.c, "g", &copy).unwrap();
    for (seq, attempt) in [(4, 2), (5, 3)] {
        let held = numbered_copy_name(&copy, other.version_hash.0, attempt);
        insert_head(&w.c, &held, "c", seq, &w.files[3]);
        ensure_native_placements_around(&w.c, "g", &held).unwrap();
    }
    let landed = numbered_copy_name(&copy, other.version_hash.0, 4);
    let whole = scoped_agrees_with_level(&w, "", &[&landed]);
    assert_eq!(source_of(&whole, &landed).as_deref(), Some(copy.as_str()));
}

/// The name a displaced entry lands on is itself the name of a placement (a kept copy of another
/// path), which then takes the name from it and displaces it again. The landing name is outside
/// what the request names, so the plan takes it in, brings its placements up to date and applies
/// again.
#[test]
fn a_displaced_entry_is_displaced_again_by_a_placement_on_its_landing_name() {
    let w = world();
    let (win, lose, other, kept) = (&w.files[0], &w.files[1], &w.files[2], &w.files[3]);
    insert_head(&w.c, "x", "a", 1, win);
    insert_head(&w.c, "x", "b", 2, lose);
    ensure_native_placements_around(&w.c, "g", "x").unwrap();
    let copy = numbered_copy_name("x", lose.version_hash.0, 1);
    insert_head(&w.c, &copy, "c", 3, other);
    ensure_native_placements_around(&w.c, "g", &copy).unwrap();
    let first_landing = numbered_copy_name(&copy, other.version_hash.0, 2);
    let second_landing = numbered_copy_name(&copy, other.version_hash.0, 3);
    // A kept copy of `z` is recorded at the name the entry is first displaced to.
    insert_head(&w.c, "z", "c", 4, kept);
    crate::stable_projection_binding::native_keep_heads_of_version(
        &w.c,
        "g",
        "z",
        &kept.version_hash.0,
    )
    .unwrap();
    w.record_copy_at("z", &first_landing);

    let whole = scoped_agrees_with_level(&w, "", &[&second_landing]);
    assert_eq!(source_of(&whole, &second_landing).as_deref(), Some(copy.as_str()));
    assert_eq!(source_of(&whole, &first_landing).as_deref(), Some("z"));
    assert!(!whole.nodes.contains_key(&SyncPath("z".to_owned())), "the kept copy left z");
    scoped_agrees_with_level(&w, "", &[&first_landing, "z", &copy]);
}

/// A kept head keeps its copy name while it lives, alone at its path; a later head of the same
/// content, which no delta declared, takes the real name. The path-scoped plan agrees with the
/// level plan at both points.
#[test]
fn a_kept_head_keeps_its_copy_name_and_a_later_head_of_the_same_content_does_not() {
    let w = world();
    let (win, kept) = (&w.files[0], &w.files[1]);
    insert_head(&w.c, "z", "a", 1, win);
    insert_head(&w.c, "z", "b", 2, kept);
    ensure_native_placements_around(&w.c, "g", "z").unwrap();
    let copy = numbered_copy_name("z", kept.version_hash.0, 1);
    // The author of the winner saw the loser as a copy, removed the winner and declared the
    // loser kept, exactly.
    assert!(crate::stable_projection_binding::native_keep_head(
        &w.c,
        "g",
        "z",
        "b",
        &[0; 16],
        2,
        &kept.version_hash.0,
    )
    .unwrap());
    w.c.execute("DELETE FROM native_heads WHERE group_id='g' AND path='z' AND author='a'", [])
        .unwrap();
    ensure_native_placements_around(&w.c, "g", "z").unwrap();
    let whole = scoped_agrees_with_level(&w, "", &["z", &copy]);
    assert_eq!(source_of(&whole, &copy).as_deref(), Some("z"), "the kept head keeps its copy name");
    assert!(!whole.nodes.contains_key(&SyncPath("z".to_owned())));

    // The kept head goes (its keep with it); the same content comes back at a new dot.
    w.c.execute("DELETE FROM native_heads WHERE group_id='g' AND path='z' AND author='b'", [])
        .unwrap();
    w.c.execute("DELETE FROM native_head_keep WHERE group_id='g' AND path='z'", []).unwrap();
    insert_head(&w.c, "z", "c", 3, kept);
    ensure_native_placements_around(&w.c, "g", "z").unwrap();
    let whole = scoped_agrees_with_level(&w, "", &["z", &copy]);
    assert_eq!(source_of(&whole, &copy), None, "nothing kept the re-put: no copy name");
    assert!(whole.nodes.contains_key(&SyncPath("z".to_owned())), "the re-put takes the real name");
}

/// A contest on a name an entry is displaced to has its copy recorded only when that name is
/// brought up to date. Asking for the copy's name alone reaches the contested name through the
/// displaced entry, and must still find the copy.
#[test]
fn a_name_brought_in_by_a_displacement_has_its_placements_brought_up_to_date() {
    let w = world();
    let (win, lose, other) = (&w.files[0], &w.files[1], &w.files[2]);
    insert_head(&w.c, "x", "a", 1, win);
    insert_head(&w.c, "x", "b", 2, lose);
    ensure_native_placements_around(&w.c, "g", "x").unwrap();
    let copy = numbered_copy_name("x", lose.version_hash.0, 1);
    insert_head(&w.c, &copy, "c", 3, other);
    ensure_native_placements_around(&w.c, "g", &copy).unwrap();
    // The name the entry is displaced to holds a contest nobody has recorded the copy of yet.
    let landing = numbered_copy_name(&copy, other.version_hash.0, 2);
    insert_head(&w.c, &landing, "a", 4, win);
    let loser = &w.files[3];
    insert_head(&w.c, &landing, "b", 5, loser);
    let landing_copy = numbered_copy_name(&landing, loser.version_hash.0, 1);

    let whole = scoped_agrees_with_level(&w, "", &[&landing_copy]);
    assert_eq!(source_of(&whole, &landing_copy).as_deref(), Some(landing.as_str()));
}

/// Whether `name` is a copy of `source` by the plan asked for `names`, as the audit of copies
/// reads it.
fn names_justify_copy(w: &World, names: &[&str], copy: &str, source: &str) -> bool {
    let asked: BTreeSet<String> = names.iter().map(|n| (*n).to_owned()).collect();
    let plan = native_plan_nodes(&w.c, "g", parent_of(copy), &asked).unwrap();
    source_of(&plan, copy).as_deref() == Some(source)
}

/// A live copy whose source has no recorded placement (the row is missing): the copy is
/// justified, and asking for the copy's name together with its source finds it, as the level plan
/// does. The placements a copy needs are recorded around its source, so the copy's name alone
/// would see none.
#[test]
fn a_copy_is_justified_when_asked_for_together_with_its_source() {
    let w = world();
    let (win, lose) = (&w.files[0], &w.files[1]);
    insert_head(&w.c, "x", "a", 1, win);
    insert_head(&w.c, "x", "b", 2, lose);
    ensure_native_placements_around(&w.c, "g", "x").unwrap();
    let copy = numbered_copy_name("x", lose.version_hash.0, 1);
    crate::stable_projection_binding::native_placement_delete(&w.c, "g", &copy).unwrap();
    let before =
        w.c.query_row("SELECT COUNT(*) FROM native_physical_placement", [], |r| r.get::<_, i64>(0));
    assert_eq!(before.unwrap(), 0, "the copy's row is missing");

    assert!(
        !names_justify_copy(&w, &[&copy], &copy, "x"),
        "the copy's name alone records nothing for it"
    );
    assert!(names_justify_copy(&w, &[&copy, "x"], &copy, "x"));
    let whole = native_plan_level(&w.c, "g", "").unwrap();
    assert_eq!(source_of(&whole, &copy).as_deref(), Some("x"), "the level plan agrees");
}

/// The same with a stale row: the one recorded for the copy names a head that has since been
/// replaced by another version of the loser.
#[test]
fn a_copy_with_a_stale_row_is_justified_when_asked_for_together_with_its_source() {
    let w = world();
    let (win, lose, newer) = (&w.files[0], &w.files[1], &w.files[2]);
    insert_head(&w.c, "x", "a", 1, win);
    insert_head(&w.c, "x", "b", 2, lose);
    ensure_native_placements_around(&w.c, "g", "x").unwrap();
    let copy = numbered_copy_name("x", lose.version_hash.0, 1);
    // The loser's head is replaced by a newer version of it, and nothing has brought the
    // placements up to date.
    w.c.execute("DELETE FROM native_heads WHERE group_id='g' AND path='x' AND author='b'", [])
        .unwrap();
    insert_head(&w.c, "x", "b", 3, newer);
    let new_copy = numbered_copy_name("x", newer.version_hash.0, 1);

    assert!(
        !names_justify_copy(&w, &[&new_copy], &new_copy, "x"),
        "the copy's name alone records nothing for it"
    );
    assert!(names_justify_copy(&w, &[&new_copy, "x"], &new_copy, "x"));
    let whole = native_plan_level(&w.c, "g", "").unwrap();
    assert_eq!(source_of(&whole, &new_copy).as_deref(), Some("x"));
    assert_eq!(source_of(&whole, &copy), None, "the replaced version's copy is gone");
}

/// `cargo nextest run -p yadorilink-sync-sqlite --lib scoped_plan_against_level_plan
/// --run-ignored only --no-capture`: where asking for many names together stops beating the
/// level plan.
#[test]
#[ignore = "measurement; run explicitly"]
fn scoped_plan_against_level_plan() {
    let (c, _) = big_directory(10_000);
    let level_started = std::time::Instant::now();
    native_plan_level(&c, "g", "big").unwrap();
    let level_wall = level_started.elapsed();
    eprintln!("level plan of 10000 siblings: {level_wall:?}");
    let started = std::time::Instant::now();
    for f in 0..10_000 {
        native_plan_node(&c, "g", &format!("big/file-{f:06}")).unwrap().unwrap();
    }
    eprintln!(
        "planning each of the 10000 entries on its own: {:?} (the level plan each time: about {:?})",
        started.elapsed(),
        level_wall * 10_000
    );
    for k in [1usize, 8, 32, 128, 512, 2048] {
        let names: BTreeSet<String> = (0..k).map(|i| format!("big/file-{:06}", i * 3)).collect();
        let started = std::time::Instant::now();
        native_plan_nodes(&c, "g", "big", &names).unwrap();
        eprintln!("{k} names together: {:?}", started.elapsed());
    }
}
