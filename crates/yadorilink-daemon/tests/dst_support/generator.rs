//! Deterministic, seed-driven `Case` generator: the "grow an ever-widening
//! variety of scenarios from a seed" core of the heat-run framework.
//!
//! Two strategies share one well-formedness engine:
//!   1. `generate_case(seed)` — a pure random walk from a single seed.
//!   2. `generate_pairwise()` — a bounded batch whose factor combinations are
//!      selected by an all-pairs (pairwise) algorithm operating on data, so a
//!      small set of `Case`s hits every (op-kind x fault-kind x topology) pair
//!      without any hand-typed matrix rows.
//!
//! Every `Case` this module emits is *drivable*: op paths come from a fixed
//! pool, content ids always index the `content_table`, and structural rules
//! (no writing under a missing directory, no removing a non-empty directory,
//! no chmod/delete/rename of a file that does not exist) hold by construction.
//! `validate_case` re-simulates the same rules independently and reports any
//! violation, so a generator bug cannot silently ship a malformed `Case`.
//!
//! Reads the shared `Case` IR only; it never mutates that type's shape.

#![cfg(madsim)]
#![allow(dead_code)] // exposed as a library surface; not every scenario drives every helper

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use super::case_ir::{
    Case, ContentTable, DeviceTimeline, DiskFault, Fault, FaultPlan, LinkTopology, NetFault, Op,
    Topology,
};

// ---------------------------------------------------------------------------
// Factor spaces (the categorical axes the pairwise pass covers)
// ---------------------------------------------------------------------------

/// Discriminant of an `Op`, used for coverage accounting and as the "featured
/// op" axis of the pairwise factor space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpKind {
    Write,
    Edit,
    Delete,
    Rename,
    Move,
    Mkdir,
    Rmdir,
    Chmod,
    ConflictingConcurrent,
}

pub const OP_KINDS: [OpKind; 9] = [
    OpKind::Write,
    OpKind::Edit,
    OpKind::Delete,
    OpKind::Rename,
    OpKind::Move,
    OpKind::Mkdir,
    OpKind::Rmdir,
    OpKind::Chmod,
    OpKind::ConflictingConcurrent,
];

impl OpKind {
    pub fn of(op: &Op) -> OpKind {
        match op {
            Op::Write { .. } => OpKind::Write,
            Op::Edit { .. } => OpKind::Edit,
            Op::Delete { .. } => OpKind::Delete,
            Op::Rename { .. } => OpKind::Rename,
            Op::Move { .. } => OpKind::Move,
            Op::Mkdir { .. } => OpKind::Mkdir,
            Op::Rmdir { .. } => OpKind::Rmdir,
            Op::Chmod { .. } => OpKind::Chmod,
            Op::ConflictingConcurrent { .. } => OpKind::ConflictingConcurrent,
        }
    }
}

/// Discriminant of a `Fault` (plus `None` for "this `Case` schedules no
/// fault"), used for coverage accounting and as the fault axis of the
/// pairwise factor space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultKind {
    None,
    Net,
    Disk,
    Crash,
    Restart,
    ClockSkew,
    ClockJump,
}

pub const FAULT_KINDS: [FaultKind; 7] = [
    FaultKind::None,
    FaultKind::Net,
    FaultKind::Disk,
    FaultKind::Crash,
    FaultKind::Restart,
    FaultKind::ClockSkew,
    FaultKind::ClockJump,
];

impl FaultKind {
    pub fn of(fault: &Fault) -> FaultKind {
        match fault {
            Fault::Net(_) => FaultKind::Net,
            Fault::Disk(_) => FaultKind::Disk,
            Fault::Crash { .. } => FaultKind::Crash,
            Fault::Restart { .. } => FaultKind::Restart,
            Fault::ClockSkew { .. } => FaultKind::ClockSkew,
            Fault::ClockJump { .. } => FaultKind::ClockJump,
        }
    }
}

/// Coarse topology axis of the pairwise factor space, mapped to a concrete
/// device count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyKind {
    TwoDevice,
    ThreeDevice,
    FourDevice,
}

pub const TOPOLOGY_KINDS: [TopologyKind; 3] =
    [TopologyKind::TwoDevice, TopologyKind::ThreeDevice, TopologyKind::FourDevice];

impl TopologyKind {
    pub fn device_count(self) -> usize {
        match self {
            TopologyKind::TwoDevice => 2,
            TopologyKind::ThreeDevice => 3,
            TopologyKind::FourDevice => 4,
        }
    }

    pub fn from_device_count(n: usize) -> TopologyKind {
        match n {
            0..=2 => TopologyKind::TwoDevice,
            3 => TopologyKind::ThreeDevice,
            _ => TopologyKind::FourDevice,
        }
    }
}

// ---------------------------------------------------------------------------
// Path pool + filesystem model (the well-formedness engine)
// ---------------------------------------------------------------------------

/// The fixed, closed set of paths any generated `Case` may reference. Keeping
/// the pool small and shared is what makes different devices' timelines
/// actually contend, and keeping it *closed* (renames/moves only ever target
/// another pool path) is what lets `validate_case` check "every op references
/// a pool path" as a hard invariant.
struct PathPool {
    /// Directories that exist from the start of every run.
    initial_dirs: Vec<String>,
    /// Directories that do not exist initially but may be created via `Mkdir`
    /// (and later `Rmdir`'d) — the only well-formed `Mkdir`/`Rmdir` targets.
    creatable_dirs: Vec<String>,
    /// Every file path an op may write/edit/delete/rename/move/chmod.
    files: Vec<String>,
}

impl PathPool {
    fn new() -> PathPool {
        PathPool {
            initial_dirs: vec!["dir_a".into(), "dir_b".into()],
            creatable_dirs: vec!["dir_c".into(), "dir_d".into()],
            files: vec![
                "root0.txt".into(),
                "root1.txt".into(),
                "dir_a/a0.txt".into(),
                "dir_a/a1.txt".into(),
                "dir_b/b0.txt".into(),
                "dir_b/b1.txt".into(),
                "dir_c/c0.txt".into(),
                "dir_d/d0.txt".into(),
            ],
        }
    }

    fn is_file(&self, path: &str) -> bool {
        self.files.iter().any(|f| f == path)
    }

    fn is_dir(&self, path: &str) -> bool {
        self.initial_dirs.iter().any(|d| d == path) || self.creatable_dirs.iter().any(|d| d == path)
    }

    fn known(&self, path: &str) -> bool {
        self.is_file(path) || self.is_dir(path)
    }
}

/// Parent directory of a pool path (`""` denotes the sync root, which always
/// exists).
fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

fn is_under(child: &str, dir: &str) -> bool {
    !dir.is_empty() && child.starts_with(dir) && child.as_bytes().get(dir.len()) == Some(&b'/')
}

/// The in-flight filesystem shape a timeline builds up. Both the generator
/// (to only ever construct valid ops) and `validate_case` (to independently
/// re-check them) drive this exact model, so the two can never disagree about
/// what "well-formed" means.
struct FsModel {
    dirs: BTreeSet<String>,
    files: BTreeSet<String>,
}

impl FsModel {
    fn initial(pool: &PathPool) -> FsModel {
        FsModel { dirs: pool.initial_dirs.iter().cloned().collect(), files: BTreeSet::new() }
    }

    fn dir_exists(&self, dir: &str) -> bool {
        dir.is_empty() || self.dirs.contains(dir)
    }

    fn parent_exists(&self, path: &str) -> bool {
        self.dir_exists(parent_dir(path))
    }

    fn is_dir_empty(&self, dir: &str) -> bool {
        !self.files.iter().any(|f| is_under(f, dir)) && !self.dirs.iter().any(|d| is_under(d, dir))
    }

    /// Applies `op`, returning `Err(reason)` if `op` is not well-formed against
    /// the current shape. The `Err` strings are exactly the violations
    /// `validate_case` surfaces.
    fn apply(&mut self, op: &Op) -> Result<(), String> {
        match op {
            Op::Write { path, .. } => {
                if !self.parent_exists(path) {
                    return Err(format!("write to `{path}` under a missing directory"));
                }
                self.files.insert(path.clone());
            }
            Op::Edit { path, .. } => {
                if !self.files.contains(path) {
                    return Err(format!("edit of missing file `{path}`"));
                }
            }
            Op::Delete { path } => {
                if !self.files.remove(path) {
                    return Err(format!("delete of missing file `{path}`"));
                }
            }
            Op::Rename { from, to } | Op::Move { from, to } => {
                if !self.files.contains(from) {
                    return Err(format!("rename/move of missing file `{from}`"));
                }
                if self.files.contains(to) {
                    return Err(format!("rename/move onto live file `{to}`"));
                }
                if !self.parent_exists(to) {
                    return Err(format!("rename/move to `{to}` under a missing directory"));
                }
                self.files.remove(from);
                self.files.insert(to.clone());
            }
            Op::Mkdir { path } => {
                if self.dirs.contains(path) {
                    return Err(format!("mkdir of existing directory `{path}`"));
                }
                if !self.parent_exists(path) {
                    return Err(format!("mkdir of `{path}` under a missing directory"));
                }
                self.dirs.insert(path.clone());
            }
            Op::Rmdir { path } => {
                if !self.dirs.contains(path) {
                    return Err(format!("rmdir of missing directory `{path}`"));
                }
                if !self.is_dir_empty(path) {
                    return Err(format!("rmdir of non-empty directory `{path}`"));
                }
                self.dirs.remove(path);
            }
            Op::Chmod { path, .. } => {
                if !self.files.contains(path) {
                    return Err(format!("chmod of missing file `{path}`"));
                }
            }
            Op::ConflictingConcurrent { paths } => {
                if paths.is_empty() {
                    return Err("conflicting-concurrent group with no paths".to_string());
                }
                for p in paths {
                    if !self.files.contains(p) {
                        return Err(format!(
                            "conflicting-concurrent group references dead file `{p}`"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Op construction (pure: reads the model, allocates content only on success)
// ---------------------------------------------------------------------------

struct ContentAllocator {
    next: u64,
}

impl ContentAllocator {
    fn new() -> ContentAllocator {
        ContentAllocator { next: 1 }
    }

    fn alloc(&mut self, table: &mut ContentTable, rng: &mut StdRng) -> u64 {
        let id = self.next;
        self.next += 1;
        // Distinct bytes per id so the ContentTable stays a meaningful
        // "did a device actually write this" witness.
        let tag: u32 = rng.random();
        let bytes = format!("content-{id}-{tag:08x}").into_bytes();
        table.insert(id, bytes);
        id
    }
}

fn pick<'a, T>(rng: &mut StdRng, items: &'a [T]) -> Option<&'a T> {
    if items.is_empty() {
        None
    } else {
        Some(&items[rng.random_range(0..items.len())])
    }
}

/// Builds one well-formed `Op` of the requested kind against `model`, or
/// `None` if the kind's preconditions cannot be met right now. Never mutates
/// `model`; the caller applies the returned op.
fn construct(
    kind: OpKind,
    model: &FsModel,
    pool: &PathPool,
    rng: &mut StdRng,
    table: &mut ContentTable,
    alloc: &mut ContentAllocator,
) -> Option<Op> {
    let live: Vec<String> = model.files.iter().cloned().collect();
    match kind {
        OpKind::Write => {
            let writable: Vec<String> =
                pool.files.iter().filter(|f| model.parent_exists(f)).cloned().collect();
            let path = pick(rng, &writable)?.clone();
            Some(Op::Write { path, content_id: alloc.alloc(table, rng) })
        }
        OpKind::Edit => {
            let path = pick(rng, &live)?.clone();
            Some(Op::Edit { path, content_id: alloc.alloc(table, rng) })
        }
        OpKind::Delete => {
            let path = pick(rng, &live)?.clone();
            Some(Op::Delete { path })
        }
        OpKind::Rename | OpKind::Move => {
            let from = pick(rng, &live)?.clone();
            let cross_dir = matches!(kind, OpKind::Move);
            let targets: Vec<String> = pool
                .files
                .iter()
                .filter(|t| {
                    !model.files.contains(*t)
                        && model.parent_exists(t)
                        && (!cross_dir || parent_dir(t) != parent_dir(&from))
                })
                .cloned()
                .collect();
            let to = pick(rng, &targets)?.clone();
            if cross_dir {
                Some(Op::Move { from, to })
            } else {
                Some(Op::Rename { from, to })
            }
        }
        OpKind::Mkdir => {
            let makeable: Vec<String> = pool
                .creatable_dirs
                .iter()
                .filter(|d| !model.dirs.contains(*d) && model.parent_exists(d))
                .cloned()
                .collect();
            let path = pick(rng, &makeable)?.clone();
            Some(Op::Mkdir { path })
        }
        OpKind::Rmdir => {
            let removable: Vec<String> =
                model.dirs.iter().filter(|d| model.is_dir_empty(d)).cloned().collect();
            let path = pick(rng, &removable)?.clone();
            Some(Op::Rmdir { path })
        }
        OpKind::Chmod => {
            let path = pick(rng, &live)?.clone();
            Some(Op::Chmod { path, exec_bit: rng.random_bool(0.5) })
        }
        OpKind::ConflictingConcurrent => {
            if live.len() < 2 {
                return None;
            }
            let mut paths = live;
            // Shuffle-lite: rotate by a seeded offset, then take 2..=3.
            let off = rng.random_range(0..paths.len());
            paths.rotate_left(off);
            let take = rng.random_range(2..=paths.len().min(3));
            paths.truncate(take);
            Some(Op::ConflictingConcurrent { paths })
        }
    }
}

/// Constructs *some* valid op, preferring the requested kind but always
/// falling back to a kind whose preconditions currently hold (`Write` to a
/// root file always qualifies), so a build step never stalls.
fn construct_any(
    desired: Option<OpKind>,
    model: &FsModel,
    pool: &PathPool,
    rng: &mut StdRng,
    table: &mut ContentTable,
    alloc: &mut ContentAllocator,
) -> Option<Op> {
    if let Some(kind) = desired {
        if let Some(op) = construct(kind, model, pool, rng, table, alloc) {
            return Some(op);
        }
    }
    // Random valid kind: try kinds in a seeded order, take the first that fits.
    let mut order = OP_KINDS;
    let start = rng.random_range(0..order.len());
    order.rotate_left(start);
    for kind in order {
        if let Some(op) = construct(kind, model, pool, rng, table, alloc) {
            return Some(op);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Timeline builder
// ---------------------------------------------------------------------------

struct Builder {
    pool: PathPool,
    model: FsModel,
    table: ContentTable,
    alloc: ContentAllocator,
    timelines: Vec<Vec<(u64, Op)>>,
}

impl Builder {
    fn new(device_count: usize) -> Builder {
        let pool = PathPool::new();
        let model = FsModel::initial(&pool);
        Builder {
            pool,
            model,
            table: ContentTable::default(),
            alloc: ContentAllocator::new(),
            timelines: vec![Vec::new(); device_count],
        }
    }

    /// Emits at most one op for device `dev` at round `ts`, applying it to the
    /// shared model. Ops are produced in global `(ts, device)` order — the very
    /// order `validate_case` replays — so the model the generator sees and the
    /// model the validator reconstructs are always identical.
    fn step(&mut self, ts: u64, dev: usize, desired: Option<OpKind>, rng: &mut StdRng) {
        if let Some(op) =
            construct_any(desired, &self.model, &self.pool, rng, &mut self.table, &mut self.alloc)
        {
            self.model
                .apply(&op)
                .expect("generator only constructs ops valid against the current model");
            self.timelines[dev].push((ts, op));
        }
    }

    fn into_workload(self) -> (Vec<DeviceTimeline>, ContentTable) {
        let workload = self
            .timelines
            .into_iter()
            .enumerate()
            .map(|(device_index, ops)| DeviceTimeline { device_index, ops })
            .collect();
        (workload, self.table)
    }
}

// ---------------------------------------------------------------------------
// Topology + fault construction
// ---------------------------------------------------------------------------

fn build_topology(kind: TopologyKind, rng: &mut StdRng) -> Topology {
    let device_count = kind.device_count();
    let links = (0..device_count)
        .map(|_| LinkTopology {
            group_id: "heat-run-group".to_string(),
            // First device always online so there is a stable anchor; the rest
            // vary so partition/heal faults have something to act against.
            initial_online: rng.random_bool(0.8),
        })
        .collect();
    Topology { device_count, links }
}

fn build_fault(kind: FaultKind, device_count: usize, rng: &mut StdRng) -> Option<Fault> {
    let two_distinct = |rng: &mut StdRng| -> (usize, usize) {
        let a = rng.random_range(0..device_count);
        let mut b = rng.random_range(0..device_count);
        if b == a {
            b = (b + 1) % device_count;
        }
        (a, b)
    };
    let dev = |rng: &mut StdRng| rng.random_range(0..device_count);
    Some(match kind {
        FaultKind::None => return None,
        FaultKind::Net => {
            let net = match rng.random_range(0..6) {
                0 => NetFault::Drop,
                1 => NetFault::Delay { millis: rng.random_range(1..500) },
                2 => NetFault::Reorder,
                3 => NetFault::Duplicate,
                4 => {
                    let (a, b) = two_distinct(rng);
                    NetFault::Partition { device_a: a, device_b: b }
                }
                _ => {
                    let (a, b) = two_distinct(rng);
                    NetFault::Heal { device_a: a, device_b: b }
                }
            };
            Fault::Net(net)
        }
        FaultKind::Disk => {
            let disk = match rng.random_range(0..7) {
                0 => DiskFault::Enospc,
                1 => DiskFault::Eio,
                2 => DiskFault::TornWrite,
                3 => DiskFault::FsyncFail,
                4 => DiskFault::SlowIo { millis: rng.random_range(1..500) },
                5 => DiskFault::SqliteBusy,
                _ => DiskFault::SqliteLocked,
            };
            Fault::Disk(disk)
        }
        FaultKind::Crash => Fault::Crash { device: dev(rng) },
        FaultKind::Restart => Fault::Restart { device: dev(rng) },
        FaultKind::ClockSkew => Fault::ClockSkew {
            device: dev(rng),
            delta_nanos: rng.random_range(-1_000_000_000..1_000_000_000),
        },
        FaultKind::ClockJump => Fault::ClockJump {
            device: dev(rng),
            to_unix_nanos: rng.random_range(0..2_000_000_000_000),
        },
    })
}

// ---------------------------------------------------------------------------
// Strategy 1: pure random from a seed
// ---------------------------------------------------------------------------

/// Deterministically produces a well-formed `Case` from `seed`. The same seed
/// always yields the same `Case`.
pub fn generate_case(seed: u64) -> Case {
    let mut rng = StdRng::seed_from_u64(seed);

    let topo_kind = TOPOLOGY_KINDS[rng.random_range(0..TOPOLOGY_KINDS.len())];
    let device_count = topo_kind.device_count();
    let topology = build_topology(topo_kind, &mut rng);

    let mut builder = Builder::new(device_count);
    let rounds = rng.random_range(6..14);
    for ts in 0..rounds {
        for dev in 0..device_count {
            if rng.random_bool(0.75) {
                builder.step(ts, dev, None, &mut rng);
            }
        }
    }
    let (workload, content_table) = builder.into_workload();

    let mut fault_schedule = Vec::new();
    let n_faults = rng.random_range(0..3);
    for _ in 0..n_faults {
        // Random pass emphasizes the transport/disk injectors the heat run
        // actually wires; the full fault vocabulary is exercised by the
        // pairwise pass.
        let kind = if rng.random_bool(0.5) { FaultKind::Net } else { FaultKind::Disk };
        if let Some(fault) = build_fault(kind, device_count, &mut rng) {
            fault_schedule.push((rng.random_range(0..rounds), fault));
        }
    }
    fault_schedule.sort_by_key(|(ts, _)| *ts);

    Case {
        seed,
        topology,
        workload,
        fault_schedule,
        content_table,
        fault_plan: FaultPlan::default(),
    }
}

// ---------------------------------------------------------------------------
// Strategy 2: pairwise / all-pairs pass
// ---------------------------------------------------------------------------

/// Greedy all-pairs (pairwise) covering array over factors of the given
/// cardinalities. Returns a set of rows (each row picks one value index per
/// factor) such that for every pair of factors, every combination of their
/// values appears in at least one row. Pure and deterministic — this is the
/// "matrix as data, not hand-typed rows" core.
fn all_pairs(cardinalities: &[usize]) -> Vec<Vec<usize>> {
    let n = cardinalities.len();
    // Every (factor_i, value)-(factor_j, value) pair still to be covered.
    let mut uncovered: BTreeSet<((usize, usize), (usize, usize))> = BTreeSet::new();
    for fi in 0..n {
        for fj in (fi + 1)..n {
            for vi in 0..cardinalities[fi] {
                for vj in 0..cardinalities[fj] {
                    uncovered.insert(((fi, vi), (fj, vj)));
                }
            }
        }
    }

    let mut rows: Vec<Vec<usize>> = Vec::new();
    const UNSET: usize = usize::MAX;
    while let Some(&((fi, vi), (fj, vj))) = uncovered.iter().next() {
        let mut row = vec![UNSET; n];
        row[fi] = vi;
        row[fj] = vj;
        // Fill remaining factors greedily: for each, choose the value that
        // newly covers the most still-uncovered pairs against already-set
        // factors.
        for f in 0..n {
            if row[f] != UNSET {
                continue;
            }
            let mut best_v = 0usize;
            let mut best_gain: i64 = -1;
            for v in 0..cardinalities[f] {
                let mut gain: i64 = 0;
                for (g, &gv) in row.iter().enumerate() {
                    if g == f || gv == UNSET {
                        continue;
                    }
                    let key = if g < f { ((g, gv), (f, v)) } else { ((f, v), (g, gv)) };
                    if uncovered.contains(&key) {
                        gain += 1;
                    }
                }
                if gain > best_gain {
                    best_gain = gain;
                    best_v = v;
                }
            }
            row[f] = best_v;
        }
        // Mark every pair this row now covers.
        for a in 0..n {
            for b in (a + 1)..n {
                uncovered.remove(&((a, row[a]), (b, row[b])));
            }
        }
        rows.push(row);
    }
    rows
}

/// Base seed for the pairwise batch; each row gets a distinct derived seed so
/// two rows featuring the same op/fault still differ, yet the whole batch is
/// reproducible.
const PAIRWISE_SEED_BASE: u64 = 0xF00D_CAFE_D00D_BEEF;

/// Prelude that establishes files (and keeps the creatable dirs free) so any
/// featured op has valid targets: writes one file at the root and one under
/// each initial directory, across the first rounds of device 0.
fn emit_prelude(builder: &mut Builder, rng: &mut StdRng, next_ts: &mut u64) {
    for path in ["root0.txt", "dir_a/a0.txt", "dir_b/b0.txt"] {
        let op = Op::Write {
            path: path.to_string(),
            content_id: builder.alloc.alloc(&mut builder.table, rng),
        };
        builder.model.apply(&op).expect("prelude writes target existing dirs");
        builder.timelines[0].push((*next_ts, op));
        *next_ts += 1;
    }
}

/// The device-0 op-kind plan (beyond the prelude) that guarantees the featured
/// op appears well-formed. `Rmdir` needs an empty dir created first; the rest
/// are satisfiable directly against the prelude's files.
fn featured_plan(op: OpKind) -> Vec<OpKind> {
    match op {
        OpKind::Rmdir => vec![OpKind::Mkdir, OpKind::Rmdir],
        other => vec![other],
    }
}

/// Builds one focused `Case` that is guaranteed to exhibit `op`, schedule a
/// `fault`-kind fault (unless `None`), and use the `topo` device count.
fn generate_focused_case(seed: u64, op: OpKind, fault: FaultKind, topo: TopologyKind) -> Case {
    let mut rng = StdRng::seed_from_u64(seed);
    let device_count = topo.device_count();
    let topology = build_topology(topo, &mut rng);

    let mut builder = Builder::new(device_count);
    let mut ts: u64 = 0;

    emit_prelude(&mut builder, &mut rng, &mut ts);

    // Device 0 realizes the featured op (with any prerequisite steps).
    for kind in featured_plan(op) {
        builder.step(ts, 0, Some(kind), &mut rng);
        ts += 1;
    }

    // Sprinkle a few random valid ops across all devices for variety and to
    // give multi-device topologies real contention.
    let extra_rounds = rng.random_range(2..5);
    for r in 0..extra_rounds {
        for dev in 0..device_count {
            if dev == 0 && r == 0 {
                continue; // device 0 just finished its featured tail
            }
            if rng.random_bool(0.7) {
                builder.step(ts + r as u64, dev, None, &mut rng);
            }
        }
    }

    let (workload, content_table) = builder.into_workload();

    let mut fault_schedule = Vec::new();
    if let Some(f) = build_fault(fault, device_count, &mut rng) {
        let at = rng.random_range(0..(ts + extra_rounds as u64).max(1));
        fault_schedule.push((at, f));
    }

    Case {
        seed,
        topology,
        workload,
        fault_schedule,
        content_table,
        fault_plan: FaultPlan::default(),
    }
}

/// Produces a bounded batch of `Case`s whose factor combinations, selected by
/// `all_pairs`, cover every (op-kind x fault-kind), (op-kind x topology), and
/// (fault-kind x topology) pair. Deterministic.
pub fn generate_pairwise() -> Vec<Case> {
    let cardinalities = [OP_KINDS.len(), FAULT_KINDS.len(), TOPOLOGY_KINDS.len()];
    let rows = all_pairs(&cardinalities);
    rows.iter()
        .enumerate()
        .map(|(i, row)| {
            let op = OP_KINDS[row[0]];
            let fault = FAULT_KINDS[row[1]];
            let topo = TOPOLOGY_KINDS[row[2]];
            let seed =
                PAIRWISE_SEED_BASE ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            generate_focused_case(seed, op, fault, topo)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Well-formedness validation (independent re-check)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Violation {
    pub at: String,
    pub detail: String,
}

fn op_paths(op: &Op) -> Vec<&str> {
    match op {
        Op::Write { path, .. }
        | Op::Edit { path, .. }
        | Op::Delete { path }
        | Op::Mkdir { path }
        | Op::Rmdir { path }
        | Op::Chmod { path, .. } => vec![path.as_str()],
        Op::Rename { from, to } | Op::Move { from, to } => vec![from.as_str(), to.as_str()],
        Op::ConflictingConcurrent { paths } => paths.iter().map(|p| p.as_str()).collect(),
    }
}

/// Re-simulates a `Case` against the same rules the generator built it under,
/// returning one `Violation` per problem. An empty result means the `Case` is
/// well-formed: every op references a pool path, every content id indexes the
/// content table, and every structural rule (no write under a missing dir, no
/// rmdir of a non-empty dir, no chmod/delete/rename of a missing file, ...)
/// holds. Independent of the generator, so it genuinely cross-checks it.
pub fn validate_case(case: &Case) -> Vec<Violation> {
    let pool = PathPool::new();
    let mut model = FsModel::initial(&pool);
    let mut violations = Vec::new();

    // Global (ts, device) replay order — identical to construction order.
    let mut ordered: Vec<(u64, usize, &Op)> = Vec::new();
    for tl in &case.workload {
        for (ts, op) in &tl.ops {
            ordered.push((*ts, tl.device_index, op));
        }
    }
    ordered.sort_by_key(|(ts, dev, _)| (*ts, *dev));

    for (ts, dev, op) in ordered {
        let at = format!("ts={ts} dev={dev} {}", debug_kind(op));

        for p in op_paths(op) {
            if !pool.known(p) {
                violations.push(Violation {
                    at: at.clone(),
                    detail: format!("references path `{p}` outside the pool"),
                });
            }
        }
        // Directory ops must name a directory; file ops must name a file.
        match op {
            Op::Mkdir { path } | Op::Rmdir { path } => {
                if !pool.is_dir(path) {
                    violations.push(Violation {
                        at: at.clone(),
                        detail: format!("directory op on non-directory path `{path}`"),
                    });
                }
            }
            _ => {
                for p in op_paths(op) {
                    if !pool.is_file(p) {
                        violations.push(Violation {
                            at: at.clone(),
                            detail: format!("file op on non-file path `{p}`"),
                        });
                    }
                }
            }
        }
        if let Op::Write { content_id, .. } | Op::Edit { content_id, .. } = op {
            if case.content_table.get(*content_id).is_none() {
                violations.push(Violation {
                    at: at.clone(),
                    detail: format!("content_id {content_id} not in content_table"),
                });
            }
        }
        if let Err(reason) = model.apply(op) {
            violations.push(Violation { at, detail: reason });
        }
    }

    // Faults must reference in-range devices.
    for (ts, fault) in &case.fault_schedule {
        for dev in fault_devices(fault) {
            if dev >= case.topology.device_count {
                violations.push(Violation {
                    at: format!("fault@ts={ts}"),
                    detail: format!(
                        "references device {dev} >= device_count {}",
                        case.topology.device_count
                    ),
                });
            }
        }
    }

    violations
}

fn fault_devices(fault: &Fault) -> Vec<usize> {
    match fault {
        Fault::Net(NetFault::Partition { device_a, device_b })
        | Fault::Net(NetFault::Heal { device_a, device_b }) => vec![*device_a, *device_b],
        Fault::Net(_) | Fault::Disk(_) => vec![],
        Fault::Crash { device }
        | Fault::Restart { device }
        | Fault::ClockSkew { device, .. }
        | Fault::ClockJump { device, .. } => vec![*device],
    }
}

fn debug_kind(op: &Op) -> String {
    format!("{:?}", OpKind::of(op))
}

// ---------------------------------------------------------------------------
// Coverage accounting + reporting
// ---------------------------------------------------------------------------

/// Accounting-only accumulator: records which op-kinds, fault-kinds,
/// topologies, and cross-factor pairs a batch of generated `Case`s actually
/// exhibited, so a batch can *report* its coverage (and a test can assert the
/// pairwise pass reaches every pair).
#[derive(Default)]
pub struct CoverageAccumulator {
    op_kinds: BTreeSet<OpKind>,
    fault_kinds: BTreeSet<FaultKind>,
    topologies: BTreeSet<TopologyKind>,
    op_fault: BTreeSet<(OpKind, FaultKind)>,
    op_topo: BTreeSet<(OpKind, TopologyKind)>,
    fault_topo: BTreeSet<(FaultKind, TopologyKind)>,
}

impl CoverageAccumulator {
    pub fn new() -> CoverageAccumulator {
        CoverageAccumulator::default()
    }

    pub fn record_case(&mut self, case: &Case) {
        let ops: BTreeSet<OpKind> = case
            .workload
            .iter()
            .flat_map(|tl| tl.ops.iter().map(|(_, op)| OpKind::of(op)))
            .collect();
        let faults: BTreeSet<FaultKind> = if case.fault_schedule.is_empty() {
            [FaultKind::None].into_iter().collect()
        } else {
            case.fault_schedule.iter().map(|(_, f)| FaultKind::of(f)).collect()
        };
        let topo = TopologyKind::from_device_count(case.topology.device_count);

        self.topologies.insert(topo);
        for &o in &ops {
            self.op_kinds.insert(o);
            self.op_topo.insert((o, topo));
            for &f in &faults {
                self.op_fault.insert((o, f));
            }
        }
        for &f in &faults {
            self.fault_kinds.insert(f);
            self.fault_topo.insert((f, topo));
        }
    }

    pub fn record_batch(&mut self, cases: &[Case]) {
        for c in cases {
            self.record_case(c);
        }
    }

    fn missing_op_fault(&self) -> Vec<(OpKind, FaultKind)> {
        let mut missing = Vec::new();
        for &o in &OP_KINDS {
            for &f in &FAULT_KINDS {
                if !self.op_fault.contains(&(o, f)) {
                    missing.push((o, f));
                }
            }
        }
        missing
    }

    fn missing_op_topo(&self) -> Vec<(OpKind, TopologyKind)> {
        let mut missing = Vec::new();
        for &o in &OP_KINDS {
            for &t in &TOPOLOGY_KINDS {
                if !self.op_topo.contains(&(o, t)) {
                    missing.push((o, t));
                }
            }
        }
        missing
    }

    fn missing_fault_topo(&self) -> Vec<(FaultKind, TopologyKind)> {
        let mut missing = Vec::new();
        for &f in &FAULT_KINDS {
            for &t in &TOPOLOGY_KINDS {
                if !self.fault_topo.contains(&(f, t)) {
                    missing.push((f, t));
                }
            }
        }
        missing
    }

    /// True once every op-kind x fault-kind, op-kind x topology, and
    /// fault-kind x topology pair has been observed.
    pub fn is_full_pairwise(&self) -> bool {
        self.missing_op_fault().is_empty()
            && self.missing_op_topo().is_empty()
            && self.missing_fault_topo().is_empty()
    }

    pub fn report(&self) -> String {
        format!(
            "coverage: op_kinds {}/{}, fault_kinds {}/{}, topologies {}/{}; \
             pairs op×fault {}/{}, op×topo {}/{}, fault×topo {}/{}; full_pairwise={}",
            self.op_kinds.len(),
            OP_KINDS.len(),
            self.fault_kinds.len(),
            FAULT_KINDS.len(),
            self.topologies.len(),
            TOPOLOGY_KINDS.len(),
            self.op_fault.len(),
            OP_KINDS.len() * FAULT_KINDS.len(),
            self.op_topo.len(),
            OP_KINDS.len() * TOPOLOGY_KINDS.len(),
            self.fault_topo.len(),
            FAULT_KINDS.len() * TOPOLOGY_KINDS.len(),
            self.is_full_pairwise(),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical string independent of `ContentTable`'s `HashMap` iteration
    /// order (which is per-map randomized), so two logically identical `Case`s
    /// compare equal.
    fn fingerprint(case: &Case) -> String {
        let content: BTreeMap<u64, Vec<u8>> =
            case.content_table.iter().map(|(id, bytes)| (*id, bytes.clone())).collect();
        format!(
            "seed={}|topo={:?}|workload={:?}|faults={:?}|content={:?}",
            case.seed, case.topology, case.workload, case.fault_schedule, content
        )
    }

    #[test]
    fn generator_is_deterministic_for_a_fixed_seed() {
        for seed in [0u64, 1, 42, 7777, u64::MAX] {
            let a = generate_case(seed);
            let b = generate_case(seed);
            assert_eq!(fingerprint(&a), fingerprint(&b), "seed {seed} not deterministic");
        }
    }

    #[test]
    fn different_seeds_generally_produce_different_cases() {
        let a = generate_case(1);
        let b = generate_case(2);
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn every_random_case_is_well_formed() {
        for seed in 0..300u64 {
            let case = generate_case(seed);
            let violations = validate_case(&case);
            assert!(violations.is_empty(), "seed {seed} produced a malformed case: {violations:?}");
        }
    }

    #[test]
    fn pairwise_batch_is_deterministic() {
        let a = generate_pairwise();
        let b = generate_pairwise();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(fingerprint(x), fingerprint(y));
        }
    }

    #[test]
    fn every_pairwise_case_is_well_formed() {
        for (i, case) in generate_pairwise().iter().enumerate() {
            let violations = validate_case(case);
            assert!(violations.is_empty(), "pairwise case {i} malformed: {violations:?}");
        }
    }

    #[test]
    fn pairwise_batch_reaches_full_pairwise_coverage() {
        let batch = generate_pairwise();
        let mut cov = CoverageAccumulator::new();
        cov.record_batch(&batch);
        assert!(
            cov.is_full_pairwise(),
            "{} cases did not cover all pairs: {}\n  missing op×fault: {:?}\n  missing op×topo: {:?}\n  missing fault×topo: {:?}",
            batch.len(),
            cov.report(),
            cov.missing_op_fault(),
            cov.missing_op_topo(),
            cov.missing_fault_topo(),
        );
        // A pairwise covering array is strictly smaller than the full
        // cartesian product; if it were not, the "pairwise selection" would be
        // buying nothing.
        let full_cartesian = OP_KINDS.len() * FAULT_KINDS.len() * TOPOLOGY_KINDS.len();
        assert!(batch.len() < full_cartesian, "batch not smaller than cartesian product");
    }

    #[test]
    fn all_pairs_covering_array_actually_covers_all_pairs() {
        let card = [OP_KINDS.len(), FAULT_KINDS.len(), TOPOLOGY_KINDS.len()];
        let rows = all_pairs(&card);
        for fi in 0..card.len() {
            for fj in (fi + 1)..card.len() {
                for vi in 0..card[fi] {
                    for vj in 0..card[fj] {
                        assert!(
                            rows.iter().any(|r| r[fi] == vi && r[fj] == vj),
                            "pair (f{fi}={vi}, f{fj}={vj}) uncovered",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn generated_case_round_trips_through_json() {
        for seed in [3u64, 99, 12345] {
            let case = generate_case(seed);
            let json = serde_json::to_string(&case).unwrap();
            let restored: Case = serde_json::from_str(&json).unwrap();
            assert_eq!(fingerprint(&case), fingerprint(&restored), "seed {seed} json mismatch");
            assert!(validate_case(&restored).is_empty());
        }
    }

    #[test]
    fn coverage_report_is_human_readable() {
        let mut cov = CoverageAccumulator::new();
        cov.record_batch(&generate_pairwise());
        let report = cov.report();
        assert!(report.contains("full_pairwise=true"), "{report}");
    }
}
