//! Complexity benchmarks of the pure kernel rules: `step`, `join` and
//! `verify_strict`, over a small concrete protocol (changes are indices
//! into an arena, paths are strings, authors are integers).
//!
//! Run one case per process:
//!
//! ```text
//! cargo bench -p yadorilink-dcf-kernel --bench kernel_bench -- \
//!     --case step_state --value 10000 [--variant full] [--repeats 50] [--out k.csv]
//! ```
//!
//! Cases (the swept parameter is `--value`):
//!
//! * `step_state`: `step` on a state of `value` paths, one head each.
//!   Variant `partial` builds the state of the touched path only, as
//!   admission does; variant `full` steps the whole state, which clones it.
//! * `step_basis`: `step` (variant `step`) or `verify_strict` (variant
//!   `verify`) of a change whose basis is `value` concurrent heads.
//! * `join_width`: `join` of two states whose one path holds `value`
//!   heads each (half shared), and (variant `sealable`) the per-path
//!   count of authors holding two heads, the seal-time bound.
//! * `join_paths`: `join` of two states of `value` paths that differ at one.

use std::collections::BTreeMap;

use yadorilink_dcf_kernel::{join, step, verify_strict, KernelOp, Protocol, State};

mod support;
use support::{heap_mark, live_since, measure, peak_rss_bytes, Args, Row};

#[global_allocator]
static ALLOC: support::CountingAlloc = support::CountingAlloc;

type Change = u32;
type Author = u32;
type KState = State<String, Change, Author>;

#[derive(Clone)]
struct ChangeData {
    author: Author,
    seq: u64,
    ops: Vec<KernelOp<String, Change>>,
}

#[derive(Default)]
struct Arena {
    changes: Vec<ChangeData>,
}

impl Arena {
    fn push(&mut self, author: Author, seq: u64, ops: Vec<KernelOp<String, Change>>) -> Change {
        self.changes.push(ChangeData { author, seq, ops });
        u32::try_from(self.changes.len() - 1).expect("arena index fits u32")
    }
}

impl Protocol for Arena {
    type Change = Change;
    type Path = String;
    type Author = Author;

    fn author(&self, change: &Change) -> Author {
        self.changes[*change as usize].author
    }

    fn seq(&self, change: &Change) -> u64 {
        self.changes[*change as usize].seq
    }

    fn ops(&self, change: &Change) -> Vec<KernelOp<String, Change>> {
        self.changes[*change as usize].ops.clone()
    }
}

const AUTHORS: u32 = 16;
const TARGET: &str = "target/file";

fn path_name(i: u64) -> String {
    format!("d{:04}/f{i:07}", i / 1000)
}

fn put(path: &str, basis: Vec<Change>) -> KernelOp<String, Change> {
    KernelOp { path: path.to_owned(), lands: true, basis }
}

/// A state of `paths` paths with one head each, written round-robin by
/// `AUTHORS` authors, plus `TARGET` with one head.
fn wide_state(arena: &mut Arena, paths: u64) -> KState {
    let mut state = KState::empty();
    let mut seqs = vec![0u64; AUTHORS as usize];
    for i in 0..paths {
        let author = (i % u64::from(AUTHORS)) as u32;
        seqs[author as usize] += 1;
        let path = path_name(i);
        let c = arena.push(author, seqs[author as usize], vec![put(&path, Vec::new())]);
        state.heads.insert(path, vec![c]);
    }
    seqs[0] += 1;
    let target = arena.push(0, seqs[0], vec![put(TARGET, Vec::new())]);
    state.heads.insert(TARGET.to_owned(), vec![target]);
    for (author, seq) in seqs.iter().enumerate() {
        state.watermarks.insert(author as u32, *seq);
    }
    state
}

fn step_state(args: &Args, value: u64, repeats: usize) -> Row {
    let variant = args.str_or("variant", "partial");
    let mark = heap_mark();
    let mut arena = Arena::default();
    let state = wide_state(&mut arena, value);
    let state_bytes = live_since(mark);
    let target_head = state.heads_at(&TARGET.to_owned())[0];
    let seq = state.watermark(&1) + 1;
    let change = arena.push(1, seq, vec![put(TARGET, vec![target_head])]);
    let rss_setup = peak_rss_bytes();
    let m = match variant.as_str() {
        "full" => measure(repeats, || (), |()| step(&arena, &state, &change), drop),
        _ => measure(
            repeats,
            || (),
            |()| {
                let mut partial = KState::empty();
                partial.watermarks.insert(1, seq - 1);
                for op in arena.ops(&change) {
                    partial.heads.insert(op.path.clone(), state.heads_at(&op.path).to_vec());
                }
                step(&arena, &partial, &change)
            },
            drop,
        ),
    };
    let mut row = Row::new("kernel", "step_state", &variant, "dcf", "state_paths", value);
    row.measurement = m;
    row.peak_rss_setup_bytes = rss_setup;
    row.state_bytes = Some(state_bytes);
    row
}

/// A path holding `n` heads, one each by authors `first..first + n`, at
/// sequence 1.
fn concurrent_heads(arena: &mut Arena, first: u32, n: u64) -> Vec<Change> {
    (0..n as u32).map(|j| arena.push(first + j, 1, vec![put(TARGET, Vec::new())])).collect()
}

fn step_basis(args: &Args, value: u64, repeats: usize) -> Row {
    let variant = args.str_or("variant", "step");
    let mut arena = Arena::default();
    let heads = concurrent_heads(&mut arena, 1, value);
    let mut state = KState::empty();
    for j in 0..value as u32 {
        state.watermarks.insert(1 + j, 1);
    }
    state.heads.insert(TARGET.to_owned(), heads.clone());
    let change = arena.push(0, 1, vec![put(TARGET, heads)]);
    let rss_setup = peak_rss_bytes();
    let m = match variant.as_str() {
        "verify" => measure(
            repeats,
            || (),
            |()| verify_strict(&arena, &state, &change).expect("the basis is current heads"),
            drop,
        ),
        _ => measure(repeats, || (), |()| step(&arena, &state, &change), drop),
    };
    let mut row = Row::new("kernel", "step_basis", &variant, "dcf", "basis_size", value);
    row.measurement = m;
    row.peak_rss_setup_bytes = rss_setup;
    row
}

/// The seal-time bound on a state: how many `(path, author)` pairs hold
/// more than one head. The kernel has no such function; the seal reads it
/// from the namespace root's aggregate.
fn duplicate_author_count(arena: &Arena, state: &KState) -> usize {
    let mut count = 0;
    for heads in state.heads.values() {
        let mut per_author: BTreeMap<Author, usize> = BTreeMap::new();
        for head in heads {
            *per_author.entry(arena.author(head)).or_default() += 1;
        }
        count += per_author.values().filter(|n| **n > 1).count();
    }
    count
}

fn join_width(args: &Args, value: u64, repeats: usize) -> Row {
    let variant = args.str_or("variant", "join");
    let mut arena = Arena::default();
    let shared = value / 2;
    let left_heads = concurrent_heads(&mut arena, 0, value);
    let right_only = concurrent_heads(&mut arena, value as u32, value - shared);
    let mut left = KState::empty();
    let mut right = KState::empty();
    for head in &left_heads {
        left.watermarks.insert(arena.author(head), 1);
    }
    for head in left_heads.iter().take(shared as usize).chain(&right_only) {
        right.watermarks.insert(arena.author(head), 1);
    }
    left.heads.insert(TARGET.to_owned(), left_heads.clone());
    let mut right_heads: Vec<Change> = left_heads[..shared as usize].to_vec();
    right_heads.extend(&right_only);
    right.heads.insert(TARGET.to_owned(), right_heads);
    let joined = join(&arena, &left, &right);
    let rss_setup = peak_rss_bytes();
    let m = match variant.as_str() {
        "sealable" => measure(repeats, || (), |()| duplicate_author_count(&arena, &joined), drop),
        _ => measure(repeats, || (), |()| join(&arena, &left, &right), drop),
    };
    let mut row = Row::new("kernel", "join_width", &variant, "dcf", "heads_per_path", value);
    row.measurement = m;
    row.peak_rss_setup_bytes = rss_setup;
    row.extra("joined_heads", joined.heads_at(&TARGET.to_owned()).len())
}

fn join_paths(value: u64, repeats: usize) -> Row {
    let mut arena = Arena::default();
    let mark = heap_mark();
    let left = wide_state(&mut arena, value);
    let state_bytes = live_since(mark);
    let mut right = left.clone();
    let head = left.heads_at(&TARGET.to_owned())[0];
    let seq = right.watermark(&1) + 1;
    let change = arena.push(1, seq, vec![put(TARGET, vec![head])]);
    right = step(&arena, &right, &change);
    let rss_setup = peak_rss_bytes();
    let m = measure(repeats, || (), |()| join(&arena, &left, &right), drop);
    let mut row = Row::new("kernel", "join_paths", "join", "dcf", "state_paths", value);
    row.measurement = m;
    row.peak_rss_setup_bytes = rss_setup;
    row.state_bytes = Some(state_bytes);
    row
}

fn main() {
    let args = Args::parse();
    let case = args.str_or("case", "step_state");
    let value = args.u64_or("value", 100);
    let repeats = usize::try_from(args.u64_or("repeats", 30)).unwrap_or(30);
    let row = match case.as_str() {
        "step_state" => step_state(&args, value, repeats),
        "step_basis" => step_basis(&args, value, repeats),
        "join_width" => join_width(&args, value, repeats),
        "join_paths" => join_paths(value, repeats),
        other => panic!("unknown case {other:?}"),
    };
    row.emit(args.out().as_ref());
}
