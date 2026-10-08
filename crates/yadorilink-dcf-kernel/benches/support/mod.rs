//! Measurement support shared by the DCF benchmark binaries.
//!
//! A benchmark case runs in its own process so that its peak resident set
//! size is attributable to it. This module provides what every case
//! records: wall time over at least 15 samples (median, p95, min; an
//! operation under a millisecond is batched so that each sample is the mean
//! of runs summing to one) plus the first run on its own, allocation count and
//! bytes through a counting global allocator, the peak live heap during the
//! measured operation, peak RSS, and one CSV row per case.
//!
//! The binary that includes this module installs the allocator:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: support::CountingAlloc = support::CountingAlloc;
//! ```

#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

// --- Counting allocator ------------------------------------------------------

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK_LIVE: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting every allocation and tracking the live
/// and peak live heap.
pub struct CountingAlloc;

fn grew(size: usize) {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    ALLOC_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK_LIVE.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the caller's arguments
// unchanged; the counters are side effects only.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = System.realloc(ptr, layout, new_size);
        if !new.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            grew(new_size);
        }
        new
    }
}

/// The allocation counters at one instant.
#[derive(Clone, Copy, Debug)]
pub struct HeapMark {
    pub allocs: u64,
    pub bytes: u64,
    pub live: usize,
}

pub fn heap_mark() -> HeapMark {
    HeapMark {
        allocs: ALLOCS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        live: LIVE.load(Ordering::Relaxed),
    }
}

/// Live heap bytes allocated since `mark` and still held.
pub fn live_since(mark: HeapMark) -> u64 {
    LIVE.load(Ordering::Relaxed).saturating_sub(mark.live) as u64
}

fn reset_peak_live() -> usize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK_LIVE.store(live, Ordering::Relaxed);
    live
}

// --- Peak RSS ----------------------------------------------------------------

/// `struct rusage` of 64-bit macOS and Linux: two `timeval`s (16 bytes
/// each) followed by fourteen `long`s, the first of which is `ru_maxrss`.
#[cfg(unix)]
#[repr(C)]
struct RUsage {
    utime: [i64; 2],
    stime: [i64; 2],
    maxrss: i64,
    rest: [i64; 13],
}

#[cfg(unix)]
extern "C" {
    fn getrusage(who: i32, usage: *mut RUsage) -> i32;
}

/// The peak resident set size of this process so far, in bytes (0 where it
/// is not measured).
#[cfg(not(unix))]
pub fn peak_rss_bytes() -> u64 {
    0
}

/// The peak resident set size of this process so far, in bytes.
#[cfg(unix)]
pub fn peak_rss_bytes() -> u64 {
    let mut usage = RUsage { utime: [0; 2], stime: [0; 2], maxrss: 0, rest: [0; 13] };
    // SAFETY: `usage` is a valid, writable `struct rusage` for this target
    // and `RUSAGE_SELF` is 0 on both supported platforms.
    let status = unsafe { getrusage(0, &mut usage) };
    if status != 0 {
        return 0;
    }
    let raw = u64::try_from(usage.maxrss).unwrap_or(0);
    // macOS reports bytes, Linux kibibytes.
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}

// --- Timing ------------------------------------------------------------------

/// Fewest measured samples per point, whatever `--repeats` asks for.
pub const MIN_REPEATS: usize = 15;

/// A sample of an operation faster than this is the mean of a batch of
/// runs whose summed time reaches it, so that timer resolution and
/// one-off interrupts do not dominate a sample.
const MIN_SAMPLE_NS: u64 = 1_000_000;

/// Most runs of the operation folded into one sample.
const MAX_BATCH: u64 = 4_096;

/// Wall time and heap use of one operation over its samples.
#[derive(Clone, Debug, Default)]
pub struct Measurement {
    /// Samples taken (each the mean of `batch` runs).
    pub repeats: usize,
    /// Runs of the operation per sample.
    pub batch: u64,
    pub median_ns: u64,
    pub p95_ns: u64,
    pub min_ns: u64,
    pub allocs_per_op: u64,
    pub alloc_bytes_per_op: u64,
    /// The largest growth of the live heap above its level at the start of
    /// the operation, over every run.
    pub peak_heap_delta_bytes: u64,
    /// The first run of the operation in this process (the warm-up), before
    /// it had touched its data: the fresh-process figure. The samples that
    /// follow repeat the operation on caches it has already warmed.
    pub first_run_ns: u64,
}

/// Runs `op` on a fresh input from `setup` each time, handing its output
/// to `teardown`; only `op` is timed and counted.
///
/// One warm-up run, recorded apart as `first_run_ns`, also sizes the batch: when a run is shorter
/// than a millisecond, each sample is the mean of as many runs as reach
/// one (at most 4096), each run timed on its own so that setup and
/// teardown stay outside the time. At least [`MIN_REPEATS`] samples are
/// taken; the median, p95 and minimum are over samples.
pub fn measure<S, T>(
    repeats: usize,
    mut setup: impl FnMut() -> S,
    mut op: impl FnMut(S) -> T,
    mut teardown: impl FnMut(T),
) -> Measurement {
    let repeats = repeats.max(MIN_REPEATS);
    let input = setup();
    let start = Instant::now();
    let warm = op(input);
    let warm_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX).max(1);
    teardown(warm);
    let batch = MIN_SAMPLE_NS.div_ceil(warm_ns).clamp(1, MAX_BATCH);
    let mut samples = Vec::with_capacity(repeats);
    let (mut allocs, mut bytes, mut peak_delta) = (0u64, 0u64, 0u64);
    for _ in 0..repeats {
        let mut total_ns = 0u64;
        for _ in 0..batch {
            let input = setup();
            let before = heap_mark();
            let base_live = reset_peak_live();
            let start = Instant::now();
            let output = op(input);
            let elapsed = start.elapsed();
            let after = heap_mark();
            let peak = PEAK_LIVE.load(Ordering::Relaxed);
            teardown(output);
            total_ns =
                total_ns.saturating_add(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
            allocs += after.allocs - before.allocs;
            bytes += after.bytes - before.bytes;
            peak_delta = peak_delta.max(peak.saturating_sub(base_live) as u64);
        }
        samples.push(total_ns / batch);
    }
    samples.sort_unstable();
    let n = samples.len();
    let runs = n as u64 * batch;
    let p95_index = ((n * 95).div_ceil(100)).clamp(1, n) - 1;
    Measurement {
        repeats: n,
        batch,
        median_ns: samples[n / 2],
        p95_ns: samples[p95_index],
        min_ns: samples[0],
        allocs_per_op: allocs / runs,
        alloc_bytes_per_op: bytes / runs,
        peak_heap_delta_bytes: peak_delta,
        first_run_ns: warm_ns,
    }
}

// --- Arguments -----------------------------------------------------------------

/// `--key value` pairs and bare `--flag`s after the binary name. Cargo's own
/// `--bench` flag, passed to every bench binary, is accepted and ignored.
pub struct Args {
    values: BTreeMap<String, String>,
}

impl Args {
    pub fn parse() -> Self {
        let mut values = BTreeMap::new();
        let mut it = std::env::args().skip(1).peekable();
        while let Some(arg) = it.next() {
            let Some(key) = arg.strip_prefix("--") else { continue };
            let value = match it.peek() {
                Some(next) if !next.starts_with("--") => it.next().unwrap_or_default(),
                _ => String::from("true"),
            };
            values.insert(key.to_owned(), value);
        }
        Self { values }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    pub fn str_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or(default).to_owned()
    }

    pub fn u64_or(&self, key: &str, default: u64) -> u64 {
        self.get(key).map_or(default, |v| {
            v.replace('_', "").parse().unwrap_or_else(|_| panic!("--{key} {v} is not a number"))
        })
    }

    pub fn flag(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn out(&self) -> Option<PathBuf> {
        self.get("out").map(PathBuf::from)
    }
}

// --- CSV ---------------------------------------------------------------------

/// The cache condition of each time, recorded on every row. Every case runs
/// in its own process, with whatever the operating system's page cache
/// holds of its fixture. `first_run_ns` is the operation's first run in
/// that process; the median, p95 and minimum are over repeats of the same
/// operation, so they are hot-cache figures.
pub const CACHE_CONDITION: &str =
    "median/p95/min: hot (repeated op) / first_run_ns: fresh process + OS page cache uncontrolled";

pub const CSV_HEADER: &str = "bench,case,variant,impl,param,value,repeats,batch,median_ns,p95_ns,\
min_ns,allocs_per_op,alloc_bytes_per_op,peak_heap_delta_bytes,peak_rss_setup_bytes,\
peak_rss_end_bytes,state_bytes,status,cache,first_run_ns,extra";

/// One CSV row: which case, at which value of its swept parameter, and what
/// was measured. `extra` holds case-specific counters as `key=value` pairs.
pub struct Row {
    pub bench: &'static str,
    pub case: String,
    pub variant: String,
    pub implementation: &'static str,
    pub param: &'static str,
    pub value: u64,
    pub measurement: Measurement,
    pub peak_rss_setup_bytes: u64,
    pub state_bytes: Option<u64>,
    pub status: &'static str,
    pub extra: Vec<(String, String)>,
}

impl Row {
    pub fn new(
        bench: &'static str,
        case: &str,
        variant: &str,
        implementation: &'static str,
        param: &'static str,
        value: u64,
    ) -> Self {
        Self {
            bench,
            case: case.to_owned(),
            variant: variant.to_owned(),
            implementation,
            param,
            value,
            measurement: Measurement::default(),
            peak_rss_setup_bytes: 0,
            state_bytes: None,
            status: "ok",
            extra: Vec::new(),
        }
    }

    pub fn extra(mut self, key: &str, value: impl ToString) -> Self {
        self.extra.push((key.to_owned(), value.to_string()));
        self
    }

    fn to_csv(&self) -> String {
        let m = &self.measurement;
        let extra: Vec<String> = self
            .extra
            .iter()
            .map(|(k, v)| format!("{k}={}", v.replace([',', ';', '\n'], " ")))
            .collect();
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.bench,
            self.case,
            self.variant,
            self.implementation,
            self.param,
            self.value,
            m.repeats,
            m.batch,
            m.median_ns,
            m.p95_ns,
            m.min_ns,
            m.allocs_per_op,
            m.alloc_bytes_per_op,
            m.peak_heap_delta_bytes,
            self.peak_rss_setup_bytes,
            peak_rss_bytes(),
            self.state_bytes.map_or(String::new(), |b| b.to_string()),
            self.status,
            CACHE_CONDITION,
            m.first_run_ns,
            extra.join(";"),
        )
    }

    /// Prints the row and, with `--out`, appends it to that CSV file
    /// (writing the header first when the file is new or empty).
    pub fn emit(&self, out: Option<&PathBuf>) {
        let line = self.to_csv();
        println!("{line}");
        let Some(path) = out else { return };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create CSV directory");
        }
        let fresh = std::fs::metadata(path).map_or(true, |m| m.len() == 0);
        let mut file =
            OpenOptions::new().create(true).append(true).open(path).expect("open CSV file");
        if fresh {
            writeln!(file, "{CSV_HEADER}").expect("write CSV header");
        }
        writeln!(file, "{line}").expect("write CSV row");
    }
}
