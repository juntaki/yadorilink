//! dst-full-stack-heat-run-framework P0 task 0.1: the unified, serializable
//! Case IR every DST scenario (today: `dst_two_device_chaos`; later:
//! `monkey_chaos` and the full-stack daemon under P1+) is retrofitted onto,
//! replacing bespoke per-scenario event bookkeeping with one shared shape
//! that survives generator evolution (a serialized `Case` persists to the
//! corpus verbatim -- a bare seed only replays as long as the generator
//! that produced it from that seed hasn't changed).
//!
//! `#![cfg(madsim)]`-gated like every DST scenario file.
//!
//! P0 scope note: `Fault` and most of `Op` are defined completely per
//! design.md's full IR shape (so P1-P3 don't need a breaking schema
//! change), but P0's only producer (`dst_two_device_chaos`'s retrofit,
//! task 0.3) populates `fault_schedule` with an empty `Vec` (no fault
//! injectors exist before P2) and only ever emits `Op::Write`/`Op::Delete`
//! (that scenario's only two op kinds -- everything from `Rename` onward
//! is P3's op-vocabulary-extension task's receiving end, defined now so
//! the type doesn't need to change shape later).

#![cfg(madsim)]
#![allow(dead_code)] // not every field/variant has a producer yet before P1-P3

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single seed-driven scenario, fully self-describing: replaying `Case`
/// against the same scenario code (independent of the generator that
/// produced it) must reproduce the same run. Serialized (not just `seed`)
/// so a shrunk failing case survives generator evolution in the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub seed: u64,
    pub topology: Topology,
    pub workload: Vec<DeviceTimeline>,
    /// `(virtual_ts, Fault)`, sorted by `virtual_ts`. Always empty before
    /// P2 (no fault injectors exist yet); the scheduler that fires these
    /// against madsim's virtual clock is P2's job.
    pub fault_schedule: Vec<(u64, Fault)>,
    /// Every content value any op in `workload` can reference by
    /// `content_id`, so an oracle can prove "this surviving byte string is
    /// something a device actually wrote" rather than merely "not empty".
    pub content_table: ContentTable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    pub device_count: usize,
    pub links: Vec<LinkTopology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkTopology {
    pub group_id: String,
    pub initial_online: bool,
}

/// One device's ordered op timeline. `virtual_ts` is a monotonic per-run
/// round counter today (P0 has no injectable `Clock` yet -- that's a P1
/// prerequisite), used only to record/replay op *order* within and across
/// devices' timelines, never to drive real scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTimeline {
    pub device_index: usize,
    pub ops: Vec<(u64, Op)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    Write {
        path: String,
        content_id: u64,
    },
    Edit {
        path: String,
        content_id: u64,
    },
    Delete {
        path: String,
    },
    /// P3 op-vocabulary extension (not yet produced by any P0 scenario).
    Rename {
        from: String,
        to: String,
    },
    Move {
        from: String,
        to: String,
    },
    Mkdir {
        path: String,
    },
    Rmdir {
        path: String,
    },
    Chmod {
        path: String,
        exec_bit: bool,
    },
    /// Multiple devices' ops at the same logical round targeting paths
    /// that are expected to race -- a generator-level grouping hint for
    /// the oracle's history-legality check (task 0.2 item 4), not a new
    /// primitive op in its own right.
    ConflictingConcurrent {
        paths: Vec<String>,
    },
}

/// All four fault classes design.md specifies, defined completely now so
/// P1-P3 slot their injectors in without a breaking IR change. No P0
/// scenario schedules any of these yet (`fault_schedule` is always empty
/// before P2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Fault {
    Net(NetFault),
    Disk(DiskFault),
    Crash { device: usize },
    Restart { device: usize },
    ClockSkew { device: usize, delta_nanos: i64 },
    ClockJump { device: usize, to_unix_nanos: i64 },
}

/// Stub shape for P2's intercepting-transport injector; fields are the
/// minimum design.md's fault model names (`drop`/`delay`/`reorder`/
/// `duplicate`/`partition`/`heal`) so `Fault::Net` doesn't need to change
/// shape once P2 wires an actual interceptor behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetFault {
    Drop,
    Delay { millis: u64 },
    Reorder,
    Duplicate,
    Partition { device_a: usize, device_b: usize },
    Heal { device_a: usize, device_b: usize },
}

/// Stub shape for P2's faulting `BlockStore`/`SyncState` injectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiskFault {
    Enospc,
    Eio,
    TornWrite,
    FsyncFail,
    SlowIo { millis: u64 },
    SqliteBusy,
    SqliteLocked,
}

/// Maps a `content_id` to the exact bytes a device wrote under that id, so
/// an oracle can check "the surviving hash is one of these" rather than
/// merely hashing whatever it finds on disk with nothing to compare
/// against. `content_id`s are assigned by whatever generates the `Case`
/// (sequential is fine; only uniqueness within one `Case` matters).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentTable {
    entries: HashMap<u64, Vec<u8>>,
}

impl ContentTable {
    pub fn insert(&mut self, content_id: u64, bytes: Vec<u8>) -> u64 {
        self.entries.insert(content_id, bytes);
        content_id
    }

    pub fn get(&self, content_id: u64) -> Option<&Vec<u8>> {
        self.entries.get(&content_id)
    }

    /// True if `bytes` matches exactly one recorded content value --
    /// the no-corruption oracle's core question ("did someone actually
    /// write this, byte for byte").
    pub fn contains_bytes(&self, bytes: &[u8]) -> bool {
        self.entries.values().any(|v| v.as_slice() == bytes)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u64, &Vec<u8>)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_table_round_trips_through_json() {
        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());
        table.insert(2, b"world".to_vec());

        let json = serde_json::to_string(&table).unwrap();
        let restored: ContentTable = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.get(1), Some(&b"hello".to_vec()));
        assert_eq!(restored.get(2), Some(&b"world".to_vec()));
        assert!(restored.contains_bytes(b"hello"));
        assert!(!restored.contains_bytes(b"nope"));
    }

    #[test]
    fn case_round_trips_through_json() {
        let mut content_table = ContentTable::default();
        content_table.insert(1, b"payload".to_vec());

        let case = Case {
            seed: 42,
            topology: Topology {
                device_count: 2,
                links: vec![
                    LinkTopology { group_id: "g".to_string(), initial_online: true },
                    LinkTopology { group_id: "g".to_string(), initial_online: true },
                ],
            },
            workload: vec![DeviceTimeline {
                device_index: 0,
                ops: vec![(0, Op::Write { path: "a.txt".to_string(), content_id: 1 })],
            }],
            fault_schedule: Vec::new(),
            content_table,
        };

        let json = serde_json::to_string(&case).unwrap();
        let restored: Case = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.seed, 42);
        assert_eq!(restored.workload.len(), 1);
    }
}
